use std::time::Duration;

use {
    anyhow::{Context, Result, ensure},
    serde_json::json,
    sqlx::{Connection, MySqlConnection},
    tokio::{
        sync::oneshot,
        time::{Instant, timeout, timeout_at},
    },
};

use super::helper::{Config, Evidence, Fixture, statements};

pub async fn run(config: &Config, evidence: &mut Evidence) -> Result<()> {
    for commit in [true, false] {
        let fixture = Fixture::create(
            config,
            if commit {
                "deletecommit"
            } else {
                "deleterollback"
            },
            4,
        )
        .await?;
        let result = conditional_delete(&fixture, commit)
            .await
            .context(format!("conditional DELETE commit={commit}"));
        fixture.finish(result).await?;
    }
    let fixture = Fixture::create(config, "namedlocks", 5).await?;
    let result = named_locks(&fixture).await.context("named lock lifecycle");
    fixture.finish(result).await?;
    let fixture = Fixture::create(config, "generation", 5).await?;
    let result = generations(&fixture)
        .await
        .context("generation publication");
    fixture.finish(result).await?;
    evidence.observations.insert("locking".into(),json!({"conditional_delete_commit_waiter_zero":true,"conditional_delete_rollback_waiter_one":true,"named_lock":"session close, not COMMIT/DDL","generation":"ready owner CAS; old retained on preparation interruption"}));
    Ok(())
}

async fn conditional_delete(fixture: &Fixture, commit: bool) -> Result<()> {
    sqlx::query("CREATE TABLE tokens(token_hash VARBINARY(64) PRIMARY KEY,valid TINYINT NOT NULL)")
        .execute(&fixture.pool)
        .await?;
    sqlx::query("INSERT INTO tokens VALUES('token',1)")
        .execute(&fixture.pool)
        .await?;
    let mut first = fixture.pool.begin().await?;
    let removed = sqlx::query("DELETE FROM tokens WHERE token_hash=? AND valid=1")
        .bind(b"token".as_slice())
        .execute(&mut *first)
        .await?;
    ensure!(
        removed.rows_affected() == 1,
        "first conditional DELETE failed to acquire source row"
    );
    let mut second = fixture.pool.begin().await?;
    {
        let delete = sqlx::query("DELETE FROM tokens WHERE token_hash=? AND valid=1")
            .bind(b"token".as_slice())
            .execute(&mut *second);
        tokio::pin!(delete);
        ensure!(
            timeout(Duration::from_millis(150), &mut delete)
                .await
                .is_err(),
            "second conditional DELETE did not wait for first transaction"
        );
        if commit {
            first.commit().await?;
        } else {
            first.rollback().await?;
        }
        let removed = timeout(Duration::from_secs(10), delete).await??;
        ensure!(
            removed.rows_affected() == u64::from(!commit),
            "conditional DELETE ignored commit/rollback visibility"
        );
    }
    second.commit().await?;
    for (key, condition) in [(b"token".as_slice(), 1), (b"missing".as_slice(), 1)] {
        let removed = sqlx::query("DELETE FROM tokens WHERE token_hash=? AND valid=?")
            .bind(key)
            .bind(condition)
            .execute(&fixture.pool)
            .await?;
        ensure!(removed.rows_affected() == 0, "absent token consumed twice");
    }
    sqlx::query("INSERT INTO tokens VALUES('invalid',0)")
        .execute(&fixture.pool)
        .await?;
    let removed = sqlx::query("DELETE FROM tokens WHERE token_hash='invalid' AND valid=1")
        .execute(&fixture.pool)
        .await?;
    ensure!(
        removed.rows_affected() == 0,
        "condition-mismatching token consumed"
    );
    Ok(())
}

async fn named_locks(fixture: &Fixture) -> Result<()> {
    statements(&fixture.pool,"CREATE TABLE authority(id INT PRIMARY KEY,cipher VARBINARY(128) NOT NULL); INSERT INTO authority VALUES(1,'original');").await?;
    let key = format!("{}:account:default", fixture.database);
    let mut first = fixture.pool.acquire().await?;
    first.close_on_drop();
    let got: i32 = sqlx::query_scalar("SELECT GET_LOCK(?,5)")
        .bind(&key)
        .fetch_one(&mut *first)
        .await?;
    ensure!(got == 1, "named lock not acquired");
    sqlx::query("BEGIN").execute(&mut *first).await?;
    sqlx::query("UPDATE authority SET cipher='new' WHERE id=1")
        .execute(&mut *first)
        .await?;
    sqlx::query("COMMIT").execute(&mut *first).await?;
    sqlx::query("CREATE TABLE ddl_marker(id INT)")
        .execute(&mut *first)
        .await?;
    let mut second = fixture.pool.acquire().await?;
    second.close_on_drop();
    sqlx::query("SET SESSION ob_query_timeout=15000000")
        .execute(&mut *second)
        .await?;
    let denied: i32 = sqlx::query_scalar("SELECT GET_LOCK(?,0)")
        .bind(&key)
        .fetch_one(&mut *second)
        .await
        .context("contending after commit and DDL")?;
    ensure!(denied == 0, "COMMIT/DDL released account session lock");
    first.close().await?;
    let got: i32 = timeout(
        Duration::from_secs(15),
        sqlx::query_scalar("SELECT GET_LOCK(?,10)")
            .bind(&key)
            .fetch_one(&mut *second),
    )
    .await?
    .context("acquiring after awaited close")?;
    ensure!(
        got == 1,
        "awaited session close did not release named lock within budget"
    );
    second.close().await?;
    for commit_authority in [false, true] {
        let pool = fixture.pool.clone();
        let key_copy = key.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connection = pool.acquire().await?;
            connection.close_on_drop();
            sqlx::query("SET SESSION ob_query_timeout=15000000")
                .execute(&mut *connection)
                .await?;
            let got: i32 = sqlx::query_scalar("SELECT GET_LOCK(?,10)")
                .bind(&key_copy)
                .fetch_one(&mut *connection)
                .await
                .context("rotation worker acquiring previous closed lock")?;
            ensure!(got == 1, "rotation session failed to lock");
            if commit_authority {
                sqlx::query("BEGIN").execute(&mut *connection).await?;
                sqlx::query("UPDATE authority SET cipher='newer' WHERE id=1")
                    .execute(&mut *connection)
                    .await
                    .context("authority update after lock acquisition")?;
                sqlx::query("COMMIT")
                    .execute(&mut *connection)
                    .await
                    .context("authority commit after lock acquisition")?;
            }
            ready_tx
                .send(())
                .map_err(|_| anyhow::anyhow!("rotation coordinator disappeared"))?;
            std::future::pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        });
        if ready_rx.await.is_err() {
            task.await??;
            anyhow::bail!("rotation worker ended before readiness");
        }
        task.abort();
        ensure!(
            task.await.is_err(),
            "rotation cancellation did not take effect"
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut survivor = fixture.pool.acquire().await?;
        survivor.close_on_drop();
        sqlx::query("SET SESSION ob_query_timeout=15000000")
            .execute(&mut *survivor)
            .await?;
        let acquired: i32 = timeout_at(
            deadline,
            sqlx::query_scalar("SELECT GET_LOCK(?,10)")
                .bind(&key)
                .fetch_one(&mut *survivor),
        )
        .await?
        .context("survivor acquiring canceled rotation lock")?;
        ensure!(
            acquired == 1,
            "canceled possibly holding session returned idle or retained lock"
        );
        let authority: Vec<u8> = sqlx::query_scalar("SELECT cipher FROM authority WHERE id=1")
            .fetch_one(&mut *survivor)
            .await
            .context("survivor reading authority after canceled lock")?;
        ensure!(
            authority
                == if commit_authority {
                    b"newer".as_slice()
                } else {
                    b"new".as_slice()
                },
            "cancellation restored old authority"
        );
        survivor.close().await?;
    }
    // Cancel while the GET_LOCK result is still uncertain; close-on-drop precedes the request.
    let mut owner = MySqlConnection::connect_with(&fixture.options).await?;
    let _: i32 = sqlx::query_scalar("SELECT GET_LOCK(?,5)")
        .bind(&key)
        .fetch_one(&mut owner)
        .await
        .context("uncertain-case owner acquiring prior survivor lock")?;
    let mut uncertain = fixture.pool.acquire().await?;
    uncertain.close_on_drop();
    ensure!(
        timeout(
            Duration::from_millis(100),
            sqlx::query_scalar::<_, i32>("SELECT GET_LOCK(?,10)")
                .bind(&key)
                .fetch_one(&mut *uncertain)
        )
        .await
        .is_err(),
        "uncertain acquisition unexpectedly finished"
    );
    uncertain
        .close()
        .await
        .context("closing canceled uncertain acquisition")?;
    owner.close().await?;
    let mut final_connection = fixture.pool.acquire().await?;
    final_connection.close_on_drop();
    sqlx::query("SET SESSION ob_query_timeout=15000000")
        .execute(&mut *final_connection)
        .await?;
    let got: i32 = timeout(
        Duration::from_secs(20),
        sqlx::query_scalar("SELECT GET_LOCK(?,10)")
            .bind(&key)
            .fetch_one(&mut *final_connection),
    )
    .await?
    .context("final acquire after uncertain request disposal")?;
    ensure!(
        got == 1,
        "canceled acquisition session blocked next management operation"
    );
    final_connection.close().await?;
    Ok(())
}

async fn generations(fixture: &Fixture) -> Result<()> {
    statements(&fixture.pool,"CREATE TABLE registry(id BIGINT PRIMARY KEY,owner VARBINARY(32),state VARCHAR(16),epoch BIGINT NOT NULL); CREATE TABLE current_generation(singleton INT PRIMARY KEY CHECK(singleton=1),generation_id BIGINT NOT NULL); INSERT INTO registry VALUES(1,'old','ready',1); INSERT INTO current_generation VALUES(1,1);").await?;
    sqlx::query(
        "INSERT INTO registry VALUES(2,'starterA','preparing',2),(3,'starterB','preparing',3)",
    )
    .execute(&fixture.pool)
    .await?;
    sqlx::query("CREATE TABLE ready_generation(chunk_id VARBINARY(32) UNIQUE,content TEXT)")
        .execute(&fixture.pool)
        .await?;
    sqlx::query("UPDATE registry SET state='ready' WHERE id=3 AND owner='starterB'")
        .execute(&fixture.pool)
        .await?;
    let stale=sqlx::query("UPDATE current_generation c JOIN registry r ON r.id=2 SET c.generation_id=r.id WHERE c.singleton=1 AND r.owner='starterA' AND r.state='ready'").execute(&fixture.pool).await?;
    ensure!(
        stale.rows_affected() == 0,
        "incomplete generation published"
    );
    let old: i64 =
        sqlx::query_scalar("SELECT generation_id FROM current_generation WHERE singleton=1")
            .fetch_one(&fixture.pool)
            .await?;
    ensure!(
        old == 1,
        "interrupted preparation stopped old service generation"
    );
    let winner=sqlx::query("UPDATE current_generation c JOIN registry r ON r.id=3 SET c.generation_id=r.id WHERE c.singleton=1 AND c.generation_id=1 AND r.owner='starterB' AND r.state='ready'").execute(&fixture.pool).await?;
    ensure!(
        winner.rows_affected() == 1,
        "ready generation failed owner/CAS publication"
    );
    sqlx::query("UPDATE registry SET owner='replacement' WHERE id=2")
        .execute(&fixture.pool)
        .await?;
    let stale = sqlx::query("UPDATE registry SET state='ready' WHERE id=2 AND owner='starterA'")
        .execute(&fixture.pool)
        .await?;
    ensure!(
        stale.rows_affected() == 0,
        "expired preparation owner published"
    );
    let removed=sqlx::query("DELETE r FROM registry r LEFT JOIN current_generation c ON c.generation_id=r.id WHERE c.generation_id IS NULL AND r.state='preparing' AND r.owner='replacement'").execute(&fixture.pool).await?;
    ensure!(removed.rows_affected() == 1, "orphan cleanup failed");
    let current: i64 =
        sqlx::query_scalar("SELECT generation_id FROM current_generation WHERE singleton=1")
            .fetch_one(&fixture.pool)
            .await?;
    ensure!(current == 3, "orphan cleanup deleted published generation");
    Ok(())
}
