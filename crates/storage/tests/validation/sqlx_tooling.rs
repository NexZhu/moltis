use {
    anyhow::{Context, Result, ensure},
    serde_json::json,
    sqlx::{
        Row,
        migrate::{Migrate, Migrator},
    },
};

use super::helper::{Config, Evidence, Fixture, expect_number};

static MIGRATOR: Migrator = sqlx::migrate!("tests/validation/fixtures/migrations");

pub async fn run(config: &Config, evidence: &mut Evidence) -> Result<()> {
    let fixture = Fixture::create(config, "migration", 3).await?;
    let result = normal(&fixture).await.context("normal migration replay");
    fixture.finish(result).await?;
    let fixture = Fixture::create(config, "repair", 3).await?;
    let result = repair(&fixture)
        .await
        .context("interrupted migration repair");
    fixture.finish(result).await?;
    evidence.observations.insert("sqlx_tooling".into(),json!({"migrate_macro":true,"runner":"explicit private helper","migration_twice":"second no-op","checksum":"BLOB","repair":"conditional exact original checksum/success false; full shape before ready"}));
    Ok(())
}

async fn normal(fixture: &Fixture) -> Result<()> {
    let mut connection = fixture.pool.acquire().await?;
    connection.close_on_drop();
    sqlx::query("SET SESSION ob_query_timeout=15000000")
        .execute(&mut *connection)
        .await?;
    MIGRATOR.run_direct(&mut *connection).await?;
    sqlx::query(
        "INSERT INTO fixture_items VALUES('preserved','seed','{\"big\":9007199254740993}')",
    )
    .execute(&mut *connection)
    .await?;
    let before = sqlx::query(
        "SELECT version,checksum,execution_time FROM _sqlx_migrations WHERE success=TRUE",
    )
    .fetch_all(&mut *connection)
    .await?;
    MIGRATOR.run_direct(&mut *connection).await?;
    let after = sqlx::query(
        "SELECT version,checksum,execution_time FROM _sqlx_migrations WHERE success=TRUE",
    )
    .fetch_all(&mut *connection)
    .await?;
    ensure!(
        before.len() == 1
            && after.len() == 1
            && before[0].try_get::<Vec<u8>, _>("checksum")?
                == after[0].try_get::<Vec<u8>, _>("checksum")?
            && before[0].try_get::<i64, _>("execution_time")?
                == after[0].try_get::<i64, _>("execution_time")?,
        "second Migrator run not a no-op"
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fixture_items WHERE id='preserved'")
        .fetch_one(&mut *connection)
        .await?;
    ensure!(count == 1, "migration replay destroyed committed data");
    connection.close().await?;
    Ok(())
}

async fn repair(fixture: &Fixture) -> Result<()> {
    let migration = MIGRATOR
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("fixture migration missing"))?;
    let mut blocker = fixture.pool.acquire().await?;
    blocker.close_on_drop();
    let key = format!("{}:fixture-ddl-barrier", fixture.database);
    let got: i32 = sqlx::query_scalar("SELECT GET_LOCK(?,5)")
        .bind(&key)
        .fetch_one(&mut *blocker)
        .await?;
    ensure!(got == 1, "migration DDL barrier not acquired");
    let pool = fixture.pool.clone();
    let (session_tx, session_rx) = tokio::sync::oneshot::channel();
    let driver = tokio::spawn(async move {
        let mut connection = pool.acquire().await?;
        connection.close_on_drop();
        let session: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&mut *connection)
            .await?;
        session_tx
            .send(session)
            .map_err(|_| anyhow::anyhow!("migration interruption coordinator disappeared"))?;
        MIGRATOR.run_direct(&mut *connection).await?;
        connection.close().await?;
        Ok::<_, anyhow::Error>(())
    });
    let session = session_rx.await?;
    tokio::time::timeout(std::time::Duration::from_secs(20),async {
        loop {
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='fixture_accounts'").fetch_one(&mut *blocker).await?;
            if count==1 {break;}
            tokio::task::yield_now().await;
        }
        Ok::<_,anyhow::Error>(())
    }).await??;
    let absent:i64=sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='fixture_items'").fetch_one(&mut *blocker).await?;
    ensure!(
        absent == 0,
        "driver interruption did not occur between actual DDLs"
    );
    sqlx::query(&format!("KILL CONNECTION {session}"))
        .execute(&mut *blocker)
        .await?;
    driver.abort();
    match driver.await {
        Err(error) => ensure!(
            error.is_cancelled(),
            "migration worker failed unexpectedly: {error}"
        ),
        Ok(result) => ensure!(result.is_err(), "killed migration completed successfully"),
    }
    blocker.close().await?;
    let mut connection = fixture.pool.acquire().await?;
    connection.close_on_drop();
    sqlx::query("SET SESSION ob_query_timeout=15000000")
        .execute(&mut *connection)
        .await?;
    tokio::time::timeout(std::time::Duration::from_secs(20), connection.lock()).await??;
    let repair_started = std::time::Instant::now();
    sqlx::query("INSERT INTO fixture_accounts VALUES('preserved',1)")
        .execute(&mut *connection)
        .await?;
    let row =
        sqlx::query("SELECT success,checksum,execution_time FROM _sqlx_migrations WHERE version=1")
            .fetch_one(&mut *connection)
            .await?;
    let checksum: Vec<u8> = row.try_get("checksum")?;
    ensure!(
        checksum == migration.checksum.as_ref()
            && !row.try_get::<bool, _>("success")?
            && row.try_get::<i64, _>("execution_time")? == -1,
        "dirty migration changed original evidence"
    );
    let shape = sqlx::query("SHOW CREATE TABLE fixture_accounts")
        .fetch_one(&mut *connection)
        .await?;
    let ddl: String = shape.try_get(1)?;
    ensure!(
        ddl.to_ascii_lowercase().contains("varbinary(64)")
            && ddl.to_ascii_lowercase().contains("primary key")
            && ddl.to_ascii_lowercase().contains("check")
            && ddl.contains("enabled"),
        "repair cannot accept wrong existing shape"
    );
    // Each refusal keeps the original dirty row and valid data, then restores only this fixture's corruption.
    sqlx::query("UPDATE _sqlx_migrations SET checksum=X'00' WHERE version=1")
        .execute(&mut *connection)
        .await?;
    ensure!(
        validate_repair(&mut connection, migration.checksum.as_ref())
            .await
            .is_err(),
        "repair accepted mismatched checksum"
    );
    sqlx::query("UPDATE _sqlx_migrations SET checksum=? WHERE version=1")
        .bind(migration.checksum.as_ref())
        .execute(&mut *connection)
        .await?;
    sqlx::query("ALTER TABLE fixture_accounts ADD COLUMN unexpected INT")
        .execute(&mut *connection)
        .await?;
    ensure!(
        validate_repair(&mut connection, migration.checksum.as_ref())
            .await
            .is_err(),
        "repair accepted extra column shape"
    );
    sqlx::query("ALTER TABLE fixture_accounts DROP COLUMN unexpected")
        .execute(&mut *connection)
        .await?;
    sqlx::query("INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES(2,'later',FALSE,X'01',-1)").execute(&mut *connection).await?;
    ensure!(
        validate_repair(&mut connection, migration.checksum.as_ref())
            .await
            .is_err(),
        "repair accepted later dirty migration"
    );
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version=2")
        .execute(&mut *connection)
        .await?;
    validate_repair(&mut connection, migration.checksum.as_ref()).await?;
    // Cancellation after acquiring the real driver lock must not return that session idle.
    connection.close().await?;
    let pool = fixture.pool.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let canceled = tokio::spawn(async move {
        let mut connection = pool.acquire().await?;
        connection.close_on_drop();
        connection.lock().await?;
        ready_tx
            .send(())
            .map_err(|_| anyhow::anyhow!("repair coordinator disappeared"))?;
        std::future::pending::<()>().await;
        Ok::<_, anyhow::Error>(())
    });
    ready_rx.await?;
    canceled.abort();
    ensure!(canceled.await.is_err(), "repair cancellation ineffective");
    let mut connection = fixture.pool.acquire().await?;
    connection.close_on_drop();
    sqlx::query("SET SESSION ob_query_timeout=15000000")
        .execute(&mut *connection)
        .await?;
    tokio::time::timeout(std::time::Duration::from_secs(20), connection.lock()).await??;
    validate_repair(&mut connection, migration.checksum.as_ref()).await?;
    sqlx::query("CREATE TABLE fixture_items(id VARBINARY(64) PRIMARY KEY,account_id VARBINARY(64) NOT NULL,payload JSON NOT NULL,FOREIGN KEY(account_id) REFERENCES fixture_accounts(id) ON DELETE CASCADE)").execute(&mut *connection).await?;
    sqlx::query("INSERT INTO fixture_accounts VALUES('seed',1)")
        .execute(&mut *connection)
        .await?;
    for (damage, restore) in [
        (
            "CREATE INDEX unexpected_idx ON fixture_accounts(enabled)",
            "DROP INDEX unexpected_idx ON fixture_accounts",
        ),
        (
            "UPDATE fixture_accounts SET enabled=0 WHERE id='seed'",
            "UPDATE fixture_accounts SET enabled=1 WHERE id='seed'",
        ),
        (
            "ALTER TABLE fixture_items MODIFY payload LONGTEXT NOT NULL",
            "ALTER TABLE fixture_items MODIFY payload JSON NOT NULL",
        ),
        (
            "CREATE INDEX unexpected_child ON fixture_items(id)",
            "DROP INDEX unexpected_child ON fixture_items",
        ),
    ] {
        sqlx::query(damage).execute(&mut *connection).await?;
        ensure!(
            validate_repair(&mut connection, migration.checksum.as_ref())
                .await
                .is_err(),
            "repair accepted wrong existing index/seed shape: {damage}"
        );
        sqlx::query(restore).execute(&mut *connection).await?;
    }
    let fk: String = sqlx::query_scalar("SELECT constraint_name FROM information_schema.referential_constraints WHERE constraint_schema=DATABASE() AND table_name='fixture_items'").fetch_one(&mut *connection).await?;
    sqlx::query(&format!(
        "ALTER TABLE fixture_items DROP FOREIGN KEY `{fk}`"
    ))
    .execute(&mut *connection)
    .await?;
    ensure!(
        validate_repair(&mut connection, migration.checksum.as_ref())
            .await
            .is_err(),
        "repair accepted missing foreign key"
    );
    sqlx::query("ALTER TABLE fixture_items ADD FOREIGN KEY(account_id) REFERENCES fixture_accounts(id) ON DELETE CASCADE").execute(&mut *connection).await?;
    let check: String = sqlx::query_scalar("SELECT constraint_name FROM information_schema.table_constraints WHERE constraint_schema=DATABASE() AND table_name='fixture_accounts' AND constraint_type='CHECK'").fetch_one(&mut *connection).await?;
    sqlx::query(&format!(
        "ALTER TABLE fixture_accounts DROP CHECK `{check}`"
    ))
    .execute(&mut *connection)
    .await?;
    ensure!(
        validate_repair(&mut connection, migration.checksum.as_ref())
            .await
            .is_err(),
        "repair accepted missing CHECK"
    );
    sqlx::query("DELETE FROM fixture_accounts WHERE id='invalid'")
        .execute(&mut *connection)
        .await?;
    sqlx::query("ALTER TABLE fixture_accounts ADD CHECK(enabled IN (0,1))")
        .execute(&mut *connection)
        .await?;
    validate_repair(&mut connection, migration.checksum.as_ref()).await?;
    expect_number(
        sqlx::query("INSERT INTO fixture_items VALUES('bad','missing','{}')")
            .execute(&mut *connection)
            .await,
        1452,
    )?;
    expect_number(
        sqlx::query("INSERT INTO fixture_accounts VALUES('bad',2)")
            .execute(&mut *connection)
            .await,
        3819,
    )?;
    let elapsed = i64::try_from(repair_started.elapsed().as_nanos())?;
    let updated=sqlx::query("UPDATE _sqlx_migrations SET success=TRUE,execution_time=? WHERE version=1 AND success=FALSE AND checksum=? AND execution_time=-1").bind(elapsed).bind(migration.checksum.as_ref()).execute(&mut *connection).await?;
    ensure!(
        updated.rows_affected() == 1,
        "repair must mark exactly one original dirty migration"
    );
    MIGRATOR.run_direct(&mut *connection).await?;
    MIGRATOR.run_direct(&mut *connection).await?;
    let preserved: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM fixture_accounts WHERE id='preserved'")
            .fetch_one(&mut *connection)
            .await?;
    ensure!(preserved == 1, "repair destroyed committed valid data");
    connection.close().await?;
    Ok(())
}

async fn validate_repair(connection: &mut sqlx::MySqlConnection, expected: &[u8]) -> Result<()> {
    let row =
        sqlx::query("SELECT success,checksum,execution_time FROM _sqlx_migrations WHERE version=1")
            .fetch_one(&mut *connection)
            .await?;
    ensure!(
        !row.try_get::<bool, _>("success")?
            && row.try_get::<Vec<u8>, _>("checksum")? == expected
            && row.try_get::<i64, _>("execution_time")? == -1,
        "dirty original migration identity mismatch"
    );
    let later: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version>1")
        .fetch_one(&mut *connection)
        .await?;
    ensure!(later == 0, "later migration prevents repair");
    let columns=sqlx::query("SELECT column_name,data_type,is_nullable,character_maximum_length FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='fixture_accounts' ORDER BY ordinal_position").fetch_all(&mut *connection).await?;
    ensure!(columns.len() == 2, "wrong existing column shape");
    ensure!(
        columns[0].try_get::<String, _>("column_name")? == "id"
            && columns[0].try_get::<String, _>("data_type")? == "varbinary"
            && columns[0].try_get::<String, _>("is_nullable")? == "NO"
            && columns[0].try_get::<u64, _>("character_maximum_length")? == 64,
        "wrong primary identity column"
    );
    ensure!(
        columns[1].try_get::<String, _>("column_name")? == "enabled"
            && columns[1].try_get::<String, _>("data_type")? == "tinyint"
            && columns[1].try_get::<String, _>("is_nullable")? == "NO",
        "wrong constraint source column"
    );
    let primary:i64=sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='fixture_accounts' AND index_name='PRIMARY' AND column_name='id' AND non_unique=0").fetch_one(&mut *connection).await?;
    ensure!(primary == 1, "repair missing primary uniqueness");
    let indexes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='fixture_accounts'").fetch_one(&mut *connection).await?;
    ensure!(indexes == 1, "repair accepted extra/wrong account indexes");
    let checks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.table_constraints WHERE constraint_schema=DATABASE() AND table_name='fixture_accounts' AND constraint_type='CHECK'").fetch_one(&mut *connection).await?;
    ensure!(checks == 1, "repair missing/wrong CHECK shape");
    let child: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='fixture_items'").fetch_one(&mut *connection).await?;
    if child == 1 {
        let columns = sqlx::query("SELECT column_name,data_type,is_nullable,character_maximum_length FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='fixture_items' ORDER BY ordinal_position").fetch_all(&mut *connection).await?;
        ensure!(columns.len() == 3, "repair wrong child column count");
        for (column, name, kind, length) in [
            (&columns[0], "id", "varbinary", Some(64u64)),
            (&columns[1], "account_id", "varbinary", Some(64u64)),
            (&columns[2], "payload", "json", Some(536870911u64)),
        ] {
            ensure!(
                column.try_get::<String, _>("column_name")? == name
                    && column.try_get::<String, _>("data_type")? == kind
                    && column.try_get::<String, _>("is_nullable")? == "NO"
                    && column.try_get::<Option<u64>, _>("character_maximum_length")? == length,
                "repair wrong child column shape: {name}"
            );
        }
        let indexes = sqlx::query("SELECT index_name,column_name,non_unique FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='fixture_items'").fetch_all(&mut *connection).await?;
        ensure!(
            indexes.len() == 1
                && indexes[0].try_get::<String, _>("index_name")? == "PRIMARY"
                && indexes[0].try_get::<String, _>("column_name")? == "id"
                && indexes[0].try_get::<i64, _>("non_unique")? == 0,
            "repair wrong child indexes"
        );
        let fk = sqlx::query("SELECT referenced_table_name,update_rule,delete_rule FROM information_schema.referential_constraints WHERE constraint_schema=DATABASE() AND table_name='fixture_items'").fetch_all(&mut *connection).await?;
        ensure!(
            fk.len() == 1
                && fk[0].try_get::<String, _>("referenced_table_name")? == "fixture_accounts"
                && fk[0].try_get::<String, _>("update_rule")? == "RESTRICT"
                && fk[0].try_get::<String, _>("delete_rule")? == "CASCADE",
            "repair missing/wrong FK shape"
        );
        let key = sqlx::query("SELECT column_name,referenced_column_name FROM information_schema.key_column_usage WHERE table_schema=DATABASE() AND table_name='fixture_items' AND referenced_table_name='fixture_accounts'").fetch_all(&mut *connection).await?;
        ensure!(
            key.len() == 1
                && key[0].try_get::<String, _>("column_name")? == "account_id"
                && key[0].try_get::<String, _>("referenced_column_name")? == "id",
            "repair wrong FK identity"
        );
        let seed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM fixture_accounts WHERE id='seed' AND enabled=1",
        )
        .fetch_one(&mut *connection)
        .await?;
        ensure!(seed == 1, "repair missing/wrong seed shape");
    }
    expect_number(
        sqlx::query("INSERT INTO fixture_accounts VALUES('invalid',2)")
            .execute(&mut *connection)
            .await,
        3819,
    )?;
    Ok(())
}
