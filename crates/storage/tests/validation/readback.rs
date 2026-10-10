use {
    super::{
        helper::{Config, Evidence, Fixture, expect_number, hash},
        hybrid,
    },
    anyhow::{Result, ensure},
    serde_json::json,
    sqlx::Row,
    std::collections::BTreeMap,
};

pub async fn run(config: &Config, evidence: &mut Evidence) -> Result<()> {
    for table in ["memory_chunks_search", "code_chunks_search"] {
        let parser = evidence
            .observations
            .get(&format!("parser:{table}"))
            .and_then(|v| v["parser"].as_str())
            .ok_or_else(|| anyhow::anyhow!("missing selected parser for readback"))?
            .to_owned();
        let fixture = Fixture::create(config, "readback", 5).await?;
        let result = check(&fixture, table, &parser).await;
        fixture.finish(result).await?;
    }
    evidence.observations.insert("ranked_readback".into(),json!({"heap_pointer_unique":true,"rank_restored_after_unordered_lookup":true,"changed_scope_content_deleted":"skip; no refill","ties":"arbitrary valid members"}));
    Ok(())
}

async fn check(fixture: &Fixture, table: &str, parser: &str) -> Result<()> {
    let pool = &fixture.pool;
    hybrid::create_search(pool, table, Some(3), parser).await?;
    sqlx::query("CREATE TABLE chunks(id VARBINARY(128) PRIMARY KEY,scope VARBINARY(128) NOT NULL,content LONGTEXT NOT NULL,version BIGINT NOT NULL,content_hash VARBINARY(128) NOT NULL)").execute(pool).await?;
    for id in ["one", "two", "three", "four", "five", "six"] {
        hybrid::insert(pool, table, id, "a", "tied alpha", Some(&[1., 0., 0.])).await?;
        sqlx::query("INSERT INTO chunks VALUES(?,'a','tied alpha',1,?)")
            .bind(id.as_bytes())
            .bind(hash(b"tied alpha").as_bytes())
            .execute(pool)
            .await?;
    }
    expect_number(
        sqlx::query(&format!(
            "INSERT INTO {table} SELECT * FROM {table} WHERE chunk_id='one'"
        ))
        .execute(pool)
        .await,
        1062,
    )?;
    let ranked = hybrid::search(
        pool,
        table,
        &hybrid::dsl(Some("alpha"), Some(&[1., 0., 0.]), 0, 5)?,
    )
    .await?;
    hybrid::ranked(&ranked, 5, Some(b"a"))?;
    ensure!(
        ranked.len() == 5,
        "tie candidate boundary returned fewer than k"
    );
    let rows =
        sqlx::query("SELECT id,scope,content,version,content_hash FROM chunks ORDER BY id DESC")
            .fetch_all(pool)
            .await?;
    let mut by_id = BTreeMap::new();
    for row in rows {
        by_id.insert(row.try_get::<Vec<u8>, _>("id")?, row);
    }
    let restore = |rows: &BTreeMap<Vec<u8>, sqlx::mysql::MySqlRow>| -> Result<Vec<Vec<u8>>> {
        let mut output = Vec::new();
        for candidate in &ranked {
            let key: Vec<u8> = candidate.try_get("chunk_id")?;
            if let Some(row) = rows.get(&key)
                && row.try_get::<Vec<u8>, _>("scope")?
                    == candidate.try_get::<Vec<u8>, _>("agent_scope")?
                && row.try_get::<i64, _>("version")?
                    == candidate.try_get::<i64, _>("content_version")?
                && row.try_get::<Vec<u8>, _>("content_hash")?
                    == candidate.try_get::<Vec<u8>, _>("content_hash")?
                && row.try_get::<Vec<u8>, _>("content")?
                    == candidate.try_get::<Vec<u8>, _>("content")?
            {
                output.push(key);
            }
        }
        Ok(output)
    };
    let expected = ranked
        .iter()
        .map(|row| row.try_get::<Vec<u8>, _>("chunk_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        restore(&by_id)? == expected,
        "readback reordered this response's actual ranks"
    );
    sqlx::query("UPDATE chunks SET scope='ab' WHERE id=?")
        .bind(&expected[0])
        .execute(pool)
        .await?;
    sqlx::query(
        "UPDATE chunks SET content='changed',version=2,content_hash='changedhash' WHERE id=?",
    )
    .bind(&expected[1])
    .execute(pool)
    .await?;
    sqlx::query("DELETE FROM chunks WHERE id=?")
        .bind(&expected[2])
        .execute(pool)
        .await?;
    let rows =
        sqlx::query("SELECT id,scope,content,version,content_hash FROM chunks ORDER BY id DESC")
            .fetch_all(pool)
            .await?;
    by_id.clear();
    for row in rows {
        by_id.insert(row.try_get::<Vec<u8>, _>("id")?, row);
    }
    ensure!(
        restore(&by_id)? == expected[3..],
        "concurrent source changes produced torn/leaked/refilled result"
    );
    let updated=sqlx::query(&format!("INSERT INTO {table}(chunk_id,agent_scope,content,content_version,content_hash,vec) VALUES('one','ab','replacement',2,'replacementhash','[1,0,0]') ON DUPLICATE KEY UPDATE agent_scope=VALUES(agent_scope),content=VALUES(content),content_version=VALUES(content_version),content_hash=VALUES(content_hash),vec=VALUES(vec)")).execute(pool).await?;
    ensure!(
        updated.rows_affected() == 2,
        "pointer upsert did not update existing heap row"
    );
    let count: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {table} WHERE chunk_id='one'"
    ))
    .fetch_one(pool)
    .await?;
    ensure!(count == 1, "pointer replay duplicated heap projection");
    let old = hybrid::search(pool, table, &hybrid::dsl(Some("replacement"), None, 0, 10)?).await?;
    ensure!(
        old.is_empty(),
        "scope-updated projection still matches old scope"
    );
    fixture.drop_table(table).await?;
    Ok(())
}
