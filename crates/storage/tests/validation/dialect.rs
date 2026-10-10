use {
    anyhow::{Result, ensure},
    serde_json::{Value, json},
    sqlx::{MySqlPool, Row},
};

use super::helper::{Config, Evidence, Fixture, expect_number, statements};

pub async fn run(config: &Config, evidence: &mut Evidence) -> Result<()> {
    let fixture = Fixture::create(config, "dialect", 5).await?;
    let result = check(&fixture.pool).await;
    let observation = fixture.finish(result).await?;
    evidence.observations.insert("dialect".into(), observation);
    Ok(())
}

async fn check(pool: &MySqlPool) -> Result<Value> {
    statements(pool, "CREATE TABLE parent(id VARBINARY(64) PRIMARY KEY); CREATE TABLE record(id BIGINT AUTO_INCREMENT PRIMARY KEY, identity VARBINARY(64) NOT NULL, other_key VARBINARY(64) NOT NULL, payload JSON NOT NULL, opaque LONGTEXT NOT NULL, parent_id VARBINARY(64), small TINYINT NOT NULL DEFAULT 1, UNIQUE INDEX expected_identity(identity), UNIQUE INDEX unrelated(other_key), FOREIGN KEY(parent_id) REFERENCES parent(id)); CREATE TABLE conditional(id BIGINT PRIMARY KEY, live TINYINT NOT NULL, source VARBINARY(64), key_col VARBINARY(64), UNIQUE INDEX conditional_key(key_col), CHECK(key_col <=> CASE WHEN (live=1) IS TRUE THEN source ELSE NULL END)); CREATE TABLE composite(id BIGINT PRIMARY KEY, live TINYINT NOT NULL, source_a VARBINARY(64), source_b VARBINARY(64), key_a VARBINARY(64), key_b VARBINARY(64), UNIQUE INDEX conditional_pair(key_a,key_b), CHECK(key_a <=> CASE WHEN (live=1) IS TRUE THEN source_a ELSE NULL END), CHECK(key_b <=> CASE WHEN (live=1) IS TRUE THEN source_b ELSE NULL END));").await?;
    sqlx::query("INSERT INTO parent VALUES(?),(?)")
        .bind(b"k".as_slice())
        .bind(b"k ".as_slice())
        .execute(pool)
        .await?;
    let raw = " { \"max\":18446744073709551615, \"big\":9007199254740993, \"dup\":0, \"dup\":1, \"nested\":{\"x\":0,\"x\":2} } ";
    let parsed: Value = serde_json::from_str(raw)?;
    let insert = sqlx::query(
        "INSERT INTO record(identity,other_key,payload,opaque,parent_id) VALUES(?,?,?,?,?)",
    )
    .bind(b"ns".as_slice())
    .bind(b"other".as_slice())
    .bind(sqlx::types::Json(&parsed))
    .bind(raw)
    .bind(b"k".as_slice())
    .execute(pool)
    .await?;
    let first_id = insert.last_insert_id();
    ensure!(first_id > 0, "AUTO_INCREMENT did not assign an ID");
    let mut connection = pool.acquire().await?;
    let last: u64 = sqlx::query_scalar("SELECT LAST_INSERT_ID()")
        .fetch_one(&mut *connection)
        .await?;
    // LAST_INSERT_ID is session-scoped: prove it on the same session as its INSERT.
    let inserted = sqlx::query(
        "INSERT INTO record(identity,other_key,payload,opaque,parent_id) VALUES(?,?,?,?,?)",
    )
    .bind(b"ns ".as_slice())
    .bind(b"other ".as_slice())
    .bind(sqlx::types::Json(&parsed))
    .bind(raw)
    .bind(b"k ".as_slice())
    .execute(&mut *connection)
    .await?;
    let own_last: u64 = sqlx::query_scalar("SELECT LAST_INSERT_ID()")
        .fetch_one(&mut *connection)
        .await?;
    ensure!(
        own_last == inserted.last_insert_id() && own_last != first_id,
        "LAST_INSERT_ID is not the inserted row identity"
    );
    drop(connection);
    let rows = sqlx::query("SELECT identity,parent_id,payload,opaque FROM record ORDER BY id")
        .fetch_all(pool)
        .await?;
    ensure!(rows.len() == 2, "binary identity tail spaces merged");
    for row in &rows {
        let value: sqlx::types::Json<Value> = row.try_get("payload")?;
        ensure!(
            value.0 == parsed
                && value.0["big"].as_u64() == Some(9007199254740993)
                && value.0["max"].as_u64() == Some(u64::MAX),
            "native JSON lost precision or last-wins semantics"
        );
        ensure!(
            String::from_utf8(row.try_get::<Vec<u8>, _>("opaque")?)? == raw,
            "opaque string canonicalized"
        );
    }
    let update = sqlx::query("UPDATE record SET opaque=opaque WHERE identity=?")
        .bind(b"ns".as_slice())
        .execute(pool)
        .await?;
    ensure!(
        update.rows_affected() == 1,
        "CLIENT_FOUND_ROWS unchanged UPDATE must report 1"
    );
    let upsert = sqlx::query("INSERT INTO record(identity,other_key,payload,opaque) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE opaque=VALUES(opaque)")
        .bind(b"ns".as_slice()).bind(b"other".as_slice()).bind(sqlx::types::Json(&parsed)).bind(raw).execute(pool).await?;
    ensure!(
        upsert.rows_affected() == 1,
        "CLIENT_FOUND_ROWS unchanged UPSERT must report 1"
    );
    let changed = sqlx::query("INSERT INTO record(identity,other_key,payload,opaque) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE opaque=VALUES(opaque)")
        .bind(b"ns".as_slice()).bind(b"other".as_slice()).bind(sqlx::types::Json(&parsed)).bind("new").execute(pool).await?;
    ensure!(changed.rows_affected() == 2, "changed UPSERT must report 2");
    let untouched: Vec<u8> = sqlx::query_scalar("SELECT opaque FROM record WHERE identity=?")
        .bind(b"ns ".as_slice())
        .fetch_one(pool)
        .await?;
    ensure!(
        String::from_utf8(untouched)? == raw,
        "upsert confused binary identities"
    );
    for (identity, other, payload, expected) in [
        ("new1", "fresh1", "{", 3140),
        ("new2", "fresh2", "{}", 1452),
    ] {
        let mut transaction = pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO record(identity,other_key,payload,opaque,parent_id) VALUES(?,?,?, '',?)",
        )
        .bind(identity.as_bytes())
        .bind(other.as_bytes())
        .bind(payload)
        .bind(b"missing".as_slice())
        .execute(&mut *transaction)
        .await;
        expect_number(result, expected)?;
        transaction.rollback().await?;
    }
    for value in [128_i64, -129_i64] {
        let mut transaction = pool.begin().await?;
        expect_number(sqlx::query("INSERT INTO record(identity,other_key,payload,opaque,small) VALUES('overflow','overflow','{}','',?)").bind(value).execute(&mut *transaction).await, 1264)?;
        transaction.rollback().await?;
    }
    expect_number(sqlx::query("INSERT INTO record(identity,other_key,payload,opaque) VALUES(REPEAT('x',65),'length','{}','')").execute(pool).await, 1406)?;
    let mut collision_errors = Vec::new();
    for (identity, other, payload, replay) in [
        ("ns", "other", parsed.clone(), true),
        ("different", "other", parsed.clone(), false),
        ("ns", "other3", json!({"different":true}), false),
    ] {
        let mut transaction = pool.begin().await?;
        let error =
            sqlx::query("INSERT INTO record(identity,other_key,payload,opaque) VALUES(?,?,?,'')")
                .bind(identity.as_bytes())
                .bind(other.as_bytes())
                .bind(sqlx::types::Json(&payload))
                .execute(&mut *transaction)
                .await
                .err()
                .ok_or_else(|| anyhow::anyhow!("ordinary INSERT must not silently upsert"))?;
        ensure!(
            super::helper::number(&error)? == 1062,
            "collision must preserve original 1062"
        );
        let existing =
            sqlx::query("SELECT id,other_key,payload FROM record WHERE identity=? FOR UPDATE")
                .bind(identity.as_bytes())
                .fetch_optional(&mut *transaction)
                .await?;
        let accepted = if let Some(row) = existing {
            let old: sqlx::types::Json<Value> = row.try_get("payload")?;
            old.0 == payload && row.try_get::<Vec<u8>, _>("other_key")? == other.as_bytes()
        } else {
            false
        };
        ensure!(
            accepted == replay,
            "canonical replay accepted wrong identity/payload or rejected exact replay"
        );
        collision_errors.push(error.to_string());
        transaction.rollback().await?;
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM record")
        .fetch_one(pool)
        .await?;
    ensure!(count == 2, "error path added rows");
    for (i, value) in [
        json!([1, "x", null]),
        json!(true),
        json!(null),
        json!(9007199254740993_u64),
        json!(u64::MAX),
    ]
    .iter()
    .enumerate()
    {
        sqlx::query("UPDATE record SET payload=? WHERE id=?")
            .bind(sqlx::types::Json(value))
            .bind(first_id)
            .execute(pool)
            .await?;
        let observed: sqlx::types::Json<Value> =
            sqlx::query_scalar("SELECT payload FROM record WHERE id=?")
                .bind(first_id)
                .fetch_one(pool)
                .await?;
        ensure!(
            &observed.0 == value,
            "JSON root/precision fixture {i} changed"
        );
    }
    let nulls = sqlx::query("SELECT JSON_EXTRACT('{\"present\":null}', '$.present') IS NULL AS json_null,JSON_EXTRACT('{}','$.present') IS NULL AS missing,CAST(NULL AS JSON) IS NULL AS sql_null").fetch_one(pool).await?;
    ensure!(
        nulls.try_get::<i32, _>("json_null")? == 0
            && nulls.try_get::<i32, _>("missing")? == 1
            && nulls.try_get::<i32, _>("sql_null")? == 1,
        "missing/JSON null/SQL null collapsed"
    );
    conditional(pool).await?;
    json_identity(pool).await?;
    let joined: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM record r JOIN parent p ON p.id=r.parent_id WHERE p.id=?",
    )
    .bind(b"k".as_slice())
    .fetch_one(pool)
    .await?;
    ensure!(joined == 1, "binary FK join matched tail-space identity");
    let collation = sqlx::query("SELECT 'A' COLLATE utf8mb4_bin = 'a' COLLATE utf8mb4_bin AS case_equal,'k' COLLATE utf8mb4_bin = 'k ' COLLATE utf8mb4_bin AS pad_equal").fetch_one(pool).await?;
    ensure!(
        collation.try_get::<i32, _>("case_equal")? == 0,
        "utf8mb4_bin must distinguish case"
    );
    Ok(
        json!({"last_insert_id":own_last,"previous_session_last_id":last,"collision_errors":collision_errors,"pad_space_equal":collation.try_get::<i32,_>("pad_equal")?,"json": "semantic precise roots; opaque raw preserved","affected_rows":[1,1,2],"constraint_branch":"checked_materialized"}),
    )
}

async fn conditional(pool: &MySqlPool) -> Result<()> {
    sqlx::query(
        "INSERT INTO conditional VALUES(1,1,'a','a'),(2,0,'a',NULL),(3,0,'a',NULL),(4,1,NULL,NULL)",
    )
    .execute(pool)
    .await?;
    for sql in [
        "INSERT INTO conditional(id,live,source) VALUES(5,1,'b')",
        "INSERT INTO conditional VALUES(5,1,'b',NULL)",
        "INSERT INTO conditional VALUES(5,1,'b','wrong')",
        "UPDATE conditional SET live=0 WHERE id=1",
        "UPDATE conditional SET source='b' WHERE id=1",
        "UPDATE conditional SET key_col=NULL WHERE id=1",
    ] {
        expect_number(sqlx::query(sql).execute(pool).await, 3819)?;
    }
    expect_number(
        sqlx::query("INSERT INTO conditional VALUES(5,1,'a','a')")
            .execute(pool)
            .await,
        1062,
    )?;
    expect_number(
        sqlx::query("INSERT INTO conditional VALUES(5,NULL,'b',NULL)")
            .execute(pool)
            .await,
        1048,
    )?;
    sqlx::query("INSERT INTO composite VALUES(1,1,'a','b','a','b'),(2,0,'a','b',NULL,NULL),(3,0,'a','b',NULL,NULL),(4,1,NULL,'b',NULL,'b')").execute(pool).await?;
    for sql in [
        "INSERT INTO composite VALUES(5,1,'a','c',NULL,'c')",
        "INSERT INTO composite VALUES(5,1,'a','c','a',NULL)",
        "UPDATE composite SET source_b='x' WHERE id=1",
        "UPDATE composite SET live=0 WHERE id=1",
    ] {
        expect_number(sqlx::query(sql).execute(pool).await, 3819)?;
    }
    expect_number(
        sqlx::query("INSERT INTO composite VALUES(5,1,'a','b','a','b')")
            .execute(pool)
            .await,
        1062,
    )?;
    Ok(())
}

async fn json_identity(pool: &MySqlPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE bindings(id BIGINT PRIMARY KEY,opaque LONGTEXT NOT NULL,parsed JSON)",
    )
    .execute(pool)
    .await?;
    let cases = [
        ("{\"account\":\"account\"}", true),
        (" { \"extra\":1, \"account\":\"account\" } ", true),
        ("{\"account\":\"wrong\",\"account\":\"account\"}", true),
        ("{\"account\":\"account\",\"account\":\"wrong\"}", false),
        ("{}", false),
        ("{\"account\":1}", false),
        ("{\"nested\":{\"account\":\"account\"}}", false),
        ("{\"account\":\"account \"}", false),
        ("{\"account\":\"xaccount\"}", false),
        ("{\"account\":\"account%\"}", false),
        ("[\"account\"]", false),
        ("invalid", false),
        ("null", false),
        ("\"account\"", false),
    ];
    for (index, (opaque, expected)) in cases.iter().enumerate() {
        let parsed = serde_json::from_str::<Value>(opaque).ok();
        sqlx::query("INSERT INTO bindings VALUES(?,?,?)")
            .bind(index as i64)
            .bind(opaque)
            .bind(parsed.map(sqlx::types::Json))
            .execute(pool)
            .await?;
        let matched: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bindings WHERE id=? AND JSON_TYPE(parsed)='OBJECT' AND JSON_TYPE(JSON_EXTRACT(parsed,'$.account'))='STRING' AND CAST(JSON_UNQUOTE(JSON_EXTRACT(parsed,'$.account')) AS BINARY)=?")
            .bind(index as i64).bind(b"account".as_slice()).fetch_one(pool).await?;
        ensure!(
            (matched == 1) == *expected,
            "top-level exact JSON string match failed for {opaque}"
        );
        let actual: Vec<u8> = sqlx::query_scalar("SELECT opaque FROM bindings WHERE id=?")
            .bind(index as i64)
            .fetch_one(pool)
            .await?;
        ensure!(
            String::from_utf8(actual)? == *opaque,
            "opaque binding text changed"
        );
    }
    Ok(())
}
