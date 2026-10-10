use std::{
    collections::{BTreeSet, HashSet},
    fmt::Write,
};

use {
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sqlx::{MySqlPool, Row, mysql::MySqlRow},
};

use super::helper::{Config, Evidence, Fixture, ParserInputs, expect_number, fixture_path, hash};

#[derive(Deserialize)]
pub struct Ann {
    pub rows: usize,
    pub dimensions: usize,
    pub k: usize,
    pub query: Vec<f32>,
    pub records: Vec<AnnRow>,
}
#[derive(Deserialize)]
pub struct AnnRow {
    pub key: String,
    pub scope: String,
    pub vec: Vec<f32>,
}
#[derive(Deserialize)]
struct Corpus {
    schema_version: u32,
    parser_order: Vec<String>,
    modes: std::collections::BTreeMap<String, String>,
    records: Vec<TextRow>,
    queries: Vec<TextQuery>,
}
#[derive(Deserialize)]
struct TextRow {
    key: String,
    scope: String,
    content: String,
}
#[derive(Deserialize)]
struct TextQuery {
    text: String,
    positive: Vec<String>,
    negative: Vec<String>,
}

pub fn window(offset: usize, limit: usize) -> Result<usize> {
    ensure!(limit > 0, "empty retrieval window");
    let window = offset
        .checked_add(limit)
        .context("retrieval window overflow")?;
    ensure!(window <= 10000, "retrieval window exceeds 10000");
    Ok(window)
}

pub fn vector(value: &[f32], dimensions: usize) -> Result<String> {
    ensure!(
        (1..=4096).contains(&dimensions)
            && value.len() == dimensions
            && value.iter().all(|v| v.is_finite()),
        "invalid dimension/length/non-finite vector before SQL"
    );
    Ok(serde_json::to_string(value)?)
}

pub fn text_query(text: &str) -> Value {
    let mut required = Vec::new();
    let mut excluded = Vec::new();
    for token in text.split_whitespace() {
        if let Some(term) = token.strip_prefix('-') {
            excluded.push(json!({"match":{"content":{"query":term,"operator":"AND"}}}));
        } else {
            required.push(json!({"match":{"content":{"query":token.strip_prefix('+').unwrap_or(token),"operator":"AND"}}}));
        }
    }
    let mut query = json!({"bool":{"filter":[{"term":{"agent_scope":"a"}}]}});
    if !required.is_empty() {
        query["bool"]["must"] = json!(required);
    }
    if !excluded.is_empty() {
        query["bool"]["must_not"] = json!(excluded);
    }
    query
}

pub fn dsl(
    text: Option<&str>,
    query: Option<&[f32]>,
    offset: usize,
    limit: usize,
) -> Result<Value> {
    let w = window(offset, limit)?;
    let mut dsl = json!({"from":offset,"size":limit});
    if let Some(text) = text {
        dsl["query"] = text_query(text);
    }
    if let Some(query) = query {
        dsl["knn"] = json!({"field":"vec","k":w,"query_vector":vector(query,query.len())?,"filter":[{"term":{"agent_scope":"a"}}],"search_options":{"filter_mode":"pre"}});
    }
    if text.is_some() && query.is_some() {
        dsl["rank"] = json!({"rrf":{"rank_constant":60,"rank_window_size":w}});
    }
    Ok(dsl)
}

pub fn sql(table: &str, dsl: &Value) -> Result<String> {
    ensure!(
        table
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "unsafe hybrid table identifier"
    );
    ensure!(
        dsl.get("sort").is_none(),
        "selected native RRF never supplies sort"
    );
    let text = serde_json::to_string(dsl)?;
    let mut sql = format!(
        "SELECT chunk_id,agent_scope,content,content_version,content_hash,__score FROM HYBRID_SEARCH(TABLE {table}, _utf8mb4 X'"
    );
    for byte in text.bytes() {
        write!(sql, "{byte:02x}")?;
    }
    sql.push_str("')");
    Ok(sql)
}

pub async fn search(pool: &MySqlPool, table: &str, dsl: &Value) -> Result<Vec<MySqlRow>> {
    Ok(sqlx::query(&sql(table, dsl)?).fetch_all(pool).await?)
}

pub fn ranked(rows: &[MySqlRow], limit: usize, scope: Option<&[u8]>) -> Result<()> {
    ensure!(rows.len() <= limit, "native retrieval exceeds limit");
    let mut seen = HashSet::new();
    let mut previous = f64::INFINITY;
    for row in rows {
        let key: Vec<u8> = row.try_get("chunk_id")?;
        let score: f64 = row.try_get("__score")?;
        ensure!(seen.insert(key), "duplicate projection pointer");
        ensure!(
            score.is_finite() && score <= previous,
            "nonfinite or increasing raw database score"
        );
        if let Some(scope) = scope {
            ensure!(
                row.try_get::<Vec<u8>, _>("agent_scope")? == scope,
                "cross-scope native recall"
            );
        }
        previous = score;
    }
    Ok(())
}

pub async fn create_search(
    pool: &MySqlPool,
    table: &str,
    dimensions: Option<usize>,
    parser: &str,
) -> Result<()> {
    ensure!(
        ["default", "ngram", "ik"].contains(&parser),
        "parser outside frozen inventory"
    );
    if let Some(dim) = dimensions {
        ensure!((1..=4096).contains(&dim), "dimension rejected before DDL");
    }
    let vector = dimensions
        .map(|dim| {
            format!(
                ",vec VECTOR({dim}),VECTOR INDEX vi(vec) WITH(distance=cosine,type=hnsw,lib=vsag)"
            )
        })
        .unwrap_or_default();
    let parser = if parser == "default" {
        String::new()
    } else {
        format!(" WITH PARSER {parser}")
    };
    sqlx::query(&format!("CREATE TABLE {table}(chunk_id VARBINARY(128) NOT NULL,agent_scope VARBINARY(128) NOT NULL,content LONGTEXT NOT NULL,content_version BIGINT NOT NULL,content_hash VARBINARY(128) NOT NULL,UNIQUE INDEX pointer_unique(chunk_id),INDEX scope_idx(agent_scope),FULLTEXT INDEX ft(content){parser}{vector}) ORGANIZATION HEAP")).execute(pool).await?;
    Ok(())
}

pub async fn insert(
    pool: &MySqlPool,
    table: &str,
    key: &str,
    scope: &str,
    text: &str,
    vec: Option<&[f32]>,
) -> Result<()> {
    let hash = hash(text.as_bytes());
    if let Some(vec) = vec {
        sqlx::query(&format!("INSERT INTO {table}(chunk_id,agent_scope,content,content_version,content_hash,vec) VALUES(?,?,?,1,?,?)"))
            .bind(key.as_bytes()).bind(scope.as_bytes()).bind(text).bind(hash.as_bytes()).bind(vector(vec,vec.len())?).execute(pool).await?;
    } else {
        sqlx::query(&format!("INSERT INTO {table}(chunk_id,agent_scope,content,content_version,content_hash) VALUES(?,?,?,1,?)"))
            .bind(key.as_bytes()).bind(scope.as_bytes()).bind(text).bind(hash.as_bytes()).execute(pool).await?;
    }
    Ok(())
}

pub async fn plan(pool: &MySqlPool, sql: &str) -> Result<String> {
    let rows = sqlx::query(&format!("EXPLAIN {sql}"))
        .fetch_all(pool)
        .await?;
    let mut output = String::new();
    for row in rows {
        for index in 0..row.len() {
            if let Ok(value) = row.try_get::<String, _>(index) {
                output.push_str(&value);
                output.push('\n');
            }
        }
    }
    ensure!(!output.is_empty(), "EXPLAIN did not yield observable plan");
    Ok(output)
}

pub async fn run(config: &Config, evidence: &mut Evidence) -> Result<()> {
    let inputs = ParserInputs::load(&config.parser_inputs)?;
    let corpus: Corpus = serde_json::from_slice(&std::fs::read(fixture_path("parser.json"))?)?;
    ensure!(
        corpus.schema_version == 1 && corpus.parser_order == ["default", "ngram", "ik"],
        "parser matrix input changed"
    );
    for table in ["memory_chunks_search", "code_chunks_search"] {
        ensure!(
            corpus.modes.get(table).map(String::as_str) == Some("sql_hybrid_bool_rrf60"),
            "parser mode changed outside frozen matrix"
        );
        let mut selected = None;
        let mut excluded = Vec::new();
        for parser in &corpus.parser_order {
            let fixture = Fixture::create(config, "parser", 5).await?;
            let result = parser_check(&fixture, table, parser, &corpus, &inputs).await;
            fixture.finish(Ok(())).await?;
            match result {
                Ok(fingerprint) => {
                    selected = Some(
                        json!({"parser":parser,"query_mode":"sql_hybrid_bool_rrf60","fingerprint":fingerprint,"excluded":excluded}),
                    );
                    break;
                },
                Err(error) => excluded.push(json!({"parser":parser,"error":error.to_string()})),
            }
        }
        evidence.observations.insert(
            format!("parser:{table}"),
            selected.context(
                "no frozen parser/mode combination passed complete positive/negative corpus",
            )?,
        );
    }
    let fixture = Fixture::create(config, "hybrid", 5).await?;
    let result = core(&fixture).await;
    evidence
        .observations
        .insert("hybrid".into(), fixture.finish(result).await?);
    let fixture = Fixture::create(config, "ann", 8).await?;
    let result = ann(&fixture).await;
    evidence
        .observations
        .insert("ann".into(), fixture.finish(result).await?);
    Ok(())
}

async fn parser_check(
    fixture: &Fixture,
    table: &str,
    parser: &str,
    corpus: &Corpus,
    inputs: &ParserInputs,
) -> Result<String> {
    create_search(&fixture.pool, table, Some(32), parser).await?;
    let query = vec![1.0; 32];
    for row in &corpus.records {
        insert(
            &fixture.pool,
            table,
            &row.key,
            &row.scope,
            &row.content,
            Some(&query),
        )
        .await?;
    }
    let candidate = inputs.candidate(parser)?;
    let tuple = json!({"table":table,"parser":candidate.sql_parser,"delivery":candidate.delivery,"configuration":candidate.configuration,"dictionary":candidate.dictionary,"mode":"sql_hybrid_bool_rrf60","query_configuration":inputs.query_mode_configuration.sql_hybrid_bool_rrf60});
    let fingerprint = hash(serde_json::to_string(&tuple)?.as_bytes());
    sqlx::query("CREATE TABLE parser_identity(table_name VARBINARY(128) PRIMARY KEY,fingerprint VARBINARY(64) NOT NULL,tuple JSON NOT NULL)").execute(&fixture.pool).await?;
    sqlx::query("INSERT INTO parser_identity VALUES(?,?,?)")
        .bind(table.as_bytes())
        .bind(fingerprint.as_bytes())
        .bind(sqlx::types::Json(&tuple))
        .execute(&fixture.pool)
        .await?;
    for query in &corpus.queries {
        ensure_parser(&fixture.pool, table, &fingerprint).await?;
        let rows = search(&fixture.pool, table, &dsl(Some(&query.text), None, 0, 100)?).await?;
        ranked(&rows, 100, Some(b"a"))?;
        let keys: BTreeSet<String> = rows
            .iter()
            .map(|r| Ok(String::from_utf8(r.try_get("chunk_id")?)?))
            .collect::<Result<_>>()?;
        ensure!(
            query.positive.iter().all(|k| keys.contains(k))
                && query.negative.iter().all(|k| !keys.contains(k)),
            "{table}/{parser} exact positive/negative matrix failed {:?}: {:?}",
            query.text,
            keys
        );
    }
    for change in [
        "mode",
        "dictionary",
        "delivery",
        "configuration",
        "query_configuration",
    ] {
        let mut changed = tuple.clone();
        changed[change] = json!("changed");
        let candidate = hash(serde_json::to_string(&changed)?.as_bytes());
        ensure!(
            ensure_parser(&fixture.pool, table, &candidate)
                .await
                .is_err(),
            "kept old index accepted changed {change} before SQL"
        );
    }
    sqlx::query("UPDATE parser_identity SET fingerprint='forged' WHERE table_name=?")
        .bind(table.as_bytes())
        .execute(&fixture.pool)
        .await?;
    ensure!(
        ensure_parser(&fixture.pool, table, &fingerprint)
            .await
            .is_err(),
        "forged persisted parser fingerprint accepted"
    );
    sqlx::query("UPDATE parser_identity SET fingerprint=? WHERE table_name=?")
        .bind(fingerprint.as_bytes())
        .bind(table.as_bytes())
        .execute(&fixture.pool)
        .await?;
    ensure_parser(&fixture.pool, table, &fingerprint).await?;
    Ok(fingerprint)
}

async fn ensure_parser(pool: &MySqlPool, table: &str, expected: &str) -> Result<()> {
    let actual: Vec<u8> =
        sqlx::query_scalar("SELECT fingerprint FROM parser_identity WHERE table_name=?")
            .bind(table.as_bytes())
            .fetch_one(pool)
            .await?;
    ensure!(
        actual == expected.as_bytes(),
        "persisted parser identity differs; refuse query before retrieval SQL"
    );
    Ok(())
}

async fn core(fixture: &Fixture) -> Result<Value> {
    let pool = &fixture.pool;
    create_search(pool, "rank_probe", Some(3), "default").await?;
    let records = [
        ("vfirst", "ranking ranking ranking", vec![1., 0., 0.]),
        ("second", "ranking filler filler filler filler", vec![
            0.9, 0.1, 0.,
        ]),
        ("textfirst", "ranking ranking filler", vec![0.7, 0.3, 0.]),
    ];
    for (key, text, vec) in &records {
        insert(pool, "rank_probe", key, "a", text, Some(vec)).await?;
    }
    insert(
        pool,
        "rank_probe",
        "foreign",
        "ab",
        "ranking ranking ranking ranking",
        Some(&[1., 0., 0.]),
    )
    .await?;
    let query = [1., 0., 0.];
    let mixed = dsl(Some("ranking"), Some(&query), 0, 3)?;
    let bound = sqlx::query("SELECT chunk_id,__score FROM HYBRID_SEARCH(TABLE rank_probe,?)")
        .bind(serde_json::to_string(&mixed)?)
        .fetch_all(pool)
        .await;
    let transport = match bound {
        Ok(rows) => {
            ensure!(rows.len() == 3, "prepared DSL incomplete result");
            "prepared_and_hex"
        },
        Err(sqlx::Error::Database(e)) => {
            ensure!(
                e.code().as_deref() == Some("42000"),
                "unexpected prepared DSL failure {e}"
            );
            "utf8_hex"
        },
        Err(e) => return Err(e.into()),
    };
    let rows = search(pool, "rank_probe", &mixed).await?;
    ranked(&rows, 3, Some(b"a"))?;
    ensure!(
        rows.len() == 3,
        "RRF oracle needs all three actual candidates"
    );
    let vector_rows = search(pool, "rank_probe", &dsl(None, Some(&query), 0, 3)?).await?;
    let text_rows = search(pool, "rank_probe", &dsl(Some("ranking"), None, 0, 3)?).await?;
    ranked(&vector_rows, 3, Some(b"a"))?;
    ranked(&text_rows, 3, Some(b"a"))?;
    for row in &rows {
        let key: Vec<u8> = row.try_get("chunk_id")?;
        let mut expected = 0.;
        for path in [&vector_rows, &text_rows] {
            if let Some(index) = path
                .iter()
                .position(|r| r.try_get::<Vec<u8>, _>("chunk_id").is_ok_and(|k| k == key))
            {
                expected += 1. / (60. + (index + 1) as f64);
            }
        }
        ensure!(
            (row.try_get::<f64, _>("__score")? - expected).abs() < 1e-10,
            "explicit RRF60 disagrees with independent actual path ranks"
        );
    }
    let mut constant_one = mixed.clone();
    constant_one["rank"]["rrf"]["rank_constant"] = json!(1);
    let one = search(pool, "rank_probe", &constant_one).await?;
    ensure!(
        one[0].try_get::<f64, _>("__score")? > rows[0].try_get::<f64, _>("__score")?,
        "RRF constant ignored"
    );
    let mut text_only_scope = mixed.clone();
    text_only_scope["knn"]
        .as_object_mut()
        .context("knn object")?
        .remove("filter");
    let leaked = search(pool, "rank_probe", &text_only_scope).await?;
    ensure!(
        leaked.iter().any(|r| r
            .try_get::<Vec<u8>, _>("agent_scope")
            .is_ok_and(|s| s == b"ab")),
        "negative control: text-only filter unexpectedly isolates vector path"
    );
    let mut tx = pool.begin().await?;
    let locked: Vec<u8> =
        sqlx::query_scalar("SELECT chunk_id FROM rank_probe WHERE chunk_id=? FOR UPDATE")
            .bind(b"vfirst".as_slice())
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        locked == b"vfirst",
        "heap secondary unique FOR UPDATE failed"
    );
    tx.rollback().await?;
    expect_number(
        sqlx::query("INSERT INTO rank_probe SELECT * FROM rank_probe WHERE chunk_id='vfirst'")
            .execute(pool)
            .await,
        1062,
    )?;
    create_search(pool, "keyword_heap", None, "default").await?;
    insert(pool, "keyword_heap", "only", "a", "ranking", None).await?;
    let keyword = search(pool, "keyword_heap", &dsl(Some("ranking"), None, 0, 3)?).await?;
    ensure!(
        keyword.len() == 1,
        "keyword-only heap without vector failed"
    );
    insert(pool, "rank_probe", "nullvector", "a", "keywordonly", None).await?;
    ensure!(
        search(pool, "rank_probe", &dsl(Some("keywordonly"), None, 0, 3)?)
            .await?
            .len()
            == 1,
        "NULL vector keyword-only failed"
    );
    for dimensions in [768, 1536, 4096] {
        let table = format!("high{dimensions}");
        create_search(pool, &table, Some(dimensions), "default").await?;
        let q = vec![1.; dimensions];
        insert(pool, &table, "high", "a", "ranking", Some(&q)).await?;
        let rows = search(pool, &table, &dsl(Some("ranking"), Some(&q), 0, 1)?).await?;
        ranked(&rows, 1, Some(b"a"))?;
        ensure!(
            rows.len() == 1,
            "high-dimensional native mixed retrieval failed"
        );
        let bytes: Vec<u8> =
            sqlx::query_scalar(&format!("SELECT vec FROM {table} WHERE chunk_id='high'"))
                .fetch_one(pool)
                .await?;
        let parsed: Vec<f32> = serde_json::from_slice(&bytes)?;
        ensure!(
            parsed == q,
            "fixed build binary VECTOR readback contract failed"
        );
        let plan = plan(pool, &sql(&table, &dsl(Some("ranking"), Some(&q), 0, 1)?)?).await?;
        ensure!(
            plan.contains("vi") && plan.contains("INDEX"),
            "high-dimensional mixed query does not use native vector index"
        );
    }
    ensure!(
        vector(&[1.], 0).is_err()
            && vector(&[1.], 2).is_err()
            && vector(&vec![1.; 4097], 4097).is_err(),
        "dimension boundary must reject before SQL"
    );
    ensure!(
        window(usize::MAX, 1).is_err() && window(10000, 1).is_err() && window(9999, 1)? == 10000,
        "window boundary/overflow failed"
    );
    let special = "数据库 ' \\ ; DROP TABLE rank_probe; -- trailing ";
    insert(pool, "rank_probe", "literal", "a", special, Some(&query)).await?;
    let literal = dsl(Some(special), None, 0, 10)?;
    search(pool, "rank_probe", &literal).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rank_probe")
        .fetch_one(pool)
        .await?;
    ensure!(count == 6, "hex DSL added SQL statements");
    // Keep replay/rollback in the actual heap with both indexes active.
    sqlx::query("CREATE TABLE business(chunk_id VARBINARY(128) PRIMARY KEY,content LONGTEXT)")
        .execute(pool)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO business VALUES('rollback','value')")
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO rank_probe(chunk_id,agent_scope,content,content_version,content_hash,vec) VALUES('rollback','a','value',1,'hash','[1,0,0]')").execute(&mut *tx).await?;
    tx.rollback().await?;
    let absent:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM business)+(SELECT COUNT(*) FROM rank_probe WHERE chunk_id='rollback')").fetch_one(pool).await?;
    ensure!(absent == 0, "business/projection rollback not atomic");
    let raw: Vec<u8> = sqlx::query_scalar("SELECT vec FROM rank_probe WHERE chunk_id='vfirst'")
        .fetch_one(pool)
        .await?;
    ensure!(
        serde_json::from_slice::<Vec<f32>>(&raw)? == query,
        "VECTOR readback changed"
    );
    Ok(
        json!({"fusion":"rrf","rank_constant":60,"tie_order":"unspecified","retrieval":"ann","transport":transport,"sql":sql("rank_probe",&mixed)?,"plan":plan(pool,&sql("rank_probe",&mixed)?).await?,"dimensions":[768,1536,4096],"vector_wire":"binary UTF8 JSON"}),
    )
}

async fn ann(fixture: &Fixture) -> Result<Value> {
    let frozen: Ann = serde_json::from_slice(&std::fs::read(fixture_path("ann.json"))?)?;
    ensure!(
        frozen.rows == 10000
            && frozen.records.len() == 10000
            && frozen.dimensions == 32
            && frozen.k == 10
            && frozen.records.iter().filter(|r| r.scope == "a").count() == 100,
        "frozen ANN input distribution changed"
    );
    create_search(&fixture.pool, "ann_scope_probe", Some(32), "default").await?;
    for row in &frozen.records {
        insert(
            &fixture.pool,
            "ann_scope_probe",
            &row.key,
            &row.scope,
            "alpha",
            Some(&row.vec),
        )
        .await?;
    }
    let native = format!(
        "SELECT /*+ VECTOR_INDEX(ann_scope_probe vi pre_filter) */ chunk_id,agent_scope FROM ann_scope_probe WHERE agent_scope='a' ORDER BY cosine_distance(vec,'{}') APPROXIMATE LIMIT 10",
        vector(&frozen.query, 32)?
    );
    let rows = sqlx::query(&native).fetch_all(&fixture.pool).await?;
    ensure!(
        rows.len() == 10
            && rows.iter().all(|r| r
                .try_get::<Vec<u8>, _>("agent_scope")
                .is_ok_and(|s| s == b"a")),
        "1% filtered ANN did not return k scope-valid rows"
    );
    let native_plan = plan(&fixture.pool, &native).await?;
    ensure!(
        native_plan.contains("VECTOR INDEX") && native_plan.contains("PRE-FILTER"),
        "filtered ANN plan lacks native prefilter index scan"
    );
    let mixed = dsl(Some("alpha"), Some(&frozen.query), 0, 10)?;
    let rows = search(&fixture.pool, "ann_scope_probe", &mixed).await?;
    ranked(&rows, 10, Some(b"a"))?;
    ensure!(rows.len() == 10, "1% mixed ANN did not return k");
    let mixed_plan = plan(&fixture.pool, &sql("ann_scope_probe", &mixed)?).await?;
    ensure!(
        mixed_plan.contains("vi")
            && mixed_plan.contains("scope_idx")
            && mixed_plan.to_ascii_lowercase().contains("rrf"),
        "mixed plan lacks indexed scope/RRF"
    );
    // Actual maximum bounded query, not an arithmetic-only window assertion.
    let maximum = search(
        &fixture.pool,
        "ann_scope_probe",
        &dsl(Some("alpha"), Some(&frozen.query), 9999, 1)?,
    )
    .await?;
    ranked(&maximum, 1, Some(b"a"))?;
    let keys: Vec<String> = rows
        .iter()
        .map(|r| Ok(String::from_utf8(r.try_get("chunk_id")?)?))
        .collect::<Result<_>>()?;
    Ok(
        json!({"rows":10000,"dimensions":32,"k":10,"scope_fraction":0.01,"keys":keys,"native_plan":native_plan,"mixed_plan":mixed_plan}),
    )
}
