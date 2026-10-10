use {
    super::helper::{
        Config, ConnectorInventory, Evidence, Fixture, ParserInputs, expect_number, fixture_path,
        statements,
    },
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sqlx::{MySqlPool, Row},
    std::collections::BTreeSet,
};

#[derive(Deserialize)]
struct Corpus {
    records: Vec<Record>,
    queries: Vec<Query>,
}
#[derive(Deserialize)]
struct Record {
    key: String,
    scope: String,
    content: String,
}
#[derive(Deserialize)]
struct Query {
    text: String,
    positive: Vec<String>,
    negative: Vec<String>,
}

fn section<'a>(source: &'a str, name: &str) -> Result<&'a str> {
    source
        .split(&format!("-- @{name}\n"))
        .nth(1)
        .map(|s| s.split("-- @").next().unwrap_or(s))
        .context("missing frozen connector SQL section")
}

pub async fn run(config: &Config, evidence: &mut Evidence) -> Result<()> {
    let source = std::fs::read_to_string(fixture_path("connector_schema.sql"))?;
    let inventory = ConnectorInventory::load()?;
    ensure!(
        inventory.schema_sha256 == super::helper::hash(source.as_bytes()),
        "frozen connector schema/query input changed"
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (path, expected) in &inventory.baseline_sources {
        ensure!(
            expected == &super::helper::hash(&std::fs::read(root.join(path))?),
            "connector baseline source changed before branch selection: {path}"
        );
    }
    let corpus: Corpus = serde_json::from_slice(&std::fs::read(fixture_path("parser.json"))?)?;
    let packaged = ParserInputs::load(&config.parser_inputs)?;
    let mut failures = Vec::new();
    for fallback in [false, true] {
        for parser in ["default", "ngram", "ik"] {
            let fixture = Fixture::create(config, "connector", 5).await?;
            let result = check(&fixture, &source, &corpus, parser, fallback).await;
            fixture.finish(Ok(())).await?;
            match result {
                Ok(observed) => {
                    let candidate = packaged.candidate(parser)?;
                    let tuple = json!({"parser":candidate.sql_parser,"delivery":candidate.delivery,"configuration":candidate.configuration,"dictionary":candidate.dictionary,"mode":"native_boolean","query_configuration":packaged.query_mode_configuration.native_boolean});
                    let fingerprint =
                        super::helper::hash(serde_json::to_string(&tuple)?.as_bytes());
                    evidence.observations.insert("connector".into(),json!({"layout":if fallback {"heap_projection"}else{"direct"},"parser":parser,"query_mode":"native_boolean","tuple":tuple,"fingerprint":fingerprint,"observations":observed,"excluded":failures}));
                    return Ok(());
                },
                Err(error) => failures
                    .push(json!({"fallback":fallback,"parser":parser,"error":error.to_string()})),
            }
        }
    }
    anyhow::bail!("both frozen connector layouts failed all parser candidates: {failures:?}")
}

async fn check(
    fixture: &Fixture,
    source: &str,
    corpus: &Corpus,
    parser: &str,
    fallback: bool,
) -> Result<Value> {
    let pool = &fixture.pool;
    statements(pool, section(source, "base")?).await?;
    let definition = section(
        source,
        if fallback {
            "fallback"
        } else {
            "direct_index"
        },
    )?;
    let definition = if parser == "default" {
        definition.replace(" WITH PARSER {{parser}}", "")
    } else {
        definition.replace("{{parser}}", parser)
    };
    statements(pool, &definition).await?;
    for id in ["account", "otheraccount"] {
        sqlx::query("INSERT INTO connector_accounts(id,kind,name,config,enabled,created_at,updated_at) VALUES(?,'email','name','{}',1,1,1)").bind(id.as_bytes()).execute(pool).await?;
    }
    for (id, account) in [
        ("dataset", "account"),
        ("otherdataset", "account"),
        ("foreigndataset", "otheraccount"),
    ] {
        sqlx::query("INSERT INTO connector_datasets(id,account_id,name,config,enabled,created_at,updated_at) VALUES(?,?,'dataset','{}',1,1,1)").bind(id.as_bytes()).bind(account.as_bytes()).execute(pool).await?;
    }
    for row in &corpus.records {
        let dataset = if row.scope == "a" {
            "dataset"
        } else {
            "otherdataset"
        };
        sqlx::query("INSERT INTO connector_items(id,dataset_id,remote_id,kind,body_json,content_hash,created_at,stored_at,search_text) VALUES(?,?,?,'email','{}','hash',1,1,?)")
            .bind(row.key.as_bytes()).bind(dataset.as_bytes()).bind(row.key.as_bytes()).bind(&row.content).execute(pool).await?;
        if fallback {
            sqlx::query("INSERT INTO connector_items_search VALUES(?,?,?, ?,NULL)")
                .bind(row.key.as_bytes())
                .bind(dataset.as_bytes())
                .bind(b"account".as_slice())
                .bind(&row.content)
                .execute(pool)
                .await?;
        }
    }
    let query = section(
        source,
        if fallback {
            "fallback_query"
        } else {
            "direct_query"
        },
    )?;
    for case in &corpus.queries {
        let keys = keys(pool, query, &case.text, false, 100, 0).await?;
        ensure!(
            case.positive.iter().all(|key| keys.contains(key))
                && case.negative.iter().all(|key| !keys.contains(key)),
            "full connector joins/parser scope corpus failed {:?}: {keys:?}",
            case.text
        );
    }
    let mut tx = pool.begin().await?;
    let by_primary: Vec<u8> =
        sqlx::query_scalar("SELECT id FROM connector_items WHERE id='english' FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
    let by_unique:Vec<u8>=sqlx::query_scalar("SELECT id FROM connector_items WHERE dataset_id='dataset' AND remote_id='english' FOR UPDATE").fetch_one(&mut *tx).await?;
    ensure!(
        by_primary == by_unique,
        "connector primary/secondary lock identity mismatch"
    );
    if fallback {
        let pointer: Vec<u8> = sqlx::query_scalar(
            "SELECT item_id FROM connector_items_search WHERE item_id='english' FOR UPDATE",
        )
        .fetch_one(&mut *tx)
        .await?;
        ensure!(pointer == by_primary, "heap connector pointer lock failed");
    }
    tx.rollback().await?;
    if fallback {
        expect_number(sqlx::query("INSERT INTO connector_items_search SELECT * FROM connector_items_search WHERE item_id='english'").execute(pool).await,1062)?;
    }
    let original = keys(pool, query, "+alpha -beta", false, 100, 0).await?;
    let p1 = keys(pool, query, "+alpha -beta", false, 1, 0).await?;
    let p2 = keys(pool, query, "+alpha -beta", false, 1, 1).await?;
    ensure!(
        p1.is_disjoint(&p2) && p1.union(&p2).cloned().collect::<BTreeSet<_>>() == original,
        "stable connector item_id pagination duplicated or lost entries"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE connector_items SET deleted_at=123 WHERE id IN ('english','chinese')")
        .execute(&mut *tx)
        .await?;
    if fallback {
        sqlx::query("UPDATE connector_items_search SET deleted_at=123 WHERE item_id IN ('english','chinese')").execute(&mut *tx).await?;
    }
    tx.commit().await?;
    ensure!(
        !keys(pool, query, "alpha", false, 100, 0)
            .await?
            .contains("english"),
        "live filter did not exclude tombstone before paging"
    );
    let diagnostic = keys(pool, query, "alpha", true, 100, 0).await?;
    ensure!(
        diagnostic.contains("english") && !diagnostic.contains("chinese"),
        "diagnostic tombstone query returned nonmatching deleted content"
    );
    let text: Vec<u8> =
        sqlx::query_scalar("SELECT search_text FROM connector_items WHERE id='english'")
            .fetch_one(pool)
            .await?;
    ensure!(
        String::from_utf8(text)? == "alpha database retrieval",
        "soft-delete destroyed source text"
    );
    if fallback {
        let mut tx = pool.begin().await?;
        sqlx::query(
            "UPDATE connector_items SET search_text='replaced',deleted_at=NULL WHERE id='english'",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO connector_items_search VALUES('english','dataset','account','replaced',NULL) ON DUPLICATE KEY UPDATE search_text=VALUES(search_text),deleted_at=VALUES(deleted_at)").execute(&mut *tx).await?;
        tx.rollback().await?;
        ensure!(
            keys(pool, query, "alpha", true, 100, 0)
                .await?
                .contains("english"),
            "source/projection rollback lost old document"
        );
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM connector_items_search WHERE item_id='english'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM connector_items WHERE id='english'")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE search FROM connector_items_search search JOIN connector_datasets dataset ON dataset.id=search.dataset_id WHERE dataset.account_id='account'").execute(&mut *tx).await?;
        sqlx::query("DELETE FROM connector_accounts WHERE id='account'")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connector_items_search")
            .fetch_one(pool)
            .await?;
        ensure!(count == 0, "parent cascade left fallback projection orphan");
    } else {
        sqlx::query("DELETE FROM connector_accounts WHERE id='account'")
            .execute(pool)
            .await?;
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connector_items")
        .fetch_one(pool)
        .await?;
    ensure!(count == 0, "connector parent cascade left items");
    Ok(
        json!({"full_schema":true,"primary_and_unique_for_update":true,"tombstone":true,"stable_pages":true,"cascade":true}),
    )
}

async fn keys(
    pool: &MySqlPool,
    query: &str,
    text: &str,
    deleted: bool,
    limit: i64,
    offset: i64,
) -> Result<BTreeSet<String>> {
    let mut terms = Vec::new();
    for token in text.split_whitespace() {
        let (prefix, token) = if let Some(term) = token.strip_prefix('-') {
            ('-', term)
        } else {
            ('+', token.strip_prefix('+').unwrap_or(token))
        };
        for term in token
            .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
            .filter(|term| !term.is_empty())
        {
            terms.push(format!("{prefix}\"{term}\""));
        }
    }
    let text = terms.join(" ");
    let rows = sqlx::query(query)
        .bind(&text)
        .bind(b"account".as_slice())
        .bind(b"dataset".as_slice())
        .bind(i32::from(deleted))
        .bind(&text)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
    let mut previous = f64::INFINITY;
    let mut previous_key: Option<Vec<u8>> = None;
    let mut keys = BTreeSet::new();
    for row in rows {
        let score: f64 = row.try_get("__score")?;
        let key: Vec<u8> = row.try_get("id")?;
        ensure!(
            score.is_finite() && score <= previous,
            "connector score not descending"
        );
        if score == previous {
            ensure!(
                previous_key
                    .as_deref()
                    .is_none_or(|old| old <= key.as_slice()),
                "connector tied score pagination unstable key order"
            );
        }
        previous = score;
        previous_key = Some(key.clone());
        keys.insert(String::from_utf8(key)?);
    }
    Ok(keys)
}
