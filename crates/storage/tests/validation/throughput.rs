use {
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sqlx::{Connection, MySqlConnection, MySqlPool, Row},
    std::{
        collections::BTreeMap,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    },
    tokio::{
        task::JoinSet,
        time::{Instant, interval, timeout},
    },
};

use super::{
    helper::{Config, Evidence, Fixture, fixture_path, hash},
    hybrid::{self, Ann},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    schema_version: u32,
    memory_limit_bytes: u64,
    profiles: Vec<Profile>,
    selection_order: Vec<String>,
    seed_profile_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    id: String,
    chunks_per_logical: usize,
    dimensions: Vec<usize>,
    memory_budget_bytes: u64,
    headroom_bytes: u64,
    current_generations: usize,
    next_generations: usize,
    retained_generations: usize,
    workspace_bytes: usize,
    gateway_query_load: usize,
    external_tool_queries: usize,
    fixture_sha256: String,
}

async fn memory(container: &str, kind: &str) -> Result<u64> {
    ensure!(
        ["current", "peak", "max"].contains(&kind),
        "unknown cgroup memory value"
    );
    let output = timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("docker")
            .args([
                "exec",
                container,
                "cat",
                &format!("/sys/fs/cgroup/memory.{kind}"),
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("cgroup read deadline")??;
    ensure!(
        output.status.success(),
        "actual DB container cgroup unavailable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}

pub async fn run(config: &Config, evidence: &mut Evidence) -> Result<()> {
    let bytes = std::fs::read(fixture_path("capacity_matrix.json"))?;
    let matrix: Matrix = serde_json::from_slice(&bytes)?;
    let ann_bytes = std::fs::read(fixture_path("ann.json"))?;
    let ann: Ann = serde_json::from_slice(&ann_bytes)?;
    ensure!(
        matrix.schema_version == 1
            && memory(&config.memory_container, "max").await? == matrix.memory_limit_bytes,
        "actual cgroup memory limit does not match frozen capacity input"
    );
    ensure!(
        matrix.profiles.len() == matrix.selection_order.len() && !matrix.profiles.is_empty(),
        "capacity profile ordering is incomplete"
    );
    let mut previous = 0;
    for id in &matrix.selection_order {
        let p = matrix
            .profiles
            .iter()
            .find(|p| &p.id == id)
            .context("selection order references unknown profile")?;
        ensure!(
            p.chunks_per_logical > previous
                && p.dimensions == [32, 768, 1536, 4096]
                && p.current_generations == 1
                && p.next_generations == 1
                && p.retained_generations >= 1
                && p.external_tool_queries == 2
                && p.gateway_query_load > 0,
            "capacity input does not cover bounded real old/new/retained/+2 overlap"
        );
        ensure!(
            p.memory_budget_bytes
                .checked_add(p.headroom_bytes)
                .is_some_and(|v| v <= matrix.memory_limit_bytes)
                && p.fixture_sha256 == hash(&ann_bytes),
            "capacity budget/headroom or fixed fixture hash mismatch"
        );
        previous = p.chunks_per_logical;
    }
    let mut outputs = BTreeMap::new();
    let mut selected = None;
    for id in &matrix.selection_order {
        let p = matrix
            .profiles
            .iter()
            .find(|p| &p.id == id)
            .context("unknown capacity profile")?;
        let mut dimensions = Vec::new();
        let mut failure = None;
        for dimension in &p.dimensions {
            let fixture = Fixture::create(config, "capacity", 16).await?;
            let result = measure(config, &fixture, p, *dimension, &ann).await;
            timeout(Duration::from_secs(60), fixture.finish(Ok(())))
                .await
                .context("capacity fixture cleanup deadline")??;
            match result {
                Ok(measurement) => dimensions.push(measurement),
                Err(error) => {
                    dimensions.push(json!({"dimensions":dimension,"excluded":error.to_string()}));
                    failure = Some(error.to_string());
                },
            }
        }
        if let Some(error) = failure {
            ensure!(
                id != &matrix.seed_profile_id,
                "preseeded viable capacity failed; cannot invent smaller profile after runtime: {error}"
            );
            outputs.insert(
                id.clone(),
                json!({"excluded":error,"dimensions":dimensions}),
            );
        } else {
            selected = Some(id.clone());
            outputs.insert(id.clone(), json!({"passed":true,"dimensions":dimensions}));
        }
    }
    let selected = selected.context("no frozen capacity profile passed")?;
    evidence.observations.insert("capacity".into(),json!({"matrix_sha256":hash(&bytes),"selected_for_this_architecture":selected,"profiles":outputs,"two_arch_selection":"requires signed common maximum aggregate; not selected from one architecture"}));
    Ok(())
}

async fn measure(
    config: &Config,
    fixture: &Fixture,
    p: &Profile,
    dimensions: usize,
    ann: &Ann,
) -> Result<Value> {
    let baseline = memory(&config.memory_container, "current").await?;
    let kernel_peak_before = memory(&config.memory_container, "peak").await?;
    let observed = Arc::new(AtomicU64::new(baseline));
    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&observed);
    let done = Arc::clone(&stop);
    let container = config.memory_container.clone();
    let mut sampler = JoinSet::new();
    sampler.spawn(async move {
        let mut ticker = interval(Duration::from_millis(100));
        loop {
            ticker.tick().await;
            let current = timeout(Duration::from_secs(10), memory(&container, "current")).await??;
            seen.fetch_max(current, Ordering::SeqCst);
            if done.load(Ordering::SeqCst) {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    let mut queries = JoinSet::new();
    let outcome = timeout(Duration::from_secs(1800), async {
        let mut connection = fixture.pool.acquire().await?;
        connection.close_on_drop();
        let result = async {
            sqlx::query("SET SESSION ob_query_timeout=120000000").execute(&mut *connection).await?;
            // Workspace remains resident through creation, indexing and all overlapping queries.
            let workspace = vec![0x5au8; p.workspace_bytes];
            let old_generations = p.current_generations + p.retained_generations;
            let mut tables = Vec::new();
            let mut q = ann.query.clone();
            q.resize(dimensions, 0.);
            sqlx::query("CREATE TABLE rebuild_meta(singleton INT PRIMARY KEY,next_generations BIGINT NOT NULL,epoch BIGINT NOT NULL)").execute(&mut *connection).await?;
            sqlx::query("INSERT INTO rebuild_meta VALUES(1,0,0)").execute(&mut *connection).await?;
            // Only current and retained indexes exist when query workers start.
            for logical in ["memory", "code"] {
                for generation in 0..old_generations {
                    let table = format!("{logical}_g{generation}");
                    populate_generation(&mut connection, &table, dimensions, p.chunks_per_logical, ann, None).await?;
                    tables.push(table);
                }
            }
            let prebuilt_db = memory(&config.memory_container, "current").await?;
            let admission_per_chunk = prebuilt_db.saturating_sub(baseline)
                .checked_add(p.workspace_bytes as u64).context("prebuilt envelope overflow")?
                .div_ceil(p.chunks_per_logical as u64)
                .checked_mul(2).context("prebuilt envelope overflow")?;
            let worker_count = p.gateway_query_load + p.external_tool_queries;
            let barrier = Arc::new(tokio::sync::Barrier::new(worker_count + 1));
            let phase = Arc::new(AtomicU64::new(0));
            let written = Arc::new(AtomicU64::new(0));
            let started = Instant::now();
            for index in 0..worker_count {
                let pool = fixture.pool.clone();
                let table = tables[index % tables.len()].clone();
                let query = q.clone();
                let barrier = Arc::clone(&barrier);
                let phase = Arc::clone(&phase);
                let written = Arc::clone(&written);
                let chunks = p.chunks_per_logical;
                let role = if index < p.gateway_query_load { "gateway" } else { "external_tool" };
                queries.spawn(async move {
                    let mut connection = pool.acquire().await?;
                    connection.close_on_drop();
                    let result = async {
                        sqlx::query("SET SESSION ob_query_timeout=120000000").execute(&mut *connection).await?;
                        let small = hybrid::sql(&table, &hybrid::dsl(Some("alpha"), Some(&query), 0, 10)?)?;
                        let maximum = hybrid::sql(&table, &hybrid::dsl(Some("alpha"), Some(&query), 0, 10000)?)?;
                        barrier.wait().await;
                        let mut rounds = 0;
                        let mut maximum_overlap = 0;
                        let mut population_overlap = 0;
                        let mut observed_writes = 0;
                        let mut first_overlap_us = None;
                        let mut last_overlap_us = None;
                        loop {
                            for (sql, limit) in [(&small, 10), (&maximum, 10000)] {
                                let before = phase.load(Ordering::SeqCst);
                                let writes_before = written.load(Ordering::SeqCst);
                                let query_start = started.elapsed().as_micros();
                                let rows = timeout(Duration::from_secs(120), sqlx::query(sql).fetch_all(&mut *connection)).await??;
                                let after = phase.load(Ordering::SeqCst);
                                let writes_after = written.load(Ordering::SeqCst);
                                hybrid::ranked(&rows, limit, Some(b"a"))?;
                                ensure!(rows.len() == chunks.min(limit), "overlap query lost requested scoped rows");
                                if limit == 10000 && (1..=2).contains(&before) && (1..=2).contains(&after) {
                                    maximum_overlap += 1;
                                    if before == 2 && after == 2 {
                                        population_overlap += 1;
                                    }
                                    observed_writes += writes_after - writes_before;
                                    first_overlap_us.get_or_insert(query_start);
                                    last_overlap_us = Some(started.elapsed().as_micros());
                                }
                            }
                            rounds += 1;
                            if phase.load(Ordering::SeqCst) == 3 && rounds >= 8 {
                                break;
                            }
                        }
                        ensure!(maximum_overlap > 0 && population_overlap > 0, "worker lacked W10000 during actual next-generation population");
                        Ok::<_, anyhow::Error>(json!({"worker":index,"role":role,"table":table,"rounds":rounds,"window":10000,"maximum_window_overlap_queries":maximum_overlap,"population_overlap_queries":population_overlap,"writes_observed_during_queries":observed_writes,"first_overlap_us":first_overlap_us,"last_overlap_us":last_overlap_us}))
                    }.await;
                    timeout(Duration::from_secs(10), connection.close()).await??;
                    result
                });
            }
            timeout(Duration::from_secs(30), barrier.wait()).await.context("query worker startup deadline")?;
            let rebuild_start_us = started.elapsed().as_micros();
            let mut admissions = Vec::new();
            for logical in ["memory", "code"] {
                for generation in old_generations..old_generations + p.next_generations {
                    let table = format!("{logical}_g{generation}");
                    phase.store(1, Ordering::SeqCst);
                    let admitted = admit_generation(&mut connection, &table, dimensions, p.chunks_per_logical, ann, baseline, admission_per_chunk, p.memory_budget_bytes, Some((&phase, &written))).await?;
                    admissions.push(json!({"table":table,"baseline_bytes":baseline,"per_chunk_bytes":admission_per_chunk,"estimated_bytes":admitted}));
                    tables.push(table);
                }
            }
            phase.store(3, Ordering::SeqCst);
            let rebuild_end_us = started.elapsed().as_micros();
            let mut workers = Vec::new();
            while let Some(worker) = queries.join_next().await {
                workers.push(worker??);
            }
            ensure!(workers.iter().any(|worker| worker["writes_observed_during_queries"].as_u64().unwrap_or(0) > 0), "queries did not overlap completed next-generation writes");
            ensure!(written.load(Ordering::SeqCst) == (2 * p.next_generations * p.chunks_per_logical) as u64, "next generation population incomplete");
            ensure!(workspace.first() == Some(&0x5a) && workspace.last() == Some(&0x5a), "rebuild workspace not resident throughout overlap");
            let explain = format!("EXPLAIN {}", hybrid::sql(&tables[0], &hybrid::dsl(Some("alpha"), Some(&q), 0, 10000)?)?);
            let rows = sqlx::query(&explain).fetch_all(&mut *connection).await?;
            let mut plan = String::new();
            for row in rows {
                for index in 0..row.len() {
                    if let Ok(value) = row.try_get::<String, _>(index) {
                        plan.push_str(&value);
                        plan.push('\n');
                    }
                }
            }
            ensure!(plan.contains("vi") && plan.contains("INDEX"), "capacity high-dimensional gate lacked native index path");
            capacity_boundary(&mut connection, &fixture.pool, p.chunks_per_logical).await?;
            Ok::<_, anyhow::Error>(json!({"plan":plan,"simultaneous_queries":worker_count,"tables":tables,"chunks_per_table":p.chunks_per_logical,"prebuilt_generations_per_logical":old_generations,"next_generations_per_logical":p.next_generations,"next_rows_written":written.load(Ordering::SeqCst),"rebuild_start_us":rebuild_start_us,"rebuild_end_us":rebuild_end_us,"workers":workers,"admissions":admissions}))
        }.await;
        timeout(Duration::from_secs(10), connection.close()).await??;
        result
    }).await.context("capacity workload deadline").and_then(|result| result);
    // Every exit aborts and drains owned workers before the caller removes fixture objects.
    queries.shutdown().await;
    stop.store(true, Ordering::SeqCst);
    let sampled_result = timeout(Duration::from_secs(15), sampler.join_next()).await;
    sampler.shutdown().await;
    let workload = outcome?;
    sampled_result?.context("memory sampler missing")???;
    let sampled = observed.load(Ordering::SeqCst);
    let kernel_peak_after = memory(&config.memory_container, "peak").await?;
    // Do not reset a global cgroup peak mid-run; an older peak is a conservative upper bound.
    let db_peak = sampled.max(kernel_peak_after);
    let peak = db_peak
        .checked_add(p.workspace_bytes as u64)
        .context("measured workspace overlap overflow")?;
    ensure!(
        peak <= p.memory_budget_bytes,
        "measured overlap peak {peak} exceeds frozen budget {}",
        p.memory_budget_bytes
    );
    let measured_per_chunk = peak
        .saturating_sub(baseline)
        .div_ceil(p.chunks_per_logical as u64);
    let conservative_per_chunk = measured_per_chunk
        .checked_mul(2)
        .context("capacity estimate overflow")?;
    let estimated = estimate(
        baseline,
        conservative_per_chunk,
        p.chunks_per_logical,
        p.memory_budget_bytes,
    )?;
    ensure!(
        estimated >= peak,
        "measured conservative estimate understates overlap"
    );
    let rejection = timeout(
        Duration::from_secs(120),
        reject_generation(fixture, p, dimensions, ann, conservative_per_chunk),
    )
    .await
    .context("capacity rejection deadline")??;
    Ok(
        json!({"dimensions":dimensions,"baseline_bytes":baseline,"peak_bytes":peak,"db_peak_bytes":db_peak,"resident_workspace_bytes":p.workspace_bytes,"sampled_peak_bytes":sampled,"kernel_peak_before":kernel_peak_before,"kernel_peak_after":kernel_peak_after,"headroom_bytes":p.headroom_bytes,"estimated_bytes":estimated,"conservative_per_chunk_bytes":conservative_per_chunk,"estimate_error_bytes":estimated-peak,"workload":workload,"pre_ddl_rejection":rejection}),
    )
}

// Concrete U1 workload only: this is not a future production rebuild consumer.
async fn populate_generation(
    connection: &mut MySqlConnection,
    table: &str,
    dimensions: usize,
    chunks: usize,
    ann: &Ann,
    overlap: Option<(&AtomicU64, &AtomicU64)>,
) -> Result<()> {
    ensure!(
        table
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "unsafe generation table"
    );
    ensure!(
        (1..=4096).contains(&dimensions) && !ann.records.is_empty(),
        "invalid generation dimensions or empty ANN fixture before DDL"
    );
    sqlx::query(&format!("CREATE TABLE {table}(chunk_id VARBINARY(128) NOT NULL,agent_scope VARBINARY(128) NOT NULL,content LONGTEXT NOT NULL,content_version BIGINT NOT NULL,content_hash VARBINARY(128) NOT NULL,UNIQUE INDEX pointer_unique(chunk_id),INDEX scope_idx(agent_scope),FULLTEXT INDEX ft(content),vec VECTOR({dimensions}),VECTOR INDEX vi(vec) WITH(distance=cosine,type=hnsw,lib=vsag)) ORGANIZATION HEAP")).execute(&mut *connection).await?;
    if let Some((phase, _)) = overlap {
        phase.store(2, Ordering::SeqCst);
    }
    let sql = format!(
        "INSERT INTO {table}(chunk_id,agent_scope,content,content_version,content_hash,vec) VALUES(?,?,?,1,?,?)"
    );
    let content_hash = hash(b"alpha");
    for index in 0..chunks {
        let row = &ann.records[index % ann.records.len()];
        let mut vector = row.vec.clone();
        vector.resize(dimensions, 0.);
        sqlx::query(&sql)
            .bind(format!("chunk{index:08}").as_bytes())
            .bind(b"a".as_slice())
            .bind("alpha")
            .bind(content_hash.as_bytes())
            .bind(hybrid::vector(&vector, dimensions)?)
            .execute(&mut *connection)
            .await?;
        if let Some((_, written)) = overlap {
            written.fetch_add(1, Ordering::SeqCst);
        }
    }
    Ok(())
}

async fn admit_generation(
    connection: &mut MySqlConnection,
    table: &str,
    dimensions: usize,
    chunks: usize,
    ann: &Ann,
    baseline: u64,
    per_chunk: u64,
    budget: u64,
    overlap: Option<(&AtomicU64, &AtomicU64)>,
) -> Result<u64> {
    let estimated = estimate(baseline, per_chunk, chunks, budget)?;
    populate_generation(connection, table, dimensions, chunks, ann, overlap).await?;
    sqlx::query("UPDATE rebuild_meta SET next_generations=next_generations+1,epoch=epoch+1 WHERE singleton=1").execute(connection).await?;
    Ok(estimated)
}

async fn reject_generation(
    fixture: &Fixture,
    p: &Profile,
    dimensions: usize,
    ann: &Ann,
    per_chunk: u64,
) -> Result<Value> {
    let increment = per_chunk
        .checked_mul(p.chunks_per_logical as u64)
        .context("rejection envelope overflow")?;
    ensure!(
        increment > 0 && increment <= p.memory_budget_bytes,
        "no fitting-baseline rejection boundary"
    );
    let baseline = p.memory_budget_bytes - increment + 1;
    let mut connection = fixture.pool.acquire().await?;
    connection.close_on_drop();
    let result = async {
        sqlx::query("SET SESSION ob_query_timeout=120000000").execute(&mut *connection).await?;
        let before = generation_snapshot(&mut connection, p).await?;
        let rejected = admit_generation(&mut connection, "rejected_next", dimensions, p.chunks_per_logical, ann, baseline, per_chunk, p.memory_budget_bytes, None).await;
        ensure!(rejected.err().is_some_and(|error| error.to_string() == "pre-DDL capacity budget rejection"), "real pre-DDL operation did not reject the fitting-baseline over-budget candidate");
        let after = generation_snapshot(&mut connection, p).await?;
        ensure!(before == after && after["rejected_tables"] == 0, "budget rejection changed actual generation tables or metadata");
        Ok::<_, anyhow::Error>(json!({"baseline_bytes":baseline,"baseline_source":"synthetic fitting baseline at measured per-chunk boundary","baseline_fits_budget":baseline <= p.memory_budget_bytes,"candidate_bytes":baseline.checked_add(increment).context("rejection overflow")?,"budget_bytes":p.memory_budget_bytes,"before":before,"after":after}))
    }.await;
    timeout(Duration::from_secs(10), connection.close()).await??;
    result
}

async fn generation_snapshot(connection: &mut MySqlConnection, p: &Profile) -> Result<Value> {
    let meta = sqlx::query("SELECT next_generations,epoch FROM rebuild_meta WHERE singleton=1")
        .fetch_one(&mut *connection)
        .await?;
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()",
    )
    .fetch_one(&mut *connection)
    .await?;
    let rejected: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='rejected_next'").fetch_one(&mut *connection).await?;
    let mut rows = BTreeMap::new();
    for logical in ["memory", "code"] {
        for generation in 0..p.current_generations + p.retained_generations + p.next_generations {
            let table = format!("{logical}_g{generation}");
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&mut *connection)
                .await?;
            ensure!(
                count == p.chunks_per_logical as i64,
                "admitted generation lost rows"
            );
            rows.insert(table, count);
        }
    }
    let next = meta.try_get::<i64, _>("next_generations")?;
    let epoch = meta.try_get::<i64, _>("epoch")?;
    ensure!(
        next == (2 * p.next_generations) as i64 && epoch == next,
        "admitted generation metadata incomplete"
    );
    Ok(
        json!({"tables":tables,"rejected_tables":rejected,"next_generations":next,"epoch":epoch,"rows":rows}),
    )
}

fn estimate(baseline: u64, per_chunk: u64, chunks: usize, budget: u64) -> Result<u64> {
    let estimated = baseline
        .checked_add(
            per_chunk
                .checked_mul(chunks as u64)
                .context("capacity estimate overflow")?,
        )
        .context("capacity estimate overflow")?;
    ensure!(estimated <= budget, "pre-DDL capacity budget rejection");
    Ok(estimated)
}

async fn capacity_boundary(
    connection: &mut MySqlConnection,
    pool: &MySqlPool,
    max: usize,
) -> Result<()> {
    sqlx::query("CREATE TABLE capacity_meta(singleton INT PRIMARY KEY,chunks BIGINT NOT NULL,epoch BIGINT NOT NULL)").execute(&mut *connection).await?;
    sqlx::query("INSERT INTO capacity_meta VALUES(1,0,0)")
        .execute(&mut *connection)
        .await?;
    sqlx::query("CREATE TABLE capacity_business(id BIGINT PRIMARY KEY)")
        .execute(&mut *connection)
        .await?;
    sqlx::query("CREATE TABLE capacity_projection(id BIGINT UNIQUE)")
        .execute(&mut *connection)
        .await?;
    for count in [max, max + 1] {
        let mut tx = connection.begin().await?;
        let row =
            sqlx::query("SELECT chunks,epoch FROM capacity_meta WHERE singleton=1 FOR UPDATE")
                .fetch_one(&mut *tx)
                .await?;
        let chunks: i64 = row.try_get("chunks")?;
        if count > max {
            tx.rollback().await?;
            let stable: i64 =
                sqlx::query_scalar("SELECT chunks FROM capacity_meta WHERE singleton=1")
                    .fetch_one(&mut *connection)
                    .await?;
            ensure!(stable == max as i64, "over-cap rejection changed metadata");
            continue;
        }
        ensure!(chunks == 0, "empty generation capacity seed unexpected");
        for id in 0..count {
            sqlx::query("INSERT INTO capacity_business VALUES(?)")
                .bind(id as i64)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO capacity_projection VALUES(?)")
                .bind(id as i64)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE capacity_meta SET chunks=?,epoch=epoch+1 WHERE singleton=1")
            .bind(count as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    let counts=sqlx::query("SELECT (SELECT COUNT(*) FROM capacity_business) AS business,(SELECT COUNT(*) FROM capacity_projection) AS projection,(SELECT epoch FROM capacity_meta) AS epoch").fetch_one(&mut *connection).await?;
    ensure!(
        counts.try_get::<i64, _>("business")? == max as i64
            && counts.try_get::<i64, _>("projection")? == max as i64
            && counts.try_get::<i64, _>("epoch")? == 1,
        "capacity bound violated business/projection/epoch atomicity"
    );
    let mut first = connection.begin().await?;
    let _: i64 =
        sqlx::query_scalar("SELECT chunks FROM capacity_meta WHERE singleton=1 FOR UPDATE")
            .fetch_one(&mut *first)
            .await?;
    sqlx::query("INSERT INTO capacity_business VALUES(?)")
        .bind(max as i64)
        .execute(&mut *first)
        .await?;
    sqlx::query("INSERT INTO capacity_projection VALUES(?)")
        .bind(max as i64)
        .execute(&mut *first)
        .await?;
    let mut second_connection = pool.acquire().await?;
    second_connection.close_on_drop();
    sqlx::query("SET SESSION ob_query_timeout=120000000")
        .execute(&mut *second_connection)
        .await?;
    let mut second = second_connection.begin().await?;
    {
        let waiting = sqlx::query_scalar::<_, i64>(
            "SELECT chunks FROM capacity_meta WHERE singleton=1 FOR UPDATE",
        )
        .fetch_one(&mut *second);
        tokio::pin!(waiting);
        ensure!(
            timeout(Duration::from_millis(100), &mut waiting)
                .await
                .is_err(),
            "writer bypassed same capacity metadata lock"
        );
        first.rollback().await?;
        let current = timeout(Duration::from_secs(10), waiting).await??;
        ensure!(
            current == max as i64,
            "capacity waiter observed rolled-back chunk increment"
        );
    }
    second.rollback().await?;
    timeout(Duration::from_secs(10), second_connection.close()).await??;
    let leaked:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM capacity_business WHERE id=?)+(SELECT COUNT(*) FROM capacity_projection WHERE id=?)").bind(max as i64).bind(max as i64).fetch_one(&mut *connection).await?;
    ensure!(
        leaked == 0,
        "over-limit transaction left business/projection rows"
    );
    Ok(())
}
