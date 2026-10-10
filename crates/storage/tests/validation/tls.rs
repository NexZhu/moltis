use {
    anyhow::{Context, Result, ensure},
    serde_json::json,
    sqlx::{
        Connection, MySqlConnection,
        mysql::{MySqlConnectOptions, MySqlSslMode},
    },
    std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    },
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::{Semaphore, oneshot},
        time::{Instant, timeout, timeout_at},
    },
};

use super::{
    helper::{
        Config, Evidence, Fixture, TlsExpectation, TlsHandshake, expect_number, hash, run_command,
    },
    hybrid,
};

pub async fn run(config: &Config, evidence: &mut Evidence) -> Result<()> {
    config.validate_tls_handshakes()?;
    if !evidence.tls_handshakes_verified {
        evidence.observations.insert(
            "tls_handshakes".into(),
            json!(negative_handshakes(config).await?),
        );
        evidence.tls_handshakes_verified = true;
    }
    let fixture = Fixture::create(config, "tls", 3).await?;
    let result = transport(config, &fixture).await;
    let observation = fixture.finish(result).await?;
    let success = observation
        .get("success_handshake")
        .context("TLS success observation missing")?
        .clone();
    evidence
        .observations
        .get_mut("tls_handshakes")
        .and_then(serde_json::Value::as_array_mut)
        .context("TLS negative observations missing")?
        .push(success);
    evidence.observations.insert("tls".into(), observation);
    let fixture = Fixture::create(config, "deadline", 3).await?;
    let result = deadlines(&fixture).await;
    fixture.finish(result).await?;
    evidence.observations.insert("deadline".into(),json!({"server_timeout_error":4012,"provider_send_and_body_canceled":true,"deadline":"single absolute; no budget restart"}));
    Ok(())
}

pub async fn negative_handshakes(config: &Config) -> Result<Vec<serde_json::Value>> {
    config.validate_tls_handshakes()?;
    let mut observations = Vec::new();
    for case in &config.tls_handshakes {
        if case.expectation == TlsExpectation::Success {
            continue;
        }
        let native = timeout(Duration::from_secs(30), run_command(&case.native_command))
            .await
            .with_context(|| format!("native TLS handshake {} timed out", case.name))??;
        let options = MySqlConnectOptions::new()
            .host(&case.host)
            .port(case.port)
            .username("root@sys")
            .password("")
            .ssl_mode(MySqlSslMode::VerifyIdentity)
            .ssl_ca(&case.ca);
        let connection = timeout(
            Duration::from_secs(10),
            MySqlConnection::connect_with(&options),
        )
        .await
        .with_context(|| format!("SQLx TLS handshake {} timed out", case.name))?;
        let sqlx_error = certificate_rejection(connection, case.expectation)
            .await
            .with_context(|| format!("SQLx TLS handshake {}", case.name))?;
        let stderr = String::from_utf8(native.stderr)?;
        let reasons: &[&str] = match case.expectation {
            TlsExpectation::WrongSan => &["Validation of SSL server certificate failed"],
            TlsExpectation::Expired => &["certificate has expired"],
            TlsExpectation::WrongCa => &[
                "self signed certificate in certificate chain",
                "unable to get local issuer certificate",
            ],
            TlsExpectation::Success => unreachable!(),
        };
        ensure!(
            !native.status.success()
                && reasons.iter().any(|reason| stderr.trim()
                    == format!("ERROR 2026 (HY000): SSL connection error: {reason}")),
            "native TLS handshake {} did not produce expected certificate rejection; exit={} stderr={stderr}",
            case.name,
            native.status
        );
        observations.push(handshake_observation(
            case,
            json!({"mode":"VerifyIdentity", "error_kind":"Io", "cause":sqlx_error}),
            json!({"exit_code":native.status.code(), "stderr":stderr}),
        )?);
    }
    Ok(observations)
}

async fn certificate_rejection(
    result: std::result::Result<MySqlConnection, sqlx::Error>,
    expected: TlsExpectation,
) -> Result<String> {
    match result {
        Err(sqlx::Error::Io(error)) => {
            let cause = error.to_string();
            let certificate = cause.strip_prefix("invalid peer certificate: ");
            let matches = match expected {
                TlsExpectation::WrongSan => certificate.is_some_and(|reason| {
                    reason == "NotValidForName"
                        || reason.starts_with("certificate not valid for name \"")
                }),
                TlsExpectation::Expired => certificate.is_some_and(|reason| {
                    reason == "Expired"
                        || reason.starts_with("certificate expired: verification time ")
                }),
                TlsExpectation::WrongCa => certificate == Some("UnknownIssuer"),
                TlsExpectation::Success => false,
            };
            ensure!(matches, "unexpected SQLx Io cause: {cause}");
            Ok(cause)
        },
        Err(error) => anyhow::bail!(
            "certificate rejection required, unrelated SQLx error: {error:?}: {error}"
        ),
        Ok(connection) => {
            connection.close().await?;
            anyhow::bail!("invalid certificate accepted by VerifyIdentity")
        },
    }
}

fn handshake_observation(
    case: &TlsHandshake,
    sqlx: serde_json::Value,
    native: serde_json::Value,
) -> Result<serde_json::Value> {
    Ok(
        json!({"name":case.name,"host":case.host,"port":case.port,"ca_sha256":hash(&std::fs::read(&case.ca)?),"expectation":case.expectation,"sqlx":sqlx,"native":native}),
    )
}

async fn transport(config: &Config, fixture: &Fixture) -> Result<serde_json::Value> {
    let mut correct = MySqlConnection::connect_with(&fixture.options).await?;
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut correct)
        .await?;
    ensure!(one == 1, "VerifyIdentity correct CA failed");
    correct.close().await?;
    let wrong =
        MySqlConnection::connect_with(&fixture.options.clone().ssl_ca(&config.wrong_ca)).await;
    let wrong_ca = certificate_rejection(wrong, TlsExpectation::WrongCa).await?;
    expect_number(
        MySqlConnection::connect_with(&fixture.options.clone().ssl_mode(MySqlSslMode::Disabled))
            .await,
        1045,
    )?;
    let native = timeout(
        Duration::from_secs(30),
        run_command(&config.native_tls_command),
    )
    .await
    .context("native canonical TLS handshake timed out")??;
    ensure!(
        native.status.success(),
        "native VerifyIdentity fixture failed: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    let status = String::from_utf8(native.stdout)?;
    let cipher = status
        .lines()
        .find_map(|line| {
            let (label, value) = line.split_once(':')?;
            if !label.trim().eq_ignore_ascii_case("SSL") {
                return None;
            }
            value
                .trim()
                .strip_prefix("Cipher in use is ")
                .filter(|cipher| !cipher.trim().is_empty())
        })
        .context("native status did not expose actual nonempty negotiated TLS cipher")?;
    let success = config
        .tls_handshakes
        .iter()
        .find(|case| case.expectation == TlsExpectation::Success)
        .context("canonical success TLS fixture missing")?;
    let success_handshake = handshake_observation(
        success,
        json!({"mode":"VerifyIdentity","select_one":one,"plaintext_error":1045}),
        json!({"exit_code":native.status.code(),"status":status,"cipher":cipher}),
    )?;
    Ok(
        json!({"sqlx":"VerifyIdentity","correct_ca":true,"wrong_ca":wrong_ca,"plaintext_error":1045,"native_status":status,"success_handshake":success_handshake}),
    )
}

async fn deadlines(fixture: &Fixture) -> Result<()> {
    hybrid::create_search(&fixture.pool, "deadline_search", None, "default").await?;
    hybrid::insert(
        &fixture.pool,
        "deadline_search",
        "keyword",
        "a",
        "fallbackword",
        None,
    )
    .await?;
    let mut server = MySqlConnection::connect_with(&fixture.options).await?;
    sqlx::query("SET SESSION ob_query_timeout=100000")
        .execute(&mut server)
        .await?;
    let readback: i64 = sqlx::query_scalar("SELECT @@SESSION.ob_query_timeout")
        .fetch_one(&mut server)
        .await?;
    ensure!(
        readback == 100000,
        "tenant timeout readback differs from microseconds"
    );
    expect_number(
        sqlx::query("SELECT SLEEP(1)").execute(&mut server).await,
        4012,
    )?;
    sqlx::query("SET SESSION ob_query_timeout=5000000")
        .execute(&mut server)
        .await?;
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut server)
        .await?;
    ensure!(one == 1, "server timeout poisoned next independent query");
    server.close().await?;
    let mut connection = fixture.pool.acquire().await?;
    connection.close_on_drop();
    ensure!(
        timeout(
            Duration::from_millis(100),
            sqlx::query("SELECT SLEEP(2)").execute(&mut *connection)
        )
        .await
        .is_err(),
        "client cancellation fixture did not reach running SQL"
    );
    connection.close().await?;
    let one: i32 = timeout(
        Duration::from_secs(10),
        sqlx::query_scalar("SELECT 1").fetch_one(&fixture.pool),
    )
    .await??;
    ensure!(one == 1, "canceled connection returned active SQL to pool");
    for body in [false, true] {
        blocked_provider(fixture, body).await?;
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut request = [0u8; 4096];
        let received = socket.read(&mut request).await?;
        if received == 0 {
            return Err(std::io::Error::other(
                "provider client closed before request",
            ));
        }
        socket.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        Ok::<_, std::io::Error>(())
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let response = timeout_at(
        deadline,
        reqwest::Client::new()
            .get(format!("http://{address}/provider"))
            .send(),
    )
    .await??;
    ensure!(
        response.error_for_status().is_err(),
        "real provider error fixture unexpectedly succeeded"
    );
    budgeted_fallback(fixture, deadline).await?;
    server.await??;
    Ok(())
}

async fn blocked_provider(fixture: &Fixture, body: bool) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let active = Arc::new(AtomicUsize::new(0));
    let active_server = Arc::clone(&active);
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        active_server.fetch_add(1, Ordering::SeqCst);
        let mut request = [0u8; 4096];
        let received = socket.read(&mut request).await?;
        if received == 0 {
            return Err(std::io::Error::other(
                "provider client closed before request",
            ));
        }
        if body {
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n",
                )
                .await?;
        }
        ready_tx
            .send(())
            .map_err(|_| std::io::Error::other("provider coordinator gone"))?;
        loop {
            let read = socket.read(&mut request).await?;
            if read == 0 {
                break;
            }
        }
        active_server.fetch_sub(1, Ordering::SeqCst);
        Ok::<_, std::io::Error>(())
    });
    let permits = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&permits).acquire_owned().await?;
    let deadline = Instant::now() + Duration::from_millis(300);
    let client = reqwest::Client::new();
    let mut provider = Box::pin(async {
        let _permit = permit;
        let response = client
            .get(format!("http://{address}/provider"))
            .send()
            .await?;
        response.bytes().await?;
        Ok::<_, anyhow::Error>(())
    });
    tokio::select! {
        ready=ready_rx=>ready.context("real HTTP provider never accepted request")?,
        response=&mut provider=>{response?;anyhow::bail!("blocked provider returned before timeout")},
    }
    ensure!(
        timeout_at(deadline, &mut provider).await.is_err(),
        "blocked send/body ignored absolute deadline"
    );
    drop(provider);
    ensure!(
        deadline.saturating_duration_since(Instant::now()).is_zero(),
        "deadline exhaustion fixture has remaining budget"
    );
    timeout(Duration::from_secs(5), server).await???;
    ensure!(
        active.load(Ordering::SeqCst) == 0,
        "provider network request remained in flight after cancellation"
    );
    ensure!(
        permits.available_permits() == 1,
        "provider permit leaked on cancellation"
    );
    ensure!(
        budgeted_fallback(fixture, deadline).await.is_err(),
        "exhausted provider deadline issued fallback retrieval"
    );
    Ok(())
}

async fn budgeted_fallback(fixture: &Fixture, deadline: Instant) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    ensure!(
        !remaining.is_zero(),
        "absolute request deadline exhausted; no fallback SQL allowed"
    );
    let mut connection = timeout_at(deadline, fixture.pool.acquire()).await??;
    connection.close_on_drop();
    sqlx::query("SET SESSION ob_query_timeout=?")
        .bind(i64::try_from(remaining.as_micros())?)
        .execute(&mut *connection)
        .await?;
    let query = hybrid::sql(
        "deadline_search",
        &hybrid::dsl(Some("fallbackword"), None, 0, 1)?,
    )?;
    let rows = timeout_at(deadline, sqlx::query(&query).fetch_all(&mut *connection)).await??;
    connection.close().await?;
    ensure!(rows.len() == 1, "keyword fallback missed scoped fixture");
    Ok(())
}
