use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use {
    anyhow::{Context, Result, bail, ensure},
    secrecy::{ExposeSecret, Secret},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    sha2::{Digest, Sha256},
    sqlx::{
        ConnectOptions, Connection, MySqlConnection, MySqlPool, Row,
        mysql::{MySqlConnectOptions, MySqlDatabaseError, MySqlPoolOptions, MySqlSslMode},
    },
    tokio::process::Command,
    uuid::Uuid,
};

pub const SOURCE: &str = "071f4d9c82841d3ecb2d0004ef9213766308b714";
pub const VERSION: &str = "5.7.25-OceanBase_CE-v5.0.1.0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserInputs {
    schema_version: u32,
    source_commit: String,
    package_version: String,
    registration_source: String,
    external_plugins: Vec<String>,
    external_dictionaries: Vec<String>,
    pub candidates: Vec<Candidate>,
    pub query_mode_configuration: QueryModeConfiguration,
    tables: BTreeMap<String, TableSpec>,
    selection: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    pub sql_parser: String,
    pub delivery: String,
    pub configuration: BTreeMap<String, Value>,
    pub dictionary: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableSpec {
    candidate_order: Vec<String>,
    query_modes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryModeConfiguration {
    pub sql_hybrid_bool_rrf60: HybridQueryConfiguration,
    pub native_boolean: NativeQueryConfiguration,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HybridQueryConfiguration {
    match_operator: String,
    omit_empty_bool_clauses: bool,
    required_prefix: String,
    excluded_prefix: String,
    rank_constant: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeQueryConfiguration {
    literal_terms: String,
    required_prefix: String,
    excluded_prefix: String,
    quote_terms: bool,
}

impl ParserInputs {
    pub fn load(path: &Path) -> Result<Self> {
        let inputs: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        inputs.validate()?;
        Ok(inputs)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.source_commit == SOURCE
                && self.package_version == "5.0.1.0-100000042026072912.el8"
                && self.registration_source == "src/storage/fts/ob_fts_builtin_parser_register.cpp"
                && self.external_plugins.is_empty()
                && self.external_dictionaries.is_empty()
                && !self.selection.is_empty(),
            "parser package/source inventory changed"
        );
        ensure!(
            self.candidates.len() == 3,
            "parser candidate inventory changed"
        );
        for (candidate, (id, sql_parser, dictionary)) in self.candidates.iter().zip([
            ("default", "space", "none"),
            ("ngram", "ngram", "none"),
            (
                "ik",
                "ik",
                "fixed RPM built-in IK dictionary; no host override",
            ),
        ]) {
            ensure!(
                candidate.id == id
                    && candidate.sql_parser == sql_parser
                    && candidate.delivery == "built-in"
                    && candidate.configuration.is_empty()
                    && candidate.dictionary == dictionary,
                "parser candidate configuration changed"
            );
        }
        ensure!(self.tables.len() == 4, "parser table inventory changed");
        for table in [
            "memory_chunks_search",
            "code_chunks_search",
            "connector_items",
            "connector_items_search",
        ] {
            let spec = self
                .tables
                .get(table)
                .context("parser table inventory missing")?;
            let mode = if table.starts_with("connector") {
                "native_boolean"
            } else {
                "sql_hybrid_bool_rrf60"
            };
            ensure!(
                spec.candidate_order == ["default", "ngram", "ik"] && spec.query_modes == [mode],
                "parser table order/mode changed"
            );
        }
        let hybrid = &self.query_mode_configuration.sql_hybrid_bool_rrf60;
        let native = &self.query_mode_configuration.native_boolean;
        ensure!(
            hybrid.match_operator == "AND"
                && hybrid.omit_empty_bool_clauses
                && hybrid.required_prefix == "+"
                && hybrid.excluded_prefix == "-"
                && hybrid.rank_constant == 60
                && native.literal_terms
                    == "Unicode alphanumeric segments preserving underscore and dot"
                && native.required_prefix == "+"
                && native.excluded_prefix == "-"
                && native.quote_terms,
            "parser query configuration changed"
        );
        Ok(())
    }

    pub fn candidate(&self, id: &str) -> Result<&Candidate> {
        self.candidates
            .iter()
            .find(|candidate| candidate.id == id)
            .context("parser absent from packaged inventory")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorInventory {
    schema_version: u32,
    pub baseline_sources: BTreeMap<String, String>,
    pub schema_sha256: String,
    query_contract: QueryContract,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryContract {
    fulltext: String,
    bindings: Vec<String>,
    direct_first: bool,
    fallback: String,
}

impl ConnectorInventory {
    pub fn load() -> Result<Self> {
        let inventory: Self =
            serde_json::from_slice(&std::fs::read(fixture_path("connector_inventory.json"))?)?;
        let query = &inventory.query_contract;
        ensure!(
            inventory.schema_version == 1
                && inventory.baseline_sources.len() == 4
                && inventory.schema_sha256.len() == 64
                && query.fulltext == "score DESC, binary item_id ASC"
                && query.bindings
                    == [
                        "text",
                        "account_id",
                        "dataset_id",
                        "include_deleted",
                        "text",
                        "limit",
                        "offset"
                    ]
                && query.direct_first
                && query.fallback
                    == "ORGANIZATION HEAP; unique item_id + fulltext; same transaction source/projection",
            "connector query inventory changed"
        );
        for path in [
            "crates/connectors/migrations/20260806000000_connectors_init.sql",
            "crates/connectors/migrations/20260808000000_prompt_plan_source_search.sql",
            "crates/connectors/migrations/20260811000000_account_source_key.sql",
            "crates/connectors/src/store.rs",
        ] {
            let digest = inventory
                .baseline_sources
                .get(path)
                .context("connector baseline source missing")?;
            ensure!(
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid connector baseline digest"
            );
        }
        ensure!(
            inventory
                .schema_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
            "invalid connector schema digest"
        );
        Ok(inventory)
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsExpectation {
    Success,
    WrongSan,
    Expired,
    WrongCa,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsHandshake {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub ca: PathBuf,
    pub expectation: TlsExpectation,
    pub native_command: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub admin_url: Secret<String>,
    pub account_host: String,
    pub ob_tenant: String,
    pub ca: PathBuf,
    pub wrong_ca: PathBuf,
    pub expected_build: String,
    pub offline_tenant_readback: PathBuf,
    pub native_tls_command: Vec<String>,
    pub tls_handshakes: Vec<TlsHandshake>,
    pub memory_container: String,
    pub proof_dir: PathBuf,
    pub parser_inputs: PathBuf,
    pub output: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfflineTenant {
    image_digest: String,
    build: String,
    sql_host: String,
    ca_sha256: String,
    root_current_user: String,
    tenant_name: String,
}

#[derive(Default, Serialize)]
pub struct Evidence {
    pub image_digest: String,
    pub architecture: String,
    pub source_commit: String,
    pub version: String,
    pub build: String,
    pub ob_tenant: String,
    pub inputs: BTreeMap<String, String>,
    pub observations: BTreeMap<String, Value>,
    #[serde(skip)]
    pub tls_handshakes_verified: bool,
}

impl Config {
    pub fn load() -> Result<Self> {
        ensure!(
            std::env::var("MOLTIS_U1_ISOLATED").as_deref() == Ok("1"),
            "U1 requires MOLTIS_U1_ISOLATED=1 consent for an isolated acceptance instance"
        );
        let path = std::env::var("MOLTIS_U1_CONFIG")
            .context("MOLTIS_U1_CONFIG must name the explicit isolated acceptance configuration")?;
        let config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            !config.admin_url.expose_secret().is_empty()
                && !config.account_host.is_empty()
                && !config.ob_tenant.is_empty(),
            "missing connection/account identity"
        );
        ensure!(
            config.account_host == "%"
                || config
                    .account_host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b)),
            "unsafe SQL account host"
        );
        ensure!(
            config.expected_build.contains("5.0.1.0")
                && config.expected_build.contains("100000042026072912")
                && config.expected_build.contains(SOURCE),
            "build evidence must contain actual pinned server version/build/source"
        );
        ensure!(
            !config.memory_container.is_empty()
                && config
                    .memory_container
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
            "actual DB memory container required"
        );
        for path in [
            &config.ca,
            &config.wrong_ca,
            &config.parser_inputs,
            &config.offline_tenant_readback,
        ] {
            ensure!(
                path.is_file(),
                "required acceptance input missing: {}",
                path.display()
            );
        }
        ensure!(
            std::fs::read(&config.ca)? != std::fs::read(&config.wrong_ca)?,
            "wrong-CA negative fixture must be an independent CA"
        );
        validate_native_tls_command(&config.native_tls_command, true)?;
        config.validate_tls_handshakes()?;
        let options = config.admin_options()?;
        ensure!(
            !options
                .get_username()
                .split('@')
                .next()
                .is_some_and(|user| user.eq_ignore_ascii_case("root")),
            "runtime lifecycle administrator must be non-root"
        );
        Ok(config)
    }

    pub fn admin_options(&self) -> Result<MySqlConnectOptions> {
        Ok(
            MySqlConnectOptions::from_str(self.admin_url.expose_secret())?
                .charset("utf8mb4")
                .collation("utf8mb4_bin")
                .ssl_mode(MySqlSslMode::VerifyIdentity)
                .ssl_ca(&self.ca)
                .disable_statement_logging(),
        )
    }

    pub fn validate_tls_handshakes(&self) -> Result<()> {
        let normal = self.admin_options()?;
        let mut names = std::collections::BTreeSet::new();
        for case in &self.tls_handshakes {
            ensure!(
                !case.name.is_empty()
                    && case
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                    && names.insert(case.name.as_str()),
                "TLS handshake names must be safe and unique"
            );
            ensure!(
                !case.host.is_empty()
                    && case
                        .host
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
                    && case.port != 0,
                "TLS handshake {} requires a host and nonzero port",
                case.name
            );
            ensure!(
                case.ca.is_file(),
                "TLS handshake {} CA missing: {}",
                case.name,
                case.ca.display()
            );
            let ca = std::fs::read(&case.ca)?;
            ensure!(
                ca.windows(b"-----BEGIN CERTIFICATE-----".len())
                    .any(|w| w == b"-----BEGIN CERTIFICATE-----"),
                "TLS handshake {} CA is not PEM",
                case.name
            );
            let success = case.expectation == TlsExpectation::Success;
            let args = validate_native_tls_command(&case.native_command, success)?;
            if Path::new(&case.native_command[0])
                .file_name()
                .is_some_and(|name| name == "obclient")
            {
                ensure!(
                    native_option(args, "--host=") == Some(case.host.as_str())
                        && native_option(args, "--port=").and_then(|port| port.parse::<u16>().ok())
                            == Some(case.port)
                        && native_option(args, "--ssl-ca=") == case.ca.to_str(),
                    "direct native TLS endpoint/CA differs from sqlx fixture {}",
                    case.name
                );
            }
            if success {
                ensure!(
                    case.host == normal.get_host()
                        && case.port == normal.get_port()
                        && ca == std::fs::read(&self.ca)?
                        && case.native_command == self.native_tls_command,
                    "TLS success fixture must bind canonical SQL endpoint, CA and native command"
                );
            }
        }
        for (name, expectation) in [
            ("wrong_san", TlsExpectation::WrongSan),
            ("expired", TlsExpectation::Expired),
        ] {
            ensure!(
                self.tls_handshakes
                    .iter()
                    .any(|case| case.name == name && case.expectation == expectation),
                "mandatory real TLS handshake {name} missing"
            );
        }
        ensure!(
            self.tls_handshakes
                .iter()
                .filter(|case| case.expectation == TlsExpectation::Success)
                .count()
                == 1,
            "exactly one canonical TLS success fixture required"
        );
        Ok(())
    }

    pub async fn preflight(&self) -> Result<Evidence> {
        let verifier =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/oceanbase/verify-image.sh");
        ensure!(
            verifier.is_file(),
            "KTD1 shared cryptographic verifier missing"
        );
        let mut command = Command::new(&verifier);
        for (flag, env) in [
            ("--source-commit", "OCEANBASE_SOURCE_COMMIT"),
            ("--build-workflow-run-id", "OCEANBASE_BUILD_WORKFLOW_RUN_ID"),
            ("--build-artifact-id", "OCEANBASE_BUILD_ARTIFACT_ID"),
            ("--manifest-sha256", "OCEANBASE_MANIFEST_SHA256"),
        ] {
            command.arg(flag).arg(
                std::env::var(env)
                    .with_context(|| format!("missing approved artifact identity {env}"))?,
            );
        }
        let output = command
            .arg("--artifact-dir")
            .arg(&self.proof_dir)
            .kill_on_drop(true)
            .output()
            .await
            .context("running shared image verifier")?;
        ensure!(
            output.status.success(),
            "KTD1 signature/identity verification rejected: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let image_digest = String::from_utf8(output.stdout)?.trim().to_owned();
        ensure!(
            image_digest.contains("@sha256:")
                && image_digest
                    .rsplit(':')
                    .next()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
            "verifier must emit only validated immutable image reference"
        );
        ParserInputs::load(&self.parser_inputs)?;
        ConnectorInventory::load()?;
        let tls_handshakes = super::tls::negative_handshakes(self).await?;
        let mut connection = MySqlConnection::connect_with(&self.admin_options()?).await?;
        let result = async {
            let version: String = sqlx::query_scalar("SELECT VERSION()").fetch_one(&mut connection).await?;
            ensure!(version == VERSION, "R4 wrong server release: {version}");
            let build: String = sqlx::query_scalar("SELECT @@version_comment").fetch_one(&mut connection).await?;
            ensure!(build == self.expected_build, "R4 complete build/source mismatch: {build}");
            let readback: OfflineTenant = serde_json::from_slice(&std::fs::read(&self.offline_tenant_readback)?)?;
            let options=self.admin_options()?;
            ensure!(readback.image_digest==image_digest && readback.build==build && readback.sql_host==options.get_host() && readback.ca_sha256==hash(&std::fs::read(&self.ca)?) && readback.root_current_user.starts_with("root@"),"offline tenant readback does not bind actual approved image/build/host/CA/root account");
            let tenant=readback.tenant_name;
            ensure!(tenant == self.ob_tenant, "KTD2 actual OB tenant mismatch: {tenant}");
            let mode: String = sqlx::query_scalar("SELECT @@SESSION.sql_mode").fetch_one(&mut connection).await?;
            ensure!(mode.split(',').any(|s| s == "STRICT_ALL_TABLES" || s == "STRICT_TRANS_TABLES"), "truncation must fail under existing strict SQL mode, not opportunistically switch modes");
            let mut evidence = Evidence { image_digest, architecture: std::env::consts::ARCH.into(), source_commit: SOURCE.into(), version, build, ob_tenant: tenant, ..Evidence::default() };
            evidence.observations.insert("sql_mode".into(), Value::String(mode));
            evidence.observations.insert("tls_handshakes".into(), Value::Array(tls_handshakes));
            evidence.tls_handshakes_verified = true;
            for name in ["ann.json", "parser.json", "connector_schema.sql", "connector_inventory.json", "capacity_matrix.json"] {
                let path = fixture_path(name);
                evidence.inputs.insert(name.into(), hash(&std::fs::read(path)?));
            }
            evidence.inputs.insert("parser_inputs".into(), hash(&std::fs::read(&self.parser_inputs)?));
            Ok(evidence)
        }.await;
        let closed = connection.close().await;
        closed.context("closing preflight connection")?;
        result
    }
}

fn native_option<'a>(args: &'a [String], prefix: &str) -> Option<&'a str> {
    args.iter().find_map(|arg| arg.strip_prefix(prefix))
}

fn validate_native_tls_command(command: &[String], success: bool) -> Result<&[String]> {
    let program = command
        .first()
        .context("native TLS fixture command required")?;
    let name = Path::new(program).file_name();
    let args = if name.is_some_and(|name| name == "obclient") {
        &command[1..]
    } else {
        ensure!(
            name.is_some_and(|name| name == "docker")
                && command.get(1).map(String::as_str) == Some("exec")
                && command.get(2).is_some_and(|id| !id.is_empty()
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)))
                && command.get(3).map(String::as_str) == Some("obclient"),
            "native TLS proof must invoke obclient or fixed docker exec container obclient"
        );
        &command[4..]
    };
    ensure!(
        args.first().is_some_and(|arg| if success {
            arg.starts_with("--defaults-extra-file=") && arg.len() > "--defaults-extra-file=".len()
        } else {
            arg == "--no-defaults"
        }),
        "native TLS success requires first credential-file option; negatives require first --no-defaults"
    );
    let mut flags = std::collections::BTreeSet::new();
    for arg in args {
        let flag = arg.split('=').next().context("empty native TLS argument")?;
        ensure!(flags.insert(flag), "duplicate native TLS option {flag}");
        let allowed = match flag {
            "--ssl-verify-server-cert"
            | "--batch"
            | "--skip-column-names"
            | "--unbuffered"
            | "--skip-reconnect" => arg == flag,
            "--no-defaults" => !success && arg == flag,
            "--defaults-extra-file" => {
                success
                    && native_option(args, "--defaults-extra-file=").is_some_and(|v| !v.is_empty())
            },
            "--protocol" => arg == "--protocol=tcp",
            "--host" => native_option(args, "--host=").is_some_and(|v| {
                !v.is_empty()
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
            }),
            "--port" => native_option(args, "--port=")
                .and_then(|v| v.parse::<u16>().ok())
                .is_some_and(|v| v != 0),
            "--ssl-ca" => native_option(args, "--ssl-ca=").is_some_and(|v| !v.is_empty()),
            "--user" => native_option(args, "--user=").is_some_and(|v| {
                if success {
                    !v.is_empty()
                        && v.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_@.-".contains(&b))
                } else {
                    v == "root@sys"
                }
            }),
            "--connect-timeout" => native_option(args, "--connect-timeout=")
                .and_then(|v| v.parse::<u32>().ok())
                .is_some_and(|v| (1..=30).contains(&v)),
            "--execute" => {
                if success {
                    arg == "--execute=status"
                } else {
                    matches!(
                        arg.as_str(),
                        "--execute=status"
                            | "--execute=SELECT 1;"
                            | "--execute=SELECT CURRENT_USER();"
                    )
                }
            },
            _ => false,
        };
        ensure!(
            allowed,
            "unsafe native TLS option {flag}: no password argv, scripts or verification overrides permitted"
        );
    }
    ensure!(
        [
            "--host",
            "--port",
            "--user",
            "--ssl-ca",
            "--ssl-verify-server-cert",
            "--execute"
        ]
        .iter()
        .all(|flag| flags.contains(flag)),
        "native TLS command requires explicit endpoint, user, CA, identity verification and fixed query"
    );
    Ok(args)
}

pub fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/validation/fixtures")
        .join(name)
}

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub async fn run_command(args: &[String]) -> Result<std::process::Output> {
    let (program, args) = args.split_first().context("empty acceptance command")?;
    Ok(Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await?)
}

pub fn number(error: &sqlx::Error) -> Result<u16> {
    match error {
        sqlx::Error::Database(error) => Ok(error
            .try_downcast_ref::<MySqlDatabaseError>()
            .context("expected MySQL database error")?
            .number()),
        error => bail!("expected server MySQL error, got {error}"),
    }
}

pub fn expect_number<T>(result: std::result::Result<T, sqlx::Error>, expected: u16) -> Result<()> {
    match result {
        Err(error) => ensure!(
            number(&error)? == expected,
            "expected MySQL {expected}, got {error}"
        ),
        Ok(_) => bail!("expected MySQL {expected}, operation succeeded"),
    }
    Ok(())
}

pub struct Fixture {
    pub database: String,
    pub username: String,
    pub options: MySqlConnectOptions,
    pub pool: MySqlPool,
    admin: MySqlConnection,
    account_host: String,
}

impl Fixture {
    pub async fn create(config: &Config, label: &str, cap: u32) -> Result<Self> {
        ensure!(
            label.bytes().all(|b| b.is_ascii_alphanumeric()),
            "invalid fixture label"
        );
        let unique = Uuid::new_v4().simple().to_string();
        let database = format!("e2e{}_{}", &unique[..12], label);
        let username = format!("e2e{}_u", &unique[..12]);
        let password = Secret::new(format!("U1{}{}", unique, Uuid::new_v4().simple()));
        let mut admin = MySqlConnection::connect_with(&config.admin_options()?).await?;
        let initialized = async {
            sqlx::query(&format!("CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")).execute(&mut admin).await?;
            sqlx::query(&format!("CREATE USER '{username}'@'{}' IDENTIFIED BY '{}' REQUIRE SSL WITH MAX_USER_CONNECTIONS {cap}", config.account_host, password.expose_secret())).execute(&mut admin).await?;
            let pattern = database.replace('_', "\\_");
            sqlx::query(&format!("GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,DROP,INDEX,ALTER,REFERENCES ON `{pattern}`.* TO '{username}'@'{}'", config.account_host)).execute(&mut admin).await?;
            let options = config.admin_options()?.username(&format!("{username}@{}", config.ob_tenant)).password(password.expose_secret()).database(&database);
            let pool = MySqlPoolOptions::new().max_connections(cap).acquire_timeout(Duration::from_secs(10)).connect_with(options.clone()).await?;
            Ok((options, pool))
        }.await;
        match initialized {
            Ok((options, pool)) => Ok(Self {
                database,
                username,
                options,
                pool,
                admin,
                account_host: config.account_host.clone(),
            }),
            Err(error) => {
                let cleanup =
                    cleanup_objects(&mut admin, &database, &username, &config.account_host).await;
                admin.close().await?;
                cleanup.context("cleaning partial fixture")?;
                Err(error)
            },
        }
    }

    pub async fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        self.pool.close().await;
        let cleanup = cleanup_objects(
            &mut self.admin,
            &self.database,
            &self.username,
            &self.account_host,
        )
        .await;
        let close = self.admin.close().await;
        cleanup.context("awaited private fixture cleanup")?;
        close?;
        result
    }

    pub async fn admin(&mut self) -> &mut MySqlConnection {
        &mut self.admin
    }

    pub async fn drop_table(&self, table: &str) -> Result<()> {
        ensure!(
            table
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "unsafe table name"
        );
        let mut connection = MySqlConnection::connect_with(&self.options).await?;
        let result = async {
            recyclebin_off(&mut connection).await?;
            sqlx::query(&format!("DROP TABLE `{table}`"))
                .execute(&mut connection)
                .await?;
            assert_no_recyclebin(&mut connection).await
        }
        .await;
        connection.close().await?;
        result
    }
}

pub async fn recyclebin_off(connection: &mut MySqlConnection) -> Result<()> {
    sqlx::query("SET SESSION recyclebin = OFF")
        .execute(&mut *connection)
        .await?;
    let row = sqlx::query("SHOW VARIABLES LIKE 'recyclebin'")
        .fetch_one(&mut *connection)
        .await?;
    let value: String = row.try_get(1)?;
    ensure!(
        value.eq_ignore_ascii_case("off"),
        "KTD10 refusing DROP: recyclebin remains {value}"
    );
    Ok(())
}

pub async fn assert_no_recyclebin(connection: &mut MySqlConnection) -> Result<()> {
    let rows = sqlx::query("SHOW RECYCLEBIN").fetch_all(connection).await?;
    ensure!(
        rows.is_empty(),
        "KTD10 fixture deletion left recoverable objects"
    );
    Ok(())
}

async fn cleanup_objects(
    admin: &mut MySqlConnection,
    database: &str,
    username: &str,
    host: &str,
) -> Result<()> {
    recyclebin_off(admin).await?;
    sqlx::query(&format!("DROP DATABASE IF EXISTS `{database}`"))
        .execute(&mut *admin)
        .await?;
    assert_no_recyclebin(admin).await?;
    sqlx::query(&format!("DROP USER IF EXISTS '{username}'@'{host}'"))
        .execute(&mut *admin)
        .await?;
    let remains: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = ?",
    )
    .bind(database)
    .fetch_one(admin)
    .await?;
    ensure!(remains == 0, "private database was not deleted");
    Ok(())
}

pub async fn statements(pool: &MySqlPool, sql: &str) -> Result<()> {
    for statement in sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        sqlx::query(statement).execute(pool).await?;
    }
    Ok(())
}

#[test]
fn malformed_parser_inventory_rejected_before_sql() -> Result<()> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/oceanbase/parser-inputs.json");
    let original: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    serde_json::from_value::<ParserInputs>(original.clone())?.validate()?;
    for field in ["dictionary", "configuration"] {
        let mut missing = original.clone();
        missing["candidates"][0]
            .as_object_mut()
            .context("candidate object")?
            .remove(field);
        ensure!(
            serde_json::from_value::<ParserInputs>(missing).is_err(),
            "missing {field} accepted"
        );
        let mut wrong_type = original.clone();
        wrong_type["candidates"][0][field] = Value::Null;
        ensure!(
            serde_json::from_value::<ParserInputs>(wrong_type).is_err(),
            "null {field} accepted"
        );
    }
    let mut missing = original.clone();
    missing
        .as_object_mut()
        .context("inventory object")?
        .remove("query_mode_configuration");
    ensure!(
        serde_json::from_value::<ParserInputs>(missing).is_err(),
        "missing query configuration accepted"
    );
    let mut wrong_type = original.clone();
    wrong_type["query_mode_configuration"] = Value::Null;
    ensure!(
        serde_json::from_value::<ParserInputs>(wrong_type).is_err(),
        "null query configuration accepted"
    );
    let mut wrong_rank = original;
    wrong_rank["query_mode_configuration"]["sql_hybrid_bool_rrf60"]["rank_constant"] =
        serde_json::json!(61);
    ensure!(
        serde_json::from_value::<ParserInputs>(wrong_rank)?
            .validate()
            .is_err(),
        "wrong rank accepted"
    );
    Ok(())
}
