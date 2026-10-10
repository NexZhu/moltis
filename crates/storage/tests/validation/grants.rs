use {
    anyhow::{Result, ensure},
    serde_json::json,
    sqlx::{Connection, MySqlConnection},
};

use super::helper::{Config, Evidence, Fixture, expect_number, recyclebin_off};

pub async fn run(config: &Config, evidence: &mut Evidence) -> Result<()> {
    let mut fixture = Fixture::create(config, "grants", 2).await?;
    let result = check(&mut fixture, config).await;
    let observations = fixture.finish(result).await?;
    evidence
        .observations
        .insert("tenant_grants".into(), observations);
    Ok(())
}

async fn check(fixture: &mut Fixture, config: &Config) -> Result<serde_json::Value> {
    sqlx::query("CREATE TABLE own(id INT PRIMARY KEY)")
        .execute(&fixture.pool)
        .await?;
    fixture.pool.close().await;
    let options = fixture.options.clone();
    let mut first = MySqlConnection::connect_with(&options).await?;
    let second = MySqlConnection::connect_with(&options).await?;
    let result=async {
        let actual:String=sqlx::query_scalar("SELECT CURRENT_USER()").fetch_one(&mut first).await?;
        ensure!(actual.starts_with(&format!("{}@",fixture.username)),"account credential selected wrong SQL identity: {actual}");
        expect_number(MySqlConnection::connect_with(&options).await,1226)?;
        let lookalike=fixture.database.replace('_',"1");
        let foreign=format!("{}foreign",fixture.database);
        let database=fixture.database.clone();
        let username=fixture.username.clone();
        let host=config.account_host.clone();
        sqlx::query(&format!("CREATE DATABASE `{lookalike}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")).execute(fixture.admin().await).await?;
        sqlx::query(&format!("CREATE DATABASE `{foreign}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")).execute(fixture.admin().await).await?;
        let negative=async {
            sqlx::query(&format!("CREATE TABLE `{lookalike}`.secret(id INT)")).execute(fixture.admin().await).await?;
            sqlx::query(&format!("CREATE TABLE `{foreign}`.secret(id INT)")).execute(fixture.admin().await).await?;
            expect_number(sqlx::query(&format!("SELECT * FROM `{foreign}`.secret")).fetch_all(&mut first).await,1142)?;
            expect_number(sqlx::query(&format!("SELECT * FROM `{lookalike}`.secret")).fetch_all(&mut first).await,1142)?;
            let rows=sqlx::query(&format!("SHOW GRANTS FOR '{username}'@'{host}'")).fetch_all(fixture.admin().await).await?;
            let grants=rows.iter().map(|row| { use sqlx::Row; row.try_get::<String,_>(0) }).collect::<std::result::Result<Vec<_>,_>>()?;
            ensure!(grants.iter().all(|grant|!grant.contains("SUPER") && !grant.contains("ALL PRIVILEGES")),"tenant overgranted");
            let matched:i64=sqlx::query_scalar("SELECT ? LIKE ?").bind(&lookalike).bind(database.replace('_',"\\_")).fetch_one(&mut first).await?;
            ensure!(matched==0,"escaped database LIKE pattern matched underscore lookalike");
            Ok::<_,anyhow::Error>(grants)
        }.await;
        recyclebin_off(fixture.admin().await).await?;
        sqlx::query(&format!("DROP DATABASE `{lookalike}`")).execute(fixture.admin().await).await?;
        recyclebin_off(fixture.admin().await).await?;
        sqlx::query(&format!("DROP DATABASE `{foreign}`")).execute(fixture.admin().await).await?;
        let grants=negative?;
        Ok::<_,anyhow::Error>(json!({"current_user":actual,"grants":grants,"cap":2,"cap_error":1226,"scope_error":1142,"underscore_escape":true}))
    }.await;
    second.close().await?;
    let mut replacement = MySqlConnection::connect_with(&options).await?;
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut replacement)
        .await?;
    ensure!(one == 1, "released cap slot not reusable");
    replacement.close().await?;
    first.close().await?;
    result
}
