mod connector;
mod dialect;
mod grants;
mod helper;
mod hybrid;
mod locking;
mod readback;
mod sqlx_tooling;
mod throughput;
mod tls;

use anyhow::Result;

#[tokio::test]
async fn validation() -> Result<()> {
    let config = helper::Config::load()?;
    let mut evidence = config.preflight().await?;
    dialect::run(&config, &mut evidence).await?;
    locking::run(&config, &mut evidence).await?;
    grants::run(&config, &mut evidence).await?;
    hybrid::run(&config, &mut evidence).await?;
    readback::run(&config, &mut evidence).await?;
    connector::run(&config, &mut evidence).await?;
    tls::run(&config, &mut evidence).await?;
    sqlx_tooling::run(&config, &mut evidence).await?;
    throughput::run(&config, &mut evidence).await?;
    // This is one architecture's measured observations, not U1 approval or a selected runtime manifest.
    // Parent release acceptance authenticates the image/platform/TLS lifecycle and common two-arch envelope.
    let bytes = serde_json::to_vec_pretty(&evidence)?;
    std::fs::write(&config.output, &bytes)?;
    println!(
        "U1 per-architecture observations: {}",
        config.output.display()
    );
    Ok(())
}
