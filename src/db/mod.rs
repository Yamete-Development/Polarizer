use anyhow::{Context, bail};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use tracing::info;

pub async fn init_pool(database_url: &str, max_connections: u32) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(database_url)
        .await?;
    info!(max_connections, "database pool initialized");
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool, timeout: Duration) -> anyhow::Result<()> {
    if timeout.is_zero() {
        bail!("migration timeout must be greater than zero");
    }

    // SQLx's PostgreSQL migrator acquires a session-level advisory lock before
    // reading or updating `_sqlx_migrations`. Never return this connection to
    // the pool: cancellation or an error can occur before SQLx's explicit
    // unlock, while closing the PostgreSQL session always releases the lock.
    let mut connection = pool.acquire().await?;
    connection.close_on_drop();
    let result = tokio::time::timeout(
        timeout,
        sqlx::migrate!("./migrations").run_direct(&mut *connection),
    )
    .await
    .context(
        "timed out waiting for the Polarizer migration advisory lock or migration completion",
    )?;
    connection
        .close()
        .await
        .context("failed to close the dedicated migration connection")?;
    result?;
    info!("PostgreSQL 18 trust-and-safety baseline applied");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn zero_migration_timeout_is_rejected_before_database_access() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/polarizer")
            .expect("test URL should parse");

        let error = run_migrations(&pool, Duration::ZERO)
            .await
            .expect_err("zero timeout must fail closed");

        assert!(error.to_string().contains("greater than zero"));
    }
}
