use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use polarizer::{
    auth::Authorizer,
    command::CommandRepository,
    config::{AppConfig, MigrationConfig},
    content_policy::{
        ContentPolicyEvaluator, ContentPolicyRuntime, PolicyLimits, PolicySnapshotStore,
        SideEffectCooldown,
        invalidation::{ContentPolicyInvalidationConsumer, ContentPolicyReconciliationTask},
        repository::{ContentPolicySource, PostgresContentPolicyRepository},
    },
    db,
    eventbus::{
        self, ActionConsumer, DeliveryCallbackConsumer, OutboxRelay,
        StaffAuthorizationChangeConsumer,
    },
    grpc,
    health::{self, HealthState},
    moderation::ModerationRepository,
    policy::{
        engine::PolicyEngine,
        features::production_registry,
        ir::PolicyIrRuntime,
        luau::LuauRuntime,
        repository::{PolicyRepository, PostgresPolicyRepository},
    },
    telemetry::init_tracing,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    if std::env::args().nth(1).as_deref() == Some("migrate") {
        let migration = MigrationConfig::from_env().context("invalid migration configuration")?;
        init_tracing(&std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info,sqlx=warn".to_owned()));
        let db = db::init_pool(&migration.database_url, migration.database_max_connections).await?;
        db::run_migrations(&db, migration.timeout).await?;
        return Ok(());
    }

    let config = AppConfig::from_env().context("invalid Polarizer configuration")?;
    init_tracing(&config.log_level);
    let db = db::init_pool(&config.database_url, config.database_max_connections).await?;

    if config.auto_migrate {
        db::run_migrations(&db, config.migration_timeout)
            .await
            .context("automatic Polarizer migration failed; refusing to start")?;
    } else {
        info!("automatic migrations disabled; expecting a completed pre-deployment migration job");
    }

    let repository = Arc::new(PostgresPolicyRepository::new(db.clone(), &config)?);
    let content_policy_repository = Arc::new(PostgresContentPolicyRepository::new(
        db.clone(),
        config.content_policy_invalidation_topic.clone(),
    ));
    let content_policy_source: Arc<dyn ContentPolicySource> = content_policy_repository.clone();
    let content_policy_snapshots = Arc::new(PolicySnapshotStore::new());
    let content_policy_runtime = Arc::new(ContentPolicyRuntime::new(
        content_policy_source,
        content_policy_snapshots.clone(),
        PolicyLimits::default(),
    ));
    let loaded_content_policy_scopes = content_policy_runtime
        .bootstrap()
        .await
        .context("native content policy bootstrap failed")?;
    info!(
        loaded_content_policy_scopes,
        "native content policies compiled"
    );
    let moderation = Arc::new(ModerationRepository::new(db.clone()));
    let commands = Arc::new(CommandRepository::new(
        db.clone(),
        config.command_result_topic.clone(),
    ));
    let authorizer = Arc::new(Authorizer::connect(&config).await?);
    let features = Arc::new(production_registry(db.clone(), &config)?);

    let repository_trait: Arc<dyn PolicyRepository> = repository.clone();
    let mut engine = PolicyEngine::new(
        repository_trait,
        features,
        config.clean_allow_trace_sample_rate,
    );
    engine.register_runtime(Arc::new(PolicyIrRuntime));
    engine.register_content_policy(Arc::new(ContentPolicyEvaluator::new(
        content_policy_snapshots,
        Arc::new(SideEffectCooldown::new()),
    )));
    engine.register_runtime(Arc::new(LuauRuntime::new(
        config.policy_worker_bin.clone(),
        config.policy_worker_count,
        config.luau_source_limit,
        config.luau_heap_limit,
        config.luau_instruction_limit,
        config.luau_wall_timeout,
        config.luau_output_limit,
    )));
    let engine = Arc::new(engine);

    let cancel = CancellationToken::new();
    let health_state = Arc::new(HealthState::new());
    let mut tasks = JoinSet::new();

    let health_address = SocketAddr::new(config.http_host, config.http_port);
    tasks.spawn(health::serve(
        health_address,
        health_state.clone(),
        cancel.clone(),
    ));
    tasks.spawn({
        let config = config.clone();
        let engine = engine.clone();
        let repository = repository.clone();
        let authorizer = authorizer.clone();
        let moderation = moderation.clone();
        let commands = commands.clone();
        let cancel = cancel.clone();
        async move {
            grpc::serve(
                &config,
                grpc::GrpcDependencies {
                    engine,
                    repository,
                    content_policy_repository,
                    authorizer,
                    moderation,
                    commands,
                },
                cancel,
            )
            .await
        }
    });
    tasks.spawn(
        ActionConsumer::new(
            &config,
            engine.clone(),
            health_state.clone(),
            cancel.clone(),
        )?
        .run(),
    );
    tasks.spawn(DeliveryCallbackConsumer::new(&config, repository.clone(), cancel.clone())?.run());
    tasks.spawn(StaffAuthorizationChangeConsumer::new(&config, db.clone(), cancel.clone())?.run());
    tasks.spawn(OutboxRelay::new(db.clone(), &config, cancel.clone())?.run());
    tasks.spawn(
        ContentPolicyInvalidationConsumer::new(
            &config,
            content_policy_runtime.clone(),
            cancel.clone(),
        )?
        .run(),
    );
    tasks.spawn(ContentPolicyReconciliationTask::new(content_policy_runtime, cancel.clone()).run());
    tasks.spawn(eventbus::policy_activation_worker(
        repository.clone(),
        engine,
        cancel.clone(),
    ));
    tasks.spawn(eventbus::expiry_worker(repository, cancel.clone()));

    health_state.set_ready(true);
    info!(http = %health_address, grpc_port = config.grpc_port, "Polarizer v2 ready");
    tokio::select! {
        _ = shutdown_signal() => info!("shutdown signal received"),
        task = tasks.join_next() => {
            match task {
                Some(Ok(Ok(()))) => error!("a supervised service exited unexpectedly"),
                Some(Ok(Err(error))) => error!(error = %error, "a supervised service failed"),
                Some(Err(error)) => error!(error = %error, "a supervised service panicked"),
                None => error!("all supervised services exited"),
            }
        }
    }
    health_state.set_ready(false);
    cancel.cancel();
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            error!(error = %error, "service join failed during shutdown");
        }
    }
    info!("Polarizer shut down cleanly");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! { _ = ctrl_c => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
