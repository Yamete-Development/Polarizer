mod service;

use std::{net::SocketAddr, sync::Arc};

use tokio_util::sync::CancellationToken;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::info;

use crate::{
    auth::Authorizer,
    command::CommandRepository,
    config::AppConfig,
    content_policy::repository::PostgresContentPolicyRepository,
    contract::v2::trust_and_safety_service_server::TrustAndSafetyServiceServer,
    moderation::ModerationRepository,
    policy::{engine::PolicyEngine, repository::PostgresPolicyRepository},
};

pub use service::TrustAndSafetyService;
pub(crate) use service::action_from_proto;

/// Everything the gRPC surface needs from the rest of the process.
pub struct GrpcDependencies {
    pub engine: Arc<PolicyEngine>,
    pub repository: Arc<PostgresPolicyRepository>,
    pub content_policy_repository: Arc<PostgresContentPolicyRepository>,
    pub authorizer: Arc<Authorizer>,
    pub moderation: Arc<ModerationRepository>,
    pub commands: Arc<CommandRepository>,
}

pub async fn serve(
    config: &AppConfig,
    deps: GrpcDependencies,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.tls_is_complete(),
        "gRPC mTLS requires GRPC_TLS_CERT, GRPC_TLS_KEY, and GRPC_TLS_CLIENT_CA"
    );
    let cert = tokio::fs::read(config.tls_cert_path.as_ref().expect("checked")).await?;
    let key = tokio::fs::read(config.tls_key_path.as_ref().expect("checked")).await?;
    let client_ca = tokio::fs::read(config.tls_client_ca_path.as_ref().expect("checked")).await?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key))
        .client_ca_root(Certificate::from_pem(client_ca));
    let address = SocketAddr::new(config.grpc_host, config.grpc_port);
    let service = TrustAndSafetyService::new(
        deps.engine,
        deps.repository,
        deps.content_policy_repository,
        deps.authorizer,
        deps.moderation,
        deps.commands,
        config,
    );
    info!(%address, "mTLS gRPC server starting");
    Server::builder()
        .tls_config(tls)?
        .add_service(
            TrustAndSafetyServiceServer::new(service).max_decoding_message_size(2 * 1024 * 1024),
        )
        .serve_with_shutdown(address, cancel.cancelled_owned())
        .await?;
    Ok(())
}
