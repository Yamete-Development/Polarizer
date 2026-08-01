mod service;

use std::{net::SocketAddr, sync::Arc};

use tokio_util::sync::CancellationToken;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::info;

use crate::{
    auth::Authorizer,
    command::CommandRepository,
    config::AppConfig,
    contract::v2::trust_and_safety_service_server::TrustAndSafetyServiceServer,
    moderation::ModerationRepository,
    policy::{engine::PolicyEngine, repository::PostgresPolicyRepository},
};

pub use service::TrustAndSafetyService;
pub(crate) use service::action_from_proto;

pub async fn serve(
    config: &AppConfig,
    engine: Arc<PolicyEngine>,
    repository: Arc<PostgresPolicyRepository>,
    authorizer: Arc<Authorizer>,
    moderation: Arc<ModerationRepository>,
    commands: Arc<CommandRepository>,
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
    let service =
        TrustAndSafetyService::new(engine, repository, authorizer, moderation, commands, config);
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
