// Tonic fixes the public handler error type to `Status`; boxing it locally would
// make these helpers incompatible with generated service traits.
#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use tonic::{
    Code, Request, Status,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

use crate::{
    config::AppConfig,
    contract::{
        authz::v1::{CheckPermissionRequest, auth_z_service_client::AuthZServiceClient},
        v2,
    },
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
#[repr(u64)]
pub enum Permission {
    ModerateHubMessages = 2,
    ManageRules = 16,
    ViewLogs = 64,
    ManageBans = 128,
    ManageGlobalBlacklists = 256,
    HandleLobbyReports = 512,
    Administrator = 2048,
}

#[derive(Clone)]
pub struct Authorizer {
    iris: AuthZServiceClient<Channel>,
    timeout: Duration,
    service_principals: Arc<BTreeMap<String, BTreeSet<String>>>,
    certificate_principals: Arc<BTreeMap<String, String>>,
}

impl Authorizer {
    pub async fn connect(config: &AppConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.iris_tls_is_complete(),
            "Iris mTLS requires IRIS_TLS_CA, IRIS_TLS_CERT, and IRIS_TLS_KEY"
        );
        let ca = tokio::fs::read(config.iris_tls_ca_path.as_ref().expect("checked")).await?;
        let cert = tokio::fs::read(config.iris_tls_cert_path.as_ref().expect("checked")).await?;
        let key = tokio::fs::read(config.iris_tls_key_path.as_ref().expect("checked")).await?;
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(cert, key))
            .domain_name(config.iris_tls_domain.clone());
        let channel = Endpoint::from_shared(config.iris_endpoint.clone())?
            .tls_config(tls)?
            .connect_timeout(config.iris_timeout)
            .timeout(config.iris_timeout)
            .connect_lazy();
        let mut certificate_principals = BTreeMap::new();
        for (principal, fingerprints) in &config.service_principal_cert_sha256 {
            for fingerprint in fingerprints {
                if let Some(previous) =
                    certificate_principals.insert(fingerprint.clone(), principal.clone())
                {
                    anyhow::bail!(
                        "client certificate fingerprint is assigned to both {previous} and {principal}"
                    );
                }
            }
        }
        Ok(Self {
            iris: AuthZServiceClient::new(channel),
            timeout: config.iris_timeout,
            service_principals: Arc::new(config.service_principal_allowlist.clone()),
            certificate_principals: Arc::new(certificate_principals),
        })
    }

    pub fn authenticate_peer<T>(&self, request: &Request<T>) -> Result<String, Status> {
        let certificates = request.peer_certs().ok_or_else(|| {
            Status::unauthenticated("authenticated client certificate is required")
        })?;
        let certificate = certificates.first().ok_or_else(|| {
            Status::unauthenticated("authenticated client certificate is required")
        })?;
        certificate_principal(&self.certificate_principals, certificate.as_ref()).ok_or_else(|| {
            Status::permission_denied("client certificate is not assigned to a service principal")
        })
    }

    pub async fn authorize(
        &self,
        context: &v2::RequestContext,
        method: &str,
        hub_id: Option<&str>,
        required_permission: Option<Permission>,
    ) -> Result<(), Status> {
        self.authorize_service_principal(context, method)?;
        let actor_type = v2::ActorType::try_from(context.actor_type)
            .map_err(|_| Status::unauthenticated("invalid actor type"))?;
        match actor_type {
            v2::ActorType::Service => {
                if required_permission.is_some() {
                    return Err(Status::permission_denied(
                        "service principals cannot impersonate human moderators",
                    ));
                }
                Ok(())
            }
            v2::ActorType::Human => {
                let permission = required_permission.ok_or_else(|| {
                    Status::permission_denied("this method is restricted to service principals")
                })?;
                let mut client = self.iris.clone();
                let request = CheckPermissionRequest {
                    hub_id: hub_id.unwrap_or_default().to_owned(),
                    user_id: context.actor_id.clone(),
                    required_permissions: permission as u64,
                };
                let response = tokio::time::timeout(
                    self.timeout,
                    client.check_permission(tonic::Request::new(request)),
                )
                .await
                .map_err(|_| Status::unavailable("Iris permission check timed out"))?
                .map_err(|status| {
                    if status.code() == Code::PermissionDenied {
                        Status::permission_denied("permission denied")
                    } else {
                        Status::unavailable("Iris permission service is unavailable")
                    }
                })?
                .into_inner();
                if response.allowed {
                    Ok(())
                } else {
                    Err(Status::permission_denied("permission denied"))
                }
            }
            v2::ActorType::Policy | v2::ActorType::Unspecified => Err(Status::permission_denied(
                "actor type is not permitted on this API",
            )),
        }
    }

    pub fn authorize_user_submission(
        &self,
        context: &v2::RequestContext,
        method: &str,
    ) -> Result<(), Status> {
        self.authorize_service_principal(context, method)?;
        match v2::ActorType::try_from(context.actor_type)
            .map_err(|_| Status::unauthenticated("invalid actor type"))?
        {
            v2::ActorType::Human => Ok(()),
            _ => Err(Status::permission_denied(
                "this method requires an authenticated human actor",
            )),
        }
    }

    fn authorize_service_principal(
        &self,
        context: &v2::RequestContext,
        method: &str,
    ) -> Result<(), Status> {
        if context.service_principal.is_empty() {
            return Err(Status::unauthenticated("service_principal is required"));
        }
        let methods = self
            .service_principals
            .get(&context.service_principal)
            .ok_or_else(|| Status::permission_denied("unknown service principal"))?;
        if methods.contains(method) {
            Ok(())
        } else {
            Err(Status::permission_denied(
                "service principal is not allowed to call this method",
            ))
        }
    }
}

fn certificate_principal(
    certificate_principals: &BTreeMap<String, String>,
    certificate_der: &[u8],
) -> Option<String> {
    let fingerprint = hex::encode(Sha256::digest(certificate_der));
    certificate_principals.get(&fingerprint).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_fingerprint_selects_exact_principal() {
        let certificate = b"client certificate DER";
        let fingerprint = hex::encode(Sha256::digest(certificate));
        let principals = BTreeMap::from([(fingerprint, "interchat-bot".to_owned())]);

        assert_eq!(
            certificate_principal(&principals, certificate).as_deref(),
            Some("interchat-bot")
        );
        assert_eq!(
            certificate_principal(&principals, b"different certificate"),
            None
        );
    }
}
