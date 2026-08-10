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
        authz::v2::{
            AuthorizationDecision, AuthorizeStaffOperationRequest,
            GetEffectiveStaffAuthorizationRequest, RequestMetadata, StaffOperation,
            staff_authorization_service_client::StaffAuthorizationServiceClient,
        },
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

pub const MANAGE_GLOBAL_CONTENT_POLICY_PERMISSION: u64 = 1 << 31;

#[derive(Clone)]
pub struct Authorizer {
    iris: AuthZServiceClient<Channel>,
    staff_iris: StaffAuthorizationServiceClient<Channel>,
    timeout: Duration,
    service_principals: Arc<BTreeMap<String, BTreeSet<String>>>,
    certificate_principals: Arc<BTreeMap<String, String>>,
}

impl Authorizer {
    pub async fn authorize_staff_permission(
        &self,
        context: &v2::RequestContext,
        method: &str,
        required_permission: u64,
    ) -> Result<(), Status> {
        self.authorize_service_principal(context, method)?;
        if v2::ActorType::try_from(context.actor_type)
            .map_err(|_| Status::unauthenticated("invalid actor type"))?
            != v2::ActorType::Human
        {
            return Err(Status::permission_denied(
                "staff permissions require an authenticated human actor",
            ));
        }
        let mut client = self.staff_iris.clone();
        let response = tokio::time::timeout(
            self.timeout,
            client.get_effective_staff_authorization(tonic::Request::new(
                GetEffectiveStaffAuthorizationRequest {
                    metadata: Some(RequestMetadata {
                        request_id: context.request_id.clone(),
                        service_principal: "polarizer".to_owned(),
                        actor_id: context.actor_id.clone(),
                        idempotency_key: context.idempotency_key.clone(),
                        trace_id: context.trace_id.clone(),
                    }),
                    user_id: context.actor_id.clone(),
                },
            )),
        )
        .await
        .map_err(|_| Status::unavailable("Iris staff authorization timed out"))?
        .map_err(|_| Status::unavailable("Iris staff authorization is unavailable"))?
        .into_inner();
        if response.effective_permissions & required_permission == required_permission {
            Ok(())
        } else {
            Err(Status::permission_denied("staff authorization denied"))
        }
    }

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
            iris: AuthZServiceClient::new(channel.clone()),
            staff_iris: StaffAuthorizationServiceClient::new(channel),
            timeout: config.iris_timeout,
            service_principals: Arc::new(config.service_principal_allowlist.clone()),
            certificate_principals: Arc::new(certificate_principals),
        })
    }

    pub async fn authorize_staff_operation(
        &self,
        context: &v2::RequestContext,
        operation: StaffOperation,
        target_staff_id: Option<&str>,
        duration_seconds: Option<u64>,
        permanent: bool,
    ) -> Result<AuthorizationDecision, Status> {
        let actor_type = v2::ActorType::try_from(context.actor_type)
            .map_err(|_| Status::unauthenticated("invalid actor type"))?;
        if actor_type != v2::ActorType::Human {
            return Err(Status::permission_denied(
                "staff operations require an authenticated human actor",
            ));
        }
        let mut client = self.staff_iris.clone();
        let response = tokio::time::timeout(
            self.timeout,
            client.authorize_staff_operation(tonic::Request::new(AuthorizeStaffOperationRequest {
                metadata: Some(RequestMetadata {
                    request_id: context.request_id.clone(),
                    // Iris authenticates this request with Polarizer's client
                    // certificate. Preserve the human actor separately, but do
                    // not forward the caller's service identity as our own.
                    service_principal: "polarizer".to_string(),
                    actor_id: context.actor_id.clone(),
                    idempotency_key: context.idempotency_key.clone(),
                    trace_id: context.trace_id.clone(),
                }),
                user_id: context.actor_id.clone(),
                operation: operation as i32,
                target_staff_id: target_staff_id.unwrap_or_default().to_owned(),
                duration_seconds,
                permanent,
            })),
        )
        .await
        .map_err(|_| Status::unavailable("Iris staff authorization timed out"))?
        .map_err(|status| {
            if status.code() == Code::PermissionDenied {
                Status::permission_denied("staff authorization denied")
            } else {
                Status::unavailable("Iris staff authorization is unavailable")
            }
        })?
        .into_inner();
        AuthorizationDecision::try_from(response.decision)
            .map_err(|_| Status::unavailable("Iris returned an invalid staff decision"))
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

    fn test_authorizer(methods: &[&str]) -> Authorizer {
        let channel = Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        Authorizer {
            iris: AuthZServiceClient::new(channel.clone()),
            staff_iris: StaffAuthorizationServiceClient::new(channel),
            timeout: Duration::from_millis(10),
            service_principals: Arc::new(BTreeMap::from([(
                "interchat-bot".to_owned(),
                methods.iter().map(|method| (*method).to_owned()).collect(),
            )])),
            certificate_principals: Arc::new(BTreeMap::new()),
        }
    }

    fn human_context() -> v2::RequestContext {
        v2::RequestContext {
            actor_id: "123".to_owned(),
            actor_type: v2::ActorType::Human as i32,
            service_principal: "interchat-bot".to_owned(),
            ..Default::default()
        }
    }

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

    #[tokio::test]
    async fn server_content_policy_requires_an_explicit_trusted_method() {
        let context = human_context();
        assert!(
            test_authorizer(&["ReplaceContentPolicy"])
                .authorize_user_submission(&context, "ReplaceContentPolicy")
                .is_ok()
        );
        let denied = test_authorizer(&["EvaluateAction"])
            .authorize_user_submission(&context, "ReplaceContentPolicy")
            .expect_err("method must be allowlisted");
        assert_eq!(denied.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn content_policy_mutation_rejects_non_human_actor() {
        let mut context = human_context();
        context.actor_type = v2::ActorType::Service as i32;
        let denied = test_authorizer(&["ReplaceContentPolicy"])
            .authorize_user_submission(&context, "ReplaceContentPolicy")
            .expect_err("service actors cannot edit server policy");
        assert_eq!(denied.code(), Code::PermissionDenied);
    }
}
