// Generated tonic service traits require `Status` by value. Keep that boundary
// type instead of introducing wrapper conversions solely to reduce its size.
#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};
use tonic::{Code, Request, Response, Status};
use tracing::warn;
use uuid::Uuid;

use crate::{
    auth::{Authorizer, MANAGE_GLOBAL_CONTENT_POLICY_PERMISSION, Permission},
    command::{
        ClaimState, CommandCompletion, CommandOutcome, CommandRepository, CommandRepositoryError,
    },
    content_policy::{
        Authority as ContentAuthority, ContentPolicy, PolicyAction, PolicyActionType, PolicyLimits,
        PolicyRule, PolicyScope, RulePattern, Surface as ContentSurface, WildcardPatternType,
        repository::{ContentPolicySource, PostgresContentPolicyRepository},
    },
    contract::{
        authz::v2::{AuthorizationDecision as StaffDecision, StaffOperation},
        effect_to_proto as contract_fixture_effect_to_proto,
        emitted_effect_to_proto as contract_effect_to_proto,
        scope_to_proto as contract_scope_to_proto, subject_to_proto as contract_subject_to_proto,
        v2::{
            self,
            trust_and_safety_service_server::TrustAndSafetyService as TrustAndSafetyServiceApi,
        },
    },
    moderation::{ModerationRepository, ReportSubmissionData},
    nsfw::{
        NsfwOverrideRepository, NsfwOverrideUpdateMask,
        classification_name as nsfw_classification_name,
    },
    policy::{
        engine::PolicyEngine,
        model::{
            Action, DataHandlingClass, Effect, ErrorBehavior, FeatureFailure, FeatureSnapshot,
            FeatureValue, PolicyLanguage, PolicyManifest, PolicyState, Product, Scope, ScopeType,
            Subject, TextSpan,
        },
        repository::{HeldActionRecord, HeldActionResolution, PostgresPolicyRepository},
        runtime::{Diagnostic as RuntimeDiagnostic, DiagnosticSeverity},
    },
};

pub struct TrustAndSafetyService {
    engine: Arc<PolicyEngine>,
    repository: Arc<PostgresPolicyRepository>,
    content_policy_repository: Arc<PostgresContentPolicyRepository>,
    authorizer: Arc<Authorizer>,
    moderation: Arc<ModerationRepository>,
    commands: Arc<CommandRepository>,
    nsfw_overrides: Arc<NsfwOverrideRepository>,
    staff_authorization_mode: crate::config::StaffAuthorizationMode,
    staff_case_claim_lease_seconds: i64,
    staff_case_transfer_cooldown_seconds: i64,
}

macro_rules! authenticate_request {
    ($service:expr, $request:ident, $context:ident, $mutation:expr) => {
        let authenticated_principal = $service.authorizer.authenticate_peer(&$request)?;
        let $request = $request.into_inner();
        let $context = validate_context(
            $request.context.as_ref(),
            $mutation,
            &authenticated_principal,
        )?;
    };
}

fn punishment_operation<'a>(
    creator_id: &'a str,
    actor_id: &str,
    own: StaffOperation,
    others: StaffOperation,
) -> (StaffOperation, Option<&'a str>) {
    if creator_id == actor_id {
        (own, None)
    } else {
        (others, Some(creator_id))
    }
}

impl TrustAndSafetyService {
    pub fn new(
        engine: Arc<PolicyEngine>,
        repository: Arc<PostgresPolicyRepository>,
        content_policy_repository: Arc<PostgresContentPolicyRepository>,
        authorizer: Arc<Authorizer>,
        moderation: Arc<ModerationRepository>,
        commands: Arc<CommandRepository>,
        config: &crate::config::AppConfig,
    ) -> Self {
        let nsfw_overrides = Arc::new(NsfwOverrideRepository::new(repository.pool().clone()));
        Self {
            engine,
            repository,
            content_policy_repository,
            authorizer,
            moderation,
            commands,
            nsfw_overrides,
            staff_authorization_mode: config.staff_authorization_mode,
            staff_case_claim_lease_seconds: config.staff_case_claim_lease.as_secs() as i64,
            staff_case_transfer_cooldown_seconds: config.staff_case_transfer_cooldown.as_secs()
                as i64,
        }
    }

    async fn authorize_policy_bundle(
        &self,
        context: &v2::RequestContext,
        method: &str,
        bundle: &crate::policy::model::PolicyBundle,
        hub_permission: Permission,
    ) -> Result<(), Status> {
        match bundle.scope.scope_type {
            ScopeType::Hub => {
                self.authorizer
                    .authorize(
                        context,
                        method,
                        Some(&bundle.scope.id),
                        Some(hub_permission),
                    )
                    .await
            }
            ScopeType::Lobby => {
                self.authorizer
                    .authorize(context, method, None, Some(Permission::HandleLobbyReports))
                    .await
            }
            ScopeType::Platform | ScopeType::Product | ScopeType::IncidentOverlay => {
                self.authorizer
                    .authorize(context, method, None, Some(Permission::Administrator))
                    .await
            }
        }
    }

    async fn authorize_content_policy_scope(
        &self,
        context: &v2::RequestContext,
        method: &str,
        scope: &PolicyScope,
    ) -> Result<(), Status> {
        match scope.authority {
            ContentAuthority::Global => {
                self.authorizer
                    .authorize_staff_permission(
                        context,
                        method,
                        MANAGE_GLOBAL_CONTENT_POLICY_PERMISSION,
                    )
                    .await
            }
            ContentAuthority::Hub => {
                self.authorizer
                    .authorize(
                        context,
                        method,
                        Some(&scope.id),
                        Some(Permission::ManageRules),
                    )
                    .await
            }
            ContentAuthority::Server => self.authorizer.authorize_user_submission(context, method),
        }
    }

    async fn authorize_staff(
        &self,
        context: &v2::RequestContext,
        operation: StaffOperation,
        legacy_permission: Permission,
        target_staff_id: Option<&str>,
        duration_seconds: Option<u64>,
        permanent: bool,
    ) -> Result<StaffDecision, Status> {
        use crate::config::StaffAuthorizationMode;
        match self.staff_authorization_mode {
            StaffAuthorizationMode::Legacy => {
                self.authorizer
                    .authorize(
                        context,
                        "AuthorizeStaffOperation",
                        None,
                        Some(legacy_permission),
                    )
                    .await?;
                Ok(StaffDecision::Allow)
            }
            StaffAuthorizationMode::Shadow => {
                self.authorizer
                    .authorize(
                        context,
                        "AuthorizeStaffOperation",
                        None,
                        Some(legacy_permission),
                    )
                    .await?;
                match self
                    .authorizer
                    .authorize_staff_operation(
                        context,
                        operation,
                        target_staff_id,
                        duration_seconds,
                        permanent,
                    )
                    .await
                {
                    Ok(StaffDecision::Allow) => {}
                    Ok(decision) => {
                        warn!(operation=?operation, new_decision=?decision, "staff authorization shadow mismatch")
                    }
                    Err(error) => {
                        warn!(operation=?operation, error=%error, "staff authorization shadow call failed")
                    }
                }
                Ok(StaffDecision::Allow)
            }
            StaffAuthorizationMode::Enforce => {
                self.authorizer
                    .authorize_staff_operation(
                        context,
                        operation,
                        target_staff_id,
                        duration_seconds,
                        permanent,
                    )
                    .await
            }
        }
    }

    async fn authorize_scope(
        &self,
        context: &v2::RequestContext,
        method: &str,
        scope: &v2::Scope,
        hub_permission: Permission,
        lobby_permission: Permission,
        global_permission: Permission,
    ) -> Result<(), Status> {
        match v2::ScopeType::try_from(scope.r#type)
            .map_err(|_| Status::invalid_argument("invalid scope type"))?
        {
            v2::ScopeType::Hub => {
                self.authorizer
                    .authorize(context, method, Some(&scope.id), Some(hub_permission))
                    .await
            }
            v2::ScopeType::Lobby => {
                self.authorizer
                    .authorize(context, method, None, Some(lobby_permission))
                    .await
            }
            v2::ScopeType::Platform | v2::ScopeType::Product | v2::ScopeType::IncidentOverlay => {
                self.authorizer
                    .authorize(context, method, None, Some(global_permission))
                    .await
            }
            v2::ScopeType::Unspecified => Err(Status::invalid_argument("scope is required")),
        }
    }

    async fn authorize_scope_or_service(
        &self,
        context: &v2::RequestContext,
        method: &str,
        scope: &v2::Scope,
        hub_permission: Permission,
        lobby_permission: Permission,
        global_permission: Permission,
    ) -> Result<(), Status> {
        if v2::ActorType::try_from(context.actor_type).unwrap_or_default() == v2::ActorType::Service
        {
            self.authorizer.authorize(context, method, None, None).await
        } else {
            self.authorize_scope(
                context,
                method,
                scope,
                hub_permission,
                lobby_permission,
                global_permission,
            )
            .await
        }
    }

    async fn authorize_non_hub_staff_scope(
        &self,
        context: &v2::RequestContext,
        scope: &v2::Scope,
        operation: StaffOperation,
        lobby_legacy_permission: Permission,
        global_legacy_permission: Permission,
    ) -> Result<(), Status> {
        let legacy_permission = match v2::ScopeType::try_from(scope.r#type)
            .map_err(|_| Status::invalid_argument("invalid scope type"))?
        {
            v2::ScopeType::Lobby => lobby_legacy_permission,
            v2::ScopeType::Platform | v2::ScopeType::Product | v2::ScopeType::IncidentOverlay => {
                global_legacy_permission
            }
            v2::ScopeType::Hub => {
                return Err(Status::internal("hub scope must use hub authorization"));
            }
            v2::ScopeType::Unspecified => {
                return Err(Status::invalid_argument("scope is required"));
            }
        };
        if self
            .authorize_staff(context, operation, legacy_permission, None, None, false)
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorize_hub_or_staff(
        &self,
        context: &v2::RequestContext,
        method: &str,
        scope: &v2::Scope,
        hub_permission: Permission,
        staff_operation: StaffOperation,
        legacy_staff_permission: Permission,
        target_staff_id: Option<&str>,
    ) -> Result<(), Status> {
        if scope.r#type != v2::ScopeType::Hub as i32 {
            return Err(Status::internal(
                "hub-or-staff authorization requires hub scope",
            ));
        }
        if v2::ActorType::try_from(context.actor_type).unwrap_or_default() == v2::ActorType::Service
        {
            return self.authorizer.authorize(context, method, None, None).await;
        }
        match self
            .authorizer
            .authorize(context, method, Some(&scope.id), Some(hub_permission))
            .await
        {
            Ok(()) => return Ok(()),
            Err(status) if status.code() == Code::PermissionDenied => {}
            Err(status) => return Err(status),
        }
        if self
            .authorize_staff(
                context,
                staff_operation,
                legacy_staff_permission,
                target_staff_id,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        Ok(())
    }

    async fn evaluate_safety_assessment_update(
        &self,
        assessment: &v2::SafetyAssessment,
    ) -> Result<(), Status> {
        let scope = assessment
            .scope
            .clone()
            .ok_or_else(|| Status::internal("safety assessment scope is missing"))?;
        let subject = assessment
            .subject
            .clone()
            .ok_or_else(|| Status::internal("safety assessment subject is missing"))?;
        let identity = format!(
            "{}:{}:{}:{}:{}",
            scope.r#type, scope.id, subject.user_id, subject.server_id, assessment.version
        );
        let digest = Sha256::digest(identity.as_bytes());
        let mut action_id = [0_u8; 16];
        action_id.copy_from_slice(&digest[..16]);
        let action = action_from_proto(v2::Action {
            id: Uuid::from_bytes(action_id).to_string(),
            r#type: "safety.assessment.updated".into(),
            schema_version: 1,
            scope: Some(scope),
            subject: Some(subject),
            occurred_at: Some(timestamp(Utc::now())),
            attributes: Some(json_to_struct(&serde_json::json!({
                "assessment_id": assessment.id,
                "score": assessment.score,
                "tier": assessment.tier,
                "version": assessment.version,
            }))),
            data_handling: v2::DataHandlingClass::Internal as i32,
        })?;
        self.engine
            .evaluate_with_shadow(&action)
            .await
            .map_err(internal)?;
        Ok(())
    }

    async fn evaluate_current_safety(
        &self,
        scope: Option<&v2::Scope>,
        subject: Option<&v2::Subject>,
    ) -> Result<(), Status> {
        let (Some(scope), Some(subject)) = (scope, subject) else {
            return Ok(());
        };
        if subject.user_id.is_empty() && subject.server_id.is_empty() {
            return Ok(());
        }
        let assessment = self
            .moderation
            .get_safety_assessment(scope, subject)
            .await
            .map_err(internal)?;
        self.evaluate_safety_assessment_update(&assessment).await
    }

    async fn authorize_moderation_record_link(
        &self,
        context: &v2::RequestContext,
        record: &v2::ModerationRecord,
    ) -> Result<(), Status> {
        let (created_by, scope, kind) = moderation_record_authorization_fields(record)?;
        let (operation, target_staff_id) = punishment_operation(
            created_by,
            &context.actor_id,
            StaffOperation::EditOwnPunishment,
            StaffOperation::EditOthersPunishment,
        );
        let legacy_permission = moderation_record_legacy_permission(kind, scope);
        if self
            .authorize_staff(
                context,
                operation,
                legacy_permission,
                target_staff_id,
                None,
                false,
            )
            .await?
            == StaffDecision::Allow
        {
            Ok(())
        } else {
            Err(Status::permission_denied("staff authorization denied"))
        }
    }
}

#[tonic::async_trait]
impl TrustAndSafetyServiceApi for TrustAndSafetyService {
    async fn evaluate_action(
        &self,
        request: Request<v2::EvaluateActionRequest>,
    ) -> Result<Response<v2::EvaluateActionResponse>, Status> {
        authenticate_request!(self, request, context, false);
        self.authorizer
            .authorize(context, "EvaluateAction", None, None)
            .await?;
        let action = action_from_proto(
            request
                .action
                .ok_or_else(|| Status::invalid_argument("action is required"))?,
        )?;
        let result = if request.shadow_only {
            self.engine
                .evaluate(&action, true)
                .await
                .map_err(internal)?
                .0
        } else {
            self.engine
                .evaluate_with_shadow(&action)
                .await
                .map_err(internal)?
                .0
        };
        Ok(Response::new(v2::EvaluateActionResponse {
            decision: Some(decision_to_proto(&result)),
        }))
    }

    async fn claim_command(
        &self,
        request: Request<v2::ClaimCommandRequest>,
    ) -> Result<Response<v2::ClaimCommandResponse>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize(context, "ClaimCommand", None, None)
            .await?;
        let command_id = parse_uuid(&request.command_id, "command_id")?;
        let claimant_id = request.claimant_id.trim();
        if claimant_id.is_empty() || claimant_id.len() > 128 {
            return Err(Status::invalid_argument(
                "claimant_id must be between 1 and 128 characters",
            ));
        }
        let lease_ms = duration_to_millis(
            request
                .requested_lease
                .ok_or_else(|| Status::invalid_argument("requested_lease is required"))?,
        )?;
        if !(5_000..=300_000).contains(&lease_ms) {
            return Err(Status::invalid_argument(
                "requested_lease must be between 5 and 300 seconds",
            ));
        }
        let claim = self
            .commands
            .claim(command_id, claimant_id, lease_ms.div_ceil(1_000) as i64)
            .await
            .map_err(command_error)?;
        let completed_result = claim
            .outcome
            .as_ref()
            .map(|outcome| command_result_to_proto(&claim.command, outcome));
        Ok(Response::new(v2::ClaimCommandResponse {
            state: match claim.state {
                ClaimState::Acquired => v2::CommandClaimState::Acquired,
                ClaimState::Busy => v2::CommandClaimState::Busy,
                ClaimState::Completed => v2::CommandClaimState::Completed,
                ClaimState::RecoveryRequired => v2::CommandClaimState::RecoveryRequired,
            } as i32,
            command: Some(claim.command),
            lease_token: claim
                .lease_token
                .map(|token| token.to_string())
                .unwrap_or_default(),
            lease_expires_at: claim.lease_expires_at.map(timestamp),
            attempt_count: claim.attempt_count.max(0) as u32,
            version: claim.version.max(0) as u64,
            completed_result,
        }))
    }

    async fn complete_command(
        &self,
        request: Request<v2::CompleteCommandRequest>,
    ) -> Result<Response<v2::CompleteCommandResponse>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize(context, "CompleteCommand", None, None)
            .await?;
        let command_id = parse_uuid(&request.command_id, "command_id")?;
        let lease_token = parse_uuid(&request.lease_token, "lease_token")?;
        if request.expected_version == 0 || request.expected_version > i64::MAX as u64 {
            return Err(Status::invalid_argument("expected_version is required"));
        }
        if request.result_code.is_empty()
            || request.result_code.len() > 64
            || !request
                .result_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(Status::invalid_argument(
                "result_code must be an uppercase identifier of at most 64 characters",
            ));
        }
        let occurred_at = request
            .occurred_at
            .map(datetime)
            .transpose()?
            .ok_or_else(|| Status::invalid_argument("occurred_at is required"))?;
        let completion = self
            .commands
            .complete(
                command_id,
                lease_token,
                request.expected_version as i64,
                CommandOutcome {
                    success: request.success,
                    result_code: request.result_code,
                    occurred_at,
                },
            )
            .await
            .map_err(command_error)?;
        Ok(Response::new(v2::CompleteCommandResponse {
            result: Some(completion_result_to_proto(command_id, &completion)),
            version: completion.version.max(0) as u64,
        }))
    }

    async fn get_content_policy(
        &self,
        request: Request<v2::GetContentPolicyRequest>,
    ) -> Result<Response<v2::GetContentPolicyResponse>, Status> {
        authenticate_request!(self, request, context, false);
        let scope = content_policy_scope_from_proto(
            request
                .scope
                .ok_or_else(|| Status::invalid_argument("scope is required"))?,
        )?;
        self.authorize_content_policy_scope(context, "GetContentPolicy", &scope)
            .await?;
        let limits = PolicyLimits::default();
        let policy = self
            .content_policy_repository
            .load_scope(&scope)
            .await
            .map_err(internal)?;
        Ok(Response::new(v2::GetContentPolicyResponse {
            policy: policy.as_ref().map(content_policy_to_proto),
            pattern_limit: limits.maximum_patterns(scope.authority) as u32,
        }))
    }

    async fn replace_content_policy(
        &self,
        request: Request<v2::ReplaceContentPolicyRequest>,
    ) -> Result<Response<v2::ReplaceContentPolicyResponse>, Status> {
        authenticate_request!(self, request, context, true);
        let mut policy = content_policy_from_proto(
            request
                .policy
                .ok_or_else(|| Status::invalid_argument("policy is required"))?,
            &context.actor_id,
        )?;
        self.authorize_content_policy_scope(context, "ReplaceContentPolicy", &policy.scope)
            .await?;
        policy.version = request
            .expected_version
            .checked_add(1)
            .ok_or_else(|| Status::invalid_argument("expected_version is out of range"))?;
        let limits = PolicyLimits::default();
        let policy = self
            .content_policy_repository
            .replace_policy(&policy, request.expected_version, limits, context)
            .await
            .map_err(content_policy_error)?;
        Ok(Response::new(v2::ReplaceContentPolicyResponse {
            policy: Some(content_policy_to_proto(&policy)),
            pattern_limit: limits.maximum_patterns(policy.scope.authority) as u32,
        }))
    }

    async fn create_policy_bundle(
        &self,
        request: Request<v2::CreatePolicyBundleRequest>,
    ) -> Result<Response<v2::PolicyBundle>, Status> {
        authenticate_request!(self, request, context, true);
        let scope = policy_scope_from_proto(
            request
                .scope
                .ok_or_else(|| Status::invalid_argument("scope is required"))?,
        )?;
        self.authorize_scope(
            context,
            "CreatePolicyBundle",
            &contract_scope_to_proto(&scope),
            Permission::ManageRules,
            Permission::HandleLobbyReports,
            Permission::Administrator,
        )
        .await?;
        let bundle = self
            .repository
            .create_bundle(
                &request.name,
                &request.description,
                &scope,
                request.mandatory,
                request.priority,
                context,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(bundle_to_proto(&bundle)))
    }

    async fn get_policy_bundle(
        &self,
        request: Request<v2::GetPolicyBundleRequest>,
    ) -> Result<Response<v2::PolicyBundle>, Status> {
        authenticate_request!(self, request, context, false);
        let id = parse_uuid(&request.bundle_id, "bundle_id")?;
        let bundle = self
            .repository
            .load_bundle(id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(context, "GetPolicyBundle", &bundle, Permission::ViewLogs)
            .await?;
        Ok(Response::new(bundle_to_proto(&bundle)))
    }

    async fn list_policy_bundles(
        &self,
        request: Request<v2::ListPolicyBundlesRequest>,
    ) -> Result<Response<v2::ListPolicyBundlesResponse>, Status> {
        authenticate_request!(self, request, context, false);
        let scope = policy_scope_from_proto(
            request
                .scope
                .ok_or_else(|| Status::invalid_argument("scope is required"))?,
        )?;
        self.authorize_scope(
            context,
            "ListPolicyBundles",
            &contract_scope_to_proto(&scope),
            Permission::ViewLogs,
            Permission::HandleLobbyReports,
            Permission::Administrator,
        )
        .await?;
        let state = policy_bundle_state_from_proto(request.state)?;
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let (bundles, next) = self
            .repository
            .list_bundles(
                &scope,
                state,
                optional_uuid_cursor(&page.cursor)?,
                i64::from(page.page_size.max(1)),
            )
            .await
            .map_err(internal)?;
        Ok(Response::new(v2::ListPolicyBundlesResponse {
            bundles: bundles.iter().map(bundle_to_proto).collect(),
            page: Some(v2::CursorPageResult {
                next_cursor: next.map(|id| id.to_string()).unwrap_or_default(),
            }),
        }))
    }

    async fn update_policy_bundle(
        &self,
        request: Request<v2::UpdatePolicyBundleRequest>,
    ) -> Result<Response<v2::PolicyBundle>, Status> {
        authenticate_request!(self, request, context, true);
        let requested = request
            .bundle
            .ok_or_else(|| Status::invalid_argument("bundle is required"))?;
        let id = parse_uuid(&requested.id, "bundle.id")?;
        let existing = self
            .repository
            .load_bundle(id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "UpdatePolicyBundle",
            &existing,
            Permission::ManageRules,
        )
        .await?;
        let paths = policy_bundle_update_paths(request.update_mask.as_ref())?;
        let updated = self
            .repository
            .update_bundle(
                id,
                paths.name.then_some(requested.name.as_str()),
                paths.description.then_some(requested.description.as_str()),
                paths.mandatory.then_some(requested.mandatory),
                paths.priority.then_some(requested.priority),
                request.expected_version as i64,
                context,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(bundle_to_proto(&updated)))
    }

    async fn disable_policy_bundle(
        &self,
        request: Request<v2::DisablePolicyBundleRequest>,
    ) -> Result<Response<v2::PolicyBundle>, Status> {
        authenticate_request!(self, request, context, true);
        let id = parse_uuid(&request.bundle_id, "bundle_id")?;
        let existing = self
            .repository
            .load_bundle(id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "DisablePolicyBundle",
            &existing,
            Permission::ManageRules,
        )
        .await?;
        let updated = self
            .repository
            .transition_bundle(
                id,
                crate::policy::model::PolicyBundleState::Disabled,
                request.expected_version as i64,
                context,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(bundle_to_proto(&updated)))
    }

    async fn retire_policy_bundle(
        &self,
        request: Request<v2::RetirePolicyBundleRequest>,
    ) -> Result<Response<v2::PolicyBundle>, Status> {
        authenticate_request!(self, request, context, true);
        let id = parse_uuid(&request.bundle_id, "bundle_id")?;
        let existing = self
            .repository
            .load_bundle(id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "RetirePolicyBundle",
            &existing,
            Permission::ManageRules,
        )
        .await?;
        let updated = self
            .repository
            .transition_bundle(
                id,
                crate::policy::model::PolicyBundleState::Retired,
                request.expected_version as i64,
                context,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(bundle_to_proto(&updated)))
    }

    async fn create_policy_draft(
        &self,
        request: Request<v2::CreatePolicyDraftRequest>,
    ) -> Result<Response<v2::PolicyVersion>, Status> {
        authenticate_request!(self, request, context, true);
        let bundle_id = parse_uuid(&request.bundle_id, "bundle_id")?;
        let bundle = self
            .repository
            .load_bundle(bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "CreatePolicyDraft",
            &bundle,
            Permission::ManageRules,
        )
        .await?;
        let language = language_from_proto(request.language)?;
        let manifest = manifest_from_proto(
            request
                .manifest
                .ok_or_else(|| Status::invalid_argument("manifest is required"))?,
        )?;
        let version = self
            .repository
            .create_draft(
                bundle_id,
                language,
                request.source,
                manifest,
                context,
                request.expected_bundle_version as i64,
            )
            .await
            .map_err(conflict_or_internal)?;
        Ok(Response::new(policy_version_to_proto(&version)))
    }

    async fn validate_policy(
        &self,
        request: Request<v2::ValidatePolicyRequest>,
    ) -> Result<Response<v2::ValidatePolicyResponse>, Status> {
        authenticate_request!(self, request, context, true);
        let id = parse_uuid(&request.policy_version_id, "policy_version_id")?;
        let version = self
            .repository
            .get_version(id)
            .await
            .map_err(not_found_or_internal)?;
        let bundle = self
            .repository
            .load_bundle(version.bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(context, "ValidatePolicy", &bundle, Permission::ManageRules)
            .await?;
        if version.state != PolicyState::Draft {
            return Err(Status::failed_precondition(
                "only draft policy versions can be validated",
            ));
        }
        let (diagnostics, artifact) = self
            .engine
            .validate_and_compile(version.language, &version.source, &version.manifest)
            .await
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let version = if let Some(artifact) = artifact {
            self.repository
                .mark_validated(
                    id,
                    &artifact.runtime_version,
                    &artifact.bytes,
                    &artifact.content_sha256,
                    serde_json::to_value(&diagnostics).map_err(|error| internal(error.into()))?,
                    context,
                )
                .await
                .map_err(conflict_or_internal)?
        } else {
            version
        };
        Ok(Response::new(v2::ValidatePolicyResponse {
            diagnostics: diagnostics.iter().map(diagnostic_to_proto).collect(),
            policy_version: Some(policy_version_to_proto(&version)),
        }))
    }

    async fn run_policy_tests(
        &self,
        request: Request<v2::RunPolicyTestsRequest>,
    ) -> Result<Response<v2::RunPolicyTestsResponse>, Status> {
        authenticate_request!(self, request, context, true);
        let version_id = parse_uuid(&request.policy_version_id, "policy_version_id")?;
        let version = self
            .repository
            .get_version(version_id)
            .await
            .map_err(not_found_or_internal)?;
        let bundle = self
            .repository
            .load_bundle(version.bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(context, "RunPolicyTests", &bundle, Permission::ManageRules)
            .await?;
        if let Some(results) = self
            .repository
            .replayed_test_run(context)
            .await
            .map_err(conflict_or_internal)?
        {
            return Ok(Response::new(v2::RunPolicyTestsResponse {
                results: fixture_results_from_json(results)?,
            }));
        }
        if version.compiled_artifact.is_empty() {
            return Err(Status::failed_precondition(
                "policy version must validate before tests can run",
            ));
        }
        let mut fixtures = self
            .repository
            .fixtures(version_id)
            .await
            .map_err(internal)?;
        for fixture in request.ad_hoc_fixtures {
            let action = action_from_proto(
                fixture
                    .action
                    .ok_or_else(|| Status::invalid_argument("fixture action is required"))?,
            )?;
            let features = feature_snapshot_from_proto(fixture.features.unwrap_or_default())?;
            let expected_effects = fixture
                .expected_effects
                .into_iter()
                .map(effect_from_proto)
                .collect::<Result<Vec<_>, _>>()?;
            fixtures.push(crate::policy::repository::StoredFixture {
                id: if fixture.id.is_empty() {
                    Uuid::now_v7()
                } else {
                    parse_uuid(&fixture.id, "fixture.id")?
                },
                policy_version_id: version_id,
                name: fixture.name,
                action,
                features,
                expected_effects,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: 0,
            });
        }
        let mut results = Vec::with_capacity(fixtures.len());
        for fixture in fixtures {
            let evaluated = self
                .engine
                .evaluate_policy_version(&version, &fixture.action, &fixture.features)
                .await;
            let (passed, differences) = match evaluated {
                Ok(evaluations) => {
                    let actual = evaluations
                        .into_iter()
                        .flat_map(|item| item.effects)
                        .collect::<Vec<_>>();
                    compare_effects(&fixture.expected_effects, &actual)
                }
                Err(error) => (false, vec![format!("runtime error: {error}")]),
            };
            results.push(v2::FixtureResult {
                fixture_id: fixture.id.to_string(),
                passed,
                differences,
                trace: None,
            });
        }
        let passed = results.iter().all(|result| result.passed);
        self.repository.record_test_run(
            version_id,
            passed,
            serde_json::json!(results.iter().map(|result| serde_json::json!({"fixture_id": result.fixture_id, "passed": result.passed, "differences": result.differences})).collect::<Vec<_>>()),
            context,
        ).await.map_err(internal)?;
        Ok(Response::new(v2::RunPolicyTestsResponse { results }))
    }

    async fn create_policy_fixture(
        &self,
        request: Request<v2::CreatePolicyFixtureRequest>,
    ) -> Result<Response<v2::PolicyFixture>, Status> {
        authenticate_request!(self, request, context, true);
        let fixture = request
            .fixture
            .ok_or_else(|| Status::invalid_argument("fixture is required"))?;
        let (policy_version_id, name, action, features, expected_effects) =
            stored_fixture_from_proto(fixture)?;
        let version = self
            .repository
            .get_version(policy_version_id)
            .await
            .map_err(not_found_or_internal)?;
        let bundle = self
            .repository
            .load_bundle(version.bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "CreatePolicyFixture",
            &bundle,
            Permission::ManageRules,
        )
        .await?;
        let fixture = self
            .repository
            .create_fixture(
                policy_version_id,
                &name,
                &action,
                &features,
                &expected_effects,
                context,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(stored_fixture_to_proto(&fixture)))
    }

    async fn update_policy_fixture(
        &self,
        request: Request<v2::UpdatePolicyFixtureRequest>,
    ) -> Result<Response<v2::PolicyFixture>, Status> {
        authenticate_request!(self, request, context, true);
        let fixture = request
            .fixture
            .ok_or_else(|| Status::invalid_argument("fixture is required"))?;
        let fixture_id = parse_uuid(&fixture.id, "fixture.id")?;
        let existing = self
            .repository
            .fixture(fixture_id)
            .await
            .map_err(not_found_or_internal)?;
        let (policy_version_id, name, action, features, expected_effects) =
            stored_fixture_from_proto(fixture)?;
        if policy_version_id != existing.policy_version_id {
            return Err(Status::invalid_argument(
                "fixture policy_version_id cannot be changed",
            ));
        }
        let version = self
            .repository
            .get_version(existing.policy_version_id)
            .await
            .map_err(not_found_or_internal)?;
        let bundle = self
            .repository
            .load_bundle(version.bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "UpdatePolicyFixture",
            &bundle,
            Permission::ManageRules,
        )
        .await?;
        let fixture = self
            .repository
            .update_fixture(
                fixture_id,
                &name,
                &action,
                &features,
                &expected_effects,
                request.expected_version as i64,
                context,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(stored_fixture_to_proto(&fixture)))
    }

    async fn delete_policy_fixture(
        &self,
        request: Request<v2::DeletePolicyFixtureRequest>,
    ) -> Result<Response<()>, Status> {
        authenticate_request!(self, request, context, true);
        let fixture_id = parse_uuid(&request.fixture_id, "fixture_id")?;
        let existing = self
            .repository
            .fixture(fixture_id)
            .await
            .map_err(not_found_or_internal)?;
        let version = self
            .repository
            .get_version(existing.policy_version_id)
            .await
            .map_err(not_found_or_internal)?;
        let bundle = self
            .repository
            .load_bundle(version.bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "DeletePolicyFixture",
            &bundle,
            Permission::ManageRules,
        )
        .await?;
        self.repository
            .delete_fixture(fixture_id, request.expected_version as i64, context)
            .await
            .map_err(resource_error)?;
        Ok(Response::new(()))
    }

    async fn list_policy_fixtures(
        &self,
        request: Request<v2::ListPolicyFixturesRequest>,
    ) -> Result<Response<v2::ListPolicyFixturesResponse>, Status> {
        authenticate_request!(self, request, context, false);
        let policy_version_id = parse_uuid(&request.policy_version_id, "policy_version_id")?;
        let version = self
            .repository
            .get_version(policy_version_id)
            .await
            .map_err(not_found_or_internal)?;
        let bundle = self
            .repository
            .load_bundle(version.bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(context, "ListPolicyFixtures", &bundle, Permission::ViewLogs)
            .await?;
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let page_size = page.page_size.clamp(1, 100);
        let fixtures = self
            .repository
            .list_fixtures(
                policy_version_id,
                optional_uuid_cursor(&page.cursor)?,
                i64::from(page_size),
            )
            .await
            .map_err(internal)?;
        let next_cursor = if fixtures.len() == page_size as usize {
            fixtures
                .last()
                .map(|fixture| fixture.id.to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Response::new(v2::ListPolicyFixturesResponse {
            fixtures: fixtures.iter().map(stored_fixture_to_proto).collect(),
            page: Some(v2::CursorPageResult { next_cursor }),
        }))
    }

    async fn set_shadow_mode(
        &self,
        request: Request<v2::SetShadowModeRequest>,
    ) -> Result<Response<v2::PolicyBundle>, Status> {
        authenticate_request!(self, request, context, true);
        let bundle_id = parse_uuid(&request.bundle_id, "bundle_id")?;
        let current_bundle = self
            .repository
            .load_bundle(bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "SetShadowMode",
            &current_bundle,
            Permission::ManageRules,
        )
        .await?;
        let bundle = self
            .repository
            .set_shadow(
                bundle_id,
                parse_uuid(&request.policy_version_id, "policy_version_id")?,
                request.enabled,
                context,
                request.expected_bundle_version as i64,
            )
            .await
            .map_err(conflict_or_internal)?;
        Ok(Response::new(bundle_to_proto(&bundle)))
    }

    async fn publish_policy_version(
        &self,
        request: Request<v2::PublishPolicyVersionRequest>,
    ) -> Result<Response<v2::PolicyVersion>, Status> {
        authenticate_request!(self, request, context, true);
        let id = parse_uuid(&request.policy_version_id, "policy_version_id")?;
        let existing = self
            .repository
            .get_version(id)
            .await
            .map_err(not_found_or_internal)?;
        let bundle = self
            .repository
            .load_bundle(existing.bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "PublishPolicyVersion",
            &bundle,
            Permission::ManageRules,
        )
        .await?;
        let version = self
            .repository
            .publish(id, context, request.expected_bundle_version as i64)
            .await
            .map_err(conflict_or_internal)?;
        Ok(Response::new(policy_version_to_proto(&version)))
    }

    async fn approve_policy_version(
        &self,
        request: Request<v2::ApprovePolicyVersionRequest>,
    ) -> Result<Response<v2::PolicyApproval>, Status> {
        authenticate_request!(self, request, context, true);
        let policy_version_id = parse_uuid(&request.policy_version_id, "policy_version_id")?;
        let version = self
            .repository
            .get_version(policy_version_id)
            .await
            .map_err(not_found_or_internal)?;
        let bundle = self
            .repository
            .load_bundle(version.bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "ApprovePolicyVersion",
            &bundle,
            Permission::ManageRules,
        )
        .await?;
        let approved_at = self
            .repository
            .approve(policy_version_id, context)
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::PolicyApproval {
            policy_version_id: policy_version_id.to_string(),
            administrator_id: context.actor_id.clone(),
            approved_at: Some(timestamp(approved_at)),
        }))
    }

    async fn activate_policy_version(
        &self,
        request: Request<v2::ActivatePolicyVersionRequest>,
    ) -> Result<Response<v2::PolicyBundle>, Status> {
        authenticate_request!(self, request, context, true);
        let bundle_id = parse_uuid(&request.bundle_id, "bundle_id")?;
        let version_id = parse_uuid(&request.policy_version_id, "policy_version_id")?;
        let existing_bundle = self
            .repository
            .load_bundle(bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "ActivatePolicyVersion",
            &existing_bundle,
            Permission::ManageRules,
        )
        .await?;
        ensure_required_providers_healthy(
            &self.engine,
            &self
                .repository
                .get_version(version_id)
                .await
                .map_err(not_found_or_internal)?,
        )
        .await?;
        if let Some(activate_at) = request.activate_at.map(datetime).transpose()?
            && activate_at > Utc::now() + chrono::Duration::seconds(1)
        {
            self.repository
                .schedule_activation(
                    bundle_id,
                    version_id,
                    request.expected_bundle_version as i64,
                    "ACTIVATE",
                    activate_at,
                    context,
                )
                .await
                .map_err(internal)?;
            return Ok(Response::new(bundle_to_proto(
                &self
                    .repository
                    .load_bundle(bundle_id)
                    .await
                    .map_err(internal)?,
            )));
        }
        let bundle = self
            .repository
            .activate(
                bundle_id,
                version_id,
                context,
                request.expected_bundle_version as i64,
                "ACTIVATE",
            )
            .await
            .map_err(conflict_or_internal)?;
        Ok(Response::new(bundle_to_proto(&bundle)))
    }

    async fn rollback_policy(
        &self,
        request: Request<v2::RollbackPolicyRequest>,
    ) -> Result<Response<v2::PolicyBundle>, Status> {
        authenticate_request!(self, request, context, true);
        let bundle_id = parse_uuid(&request.bundle_id, "bundle_id")?;
        let existing_bundle = self
            .repository
            .load_bundle(bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(
            context,
            "RollbackPolicy",
            &existing_bundle,
            Permission::ManageRules,
        )
        .await?;
        let version_id = parse_uuid(
            &request.target_policy_version_id,
            "target_policy_version_id",
        )?;
        let bundle = self
            .repository
            .activate(
                bundle_id,
                version_id,
                context,
                request.expected_bundle_version as i64,
                "ROLLBACK",
            )
            .await
            .map_err(conflict_or_internal)?;
        Ok(Response::new(bundle_to_proto(&bundle)))
    }

    async fn list_policy_versions(
        &self,
        request: Request<v2::ListPolicyVersionsRequest>,
    ) -> Result<Response<v2::ListPolicyVersionsResponse>, Status> {
        authenticate_request!(self, request, context, false);
        let bundle_id = parse_uuid(&request.bundle_id, "bundle_id")?;
        let bundle = self
            .repository
            .load_bundle(bundle_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_policy_bundle(context, "ListPolicyVersions", &bundle, Permission::ViewLogs)
            .await?;
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let before_version = if page.cursor.is_empty() {
            None
        } else {
            Some(
                page.cursor
                    .parse::<i32>()
                    .map_err(|_| Status::invalid_argument("invalid cursor"))?,
            )
        };
        let versions = self
            .repository
            .list_versions(bundle_id, i64::from(page.page_size.max(1)), before_version)
            .await
            .map_err(internal)?;
        let next_cursor = if versions.len() == page.page_size.max(1) as usize {
            versions
                .last()
                .map(|version| version.version.to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Response::new(v2::ListPolicyVersionsResponse {
            versions: versions.iter().map(policy_version_to_proto).collect(),
            page: Some(v2::CursorPageResult { next_cursor }),
        }))
    }

    async fn get_execution_trace(
        &self,
        request: Request<v2::GetExecutionTraceRequest>,
    ) -> Result<Response<v2::ExecutionTrace>, Status> {
        authenticate_request!(self, request, context, false);
        let id = parse_uuid(&request.trace_id, "trace_id")?;
        let (trace, scope) = self
            .repository
            .execution_trace_with_scope(id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorizer
            .authorize(
                context,
                "GetExecutionTrace",
                (scope.scope_type == ScopeType::Hub).then_some(scope.id.as_str()),
                Some(Permission::ViewLogs),
            )
            .await?;
        Ok(Response::new(execution_trace_to_proto(&trace)))
    }

    async fn get_provider_health(
        &self,
        request: Request<v2::GetProviderHealthRequest>,
    ) -> Result<Response<v2::GetProviderHealthResponse>, Status> {
        authenticate_request!(self, request, context, false);
        self.authorizer
            .authorize(
                context,
                "GetProviderHealth",
                None,
                Some(Permission::Administrator),
            )
            .await?;
        let providers = self
            .engine
            .features()
            .health()
            .await
            .into_iter()
            .map(|provider| v2::ProviderHealth {
                name: provider.name,
                version: provider.version,
                healthy: provider.healthy,
                status: provider.status,
                checked_at: Some(timestamp(provider.checked_at)),
            })
            .collect();
        Ok(Response::new(v2::GetProviderHealthResponse { providers }))
    }

    async fn create_nsfw_override(
        &self,
        request: Request<v2::CreateNsfwOverrideRequest>,
    ) -> Result<Response<v2::NsfwOverride>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize(
                context,
                "CreateNsfwOverride",
                None,
                Some(Permission::Administrator),
            )
            .await?;
        let input = request
            .r#override
            .ok_or_else(|| Status::invalid_argument("override is required"))?;
        let created = self
            .nsfw_overrides
            .create(context, &input)
            .await
            .map_err(resource_error)?;
        Ok(Response::new(created))
    }

    async fn get_nsfw_override(
        &self,
        request: Request<v2::GetNsfwOverrideRequest>,
    ) -> Result<Response<v2::NsfwOverride>, Status> {
        authenticate_request!(self, request, context, false);
        self.authorizer
            .authorize(
                context,
                "GetNsfwOverride",
                None,
                Some(Permission::Administrator),
            )
            .await?;
        let value = self
            .nsfw_overrides
            .get(parse_uuid(&request.override_id, "override_id")?)
            .await
            .map_err(not_found_or_internal)?;
        Ok(Response::new(value))
    }

    async fn list_nsfw_overrides(
        &self,
        request: Request<v2::ListNsfwOverridesRequest>,
    ) -> Result<Response<v2::ListNsfwOverridesResponse>, Status> {
        authenticate_request!(self, request, context, false);
        self.authorizer
            .authorize(
                context,
                "ListNsfwOverrides",
                None,
                Some(Permission::Administrator),
            )
            .await?;
        let classification = if request.classification == 0 {
            None
        } else {
            Some(nsfw_classification_name(request.classification).map_err(resource_error)?)
        };
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let result = self
            .nsfw_overrides
            .list(
                classification,
                optional_uuid_cursor(&page.cursor)?,
                i64::from(page.page_size.max(1)),
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::ListNsfwOverridesResponse {
            overrides: result.items,
            page: Some(v2::CursorPageResult {
                next_cursor: result.next_cursor,
            }),
        }))
    }

    async fn update_nsfw_override(
        &self,
        request: Request<v2::UpdateNsfwOverrideRequest>,
    ) -> Result<Response<v2::NsfwOverride>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize(
                context,
                "UpdateNsfwOverride",
                None,
                Some(Permission::Administrator),
            )
            .await?;
        let input = request
            .r#override
            .ok_or_else(|| Status::invalid_argument("override is required"))?;
        let mask = nsfw_override_update_mask(request.update_mask.as_ref())?;
        let updated = self
            .nsfw_overrides
            .update(context, &input, mask, request.expected_version as i64)
            .await
            .map_err(resource_error)?;
        Ok(Response::new(updated))
    }

    async fn delete_nsfw_override(
        &self,
        request: Request<v2::DeleteNsfwOverrideRequest>,
    ) -> Result<Response<()>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize(
                context,
                "DeleteNsfwOverride",
                None,
                Some(Permission::Administrator),
            )
            .await?;
        self.nsfw_overrides
            .delete(
                context,
                parse_uuid(&request.override_id, "override_id")?,
                &request.reason,
                request.expected_version as i64,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(()))
    }

    async fn list_execution_traces(
        &self,
        request: Request<v2::ListExecutionTracesRequest>,
    ) -> Result<Response<v2::ListExecutionTracesResponse>, Status> {
        authenticate_request!(self, request, context, false);
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        self.authorize_scope(
            context,
            "ListExecutionTraces",
            &scope,
            Permission::ViewLogs,
            Permission::ViewLogs,
            Permission::ViewLogs,
        )
        .await?;
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let cursor = optional_uuid_cursor(&page.cursor)?;
        let decision = match v2::Decision::try_from(request.decision).unwrap_or_default() {
            v2::Decision::Allow => Some("ALLOW"),
            v2::Decision::Censor => Some("CENSOR"),
            v2::Decision::Hold => Some("HOLD"),
            v2::Decision::Block => Some("BLOCK"),
            v2::Decision::Unspecified => None,
        };
        let result = self
            .moderation
            .list_execution_traces(
                &scope,
                request.subject.as_ref(),
                decision,
                cursor,
                i64::from(page.page_size.max(1)),
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::ListExecutionTracesResponse {
            traces: result.items.iter().map(execution_trace_to_proto).collect(),
            page: Some(v2::CursorPageResult {
                next_cursor: result.next_cursor,
            }),
        }))
    }
    async fn create_restriction(
        &self,
        request: Request<v2::CreateRestrictionRequest>,
    ) -> Result<Response<v2::Restriction>, Status> {
        authenticate_request!(self, request, context, true);
        let restriction = request
            .restriction
            .ok_or_else(|| Status::invalid_argument("restriction is required"))?;
        let scope = restriction
            .scope
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("restriction scope is required"))?;
        let hub_permission = if v2::RestrictionType::try_from(restriction.r#type)
            .unwrap_or_default()
            == v2::RestrictionType::Ban
        {
            Permission::ManageBans
        } else {
            Permission::ModerateHubMessages
        };
        let staff_operation = if restriction.r#type == v2::RestrictionType::Ban as i32
            && scope.r#type == v2::ScopeType::Product as i32
            && scope.product == v2::Product::Lobby as i32
            && scope.id.is_empty()
        {
            Some((
                StaffOperation::CreateLobbyBan,
                Permission::HandleLobbyReports,
            ))
        } else if restriction.r#type == v2::RestrictionType::Blacklist as i32
            && scope.r#type == v2::ScopeType::Platform as i32
        {
            Some((
                StaffOperation::CreateGlobalBlacklist,
                Permission::ManageGlobalBlacklists,
            ))
        } else {
            None
        };
        if self.staff_authorization_mode != crate::config::StaffAuthorizationMode::Enforce
            || staff_operation.is_none()
        {
            self.authorize_scope(
                context,
                "CreateRestriction",
                scope,
                hub_permission,
                Permission::HandleLobbyReports,
                Permission::ManageGlobalBlacklists,
            )
            .await?;
        }
        if let Some((operation, legacy)) = staff_operation {
            let expiry = restriction.expires_at.map(datetime).transpose()?;
            let duration = expiry.map(|value| (value - Utc::now()).num_seconds().max(0) as u64);
            match self
                .authorize_staff(context, operation, legacy, None, duration, expiry.is_none())
                .await?
            {
                StaffDecision::Allow => {}
                StaffDecision::RequireApproval => {
                    return Err(Status::failed_precondition(
                        "staff action requires approval",
                    ));
                }
                _ => return Err(Status::permission_denied("staff authorization denied")),
            }
        }
        let result = self
            .moderation
            .create_restriction(context, restriction)
            .await
            .map_err(resource_error)?;
        Ok(Response::new(result))
    }
    async fn get_restriction(
        &self,
        request: Request<v2::GetRestrictionRequest>,
    ) -> Result<Response<v2::Restriction>, Status> {
        authenticate_request!(self, request, context, false);
        let restriction = self
            .moderation
            .get_restriction(parse_uuid(&request.restriction_id, "restriction_id")?)
            .await
            .map_err(not_found_or_internal)?;
        let scope = restriction
            .scope
            .as_ref()
            .expect("stored restriction scope");
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "GetRestriction",
                scope,
                Permission::ViewLogs,
                StaffOperation::ViewModerationRecords,
                Permission::ViewLogs,
                None,
            )
            .await?;
        } else if self
            .authorize_staff(
                context,
                StaffOperation::ViewModerationRecords,
                Permission::ViewLogs,
                None,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        Ok(Response::new(restriction))
    }
    async fn update_restriction(
        &self,
        request: Request<v2::UpdateRestrictionRequest>,
    ) -> Result<Response<v2::Restriction>, Status> {
        authenticate_request!(self, request, context, true);
        let restriction = request
            .restriction
            .ok_or_else(|| Status::invalid_argument("restriction is required"))?;
        let id = parse_uuid(&restriction.id, "restriction.id")?;
        let (update_reason, update_expires_at) =
            restriction_update_paths(request.update_mask.as_ref())?;
        let reason = update_reason.then_some(restriction.reason.as_str());
        let expires_at = if update_expires_at {
            Some(restriction.expires_at.map(datetime).transpose()?)
        } else {
            None
        };
        let existing = self
            .moderation
            .get_restriction(id)
            .await
            .map_err(not_found_or_internal)?;
        let scope = existing.scope.as_ref().expect("stored restriction scope");
        let hub_permission = if existing.r#type == v2::RestrictionType::Ban as i32 {
            Permission::ManageBans
        } else {
            Permission::ModerateHubMessages
        };
        if scope.r#type == v2::ScopeType::Hub as i32 {
            let (operation, target_staff_id) = punishment_operation(
                &existing.created_by,
                &context.actor_id,
                StaffOperation::EditOwnPunishment,
                StaffOperation::EditOthersPunishment,
            );
            self.authorize_hub_or_staff(
                context,
                "UpdateRestriction",
                scope,
                hub_permission,
                operation,
                Permission::HandleLobbyReports,
                target_staff_id,
            )
            .await?;
        } else if self.staff_authorization_mode != crate::config::StaffAuthorizationMode::Enforce {
            self.authorize_scope(
                context,
                "UpdateRestriction",
                scope,
                hub_permission,
                Permission::HandleLobbyReports,
                Permission::ManageGlobalBlacklists,
            )
            .await?;
        }
        if matches!(
            v2::ScopeType::try_from(scope.r#type).unwrap_or_default(),
            v2::ScopeType::Product | v2::ScopeType::Platform
        ) {
            let legacy = if scope.r#type == v2::ScopeType::Platform as i32 {
                Permission::ManageGlobalBlacklists
            } else {
                Permission::HandleLobbyReports
            };
            let (operation, target_staff_id) = punishment_operation(
                &existing.created_by,
                &context.actor_id,
                StaffOperation::EditOwnPunishment,
                StaffOperation::EditOthersPunishment,
            );
            if self
                .authorize_staff(context, operation, legacy, target_staff_id, None, false)
                .await?
                != StaffDecision::Allow
            {
                return Err(Status::permission_denied("staff authorization denied"));
            }
            if update_expires_at {
                let policy_operation = if scope.r#type == v2::ScopeType::Platform as i32 {
                    StaffOperation::CreateGlobalBlacklist
                } else {
                    StaffOperation::CreateLobbyBan
                };
                let proposed_expiry = expires_at.flatten();
                let duration =
                    proposed_expiry.map(|value| (value - Utc::now()).num_seconds().max(0) as u64);
                match self
                    .authorize_staff(
                        context,
                        policy_operation,
                        legacy,
                        None,
                        duration,
                        proposed_expiry.is_none(),
                    )
                    .await?
                {
                    StaffDecision::Allow => {}
                    StaffDecision::RequireApproval => {
                        return Err(Status::failed_precondition(
                            "punishment duration change requires approval",
                        ));
                    }
                    _ => return Err(Status::permission_denied("staff authorization denied")),
                }
            }
        }
        let result = self
            .moderation
            .update_restriction(
                context,
                id,
                reason,
                expires_at,
                request.expected_version as i64,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(result))
    }
    async fn revoke_restriction(
        &self,
        request: Request<v2::RevokeRestrictionRequest>,
    ) -> Result<Response<v2::Restriction>, Status> {
        authenticate_request!(self, request, context, true);
        let id = parse_uuid(&request.restriction_id, "restriction_id")?;
        let existing = self
            .moderation
            .get_restriction(id)
            .await
            .map_err(not_found_or_internal)?;
        let scope = existing.scope.as_ref().expect("stored restriction scope");
        let hub_permission = if existing.r#type == v2::RestrictionType::Ban as i32 {
            Permission::ManageBans
        } else {
            Permission::ModerateHubMessages
        };
        if scope.r#type == v2::ScopeType::Hub as i32 {
            let (operation, target_staff_id) = punishment_operation(
                &existing.created_by,
                &context.actor_id,
                StaffOperation::RemoveOwnPunishment,
                StaffOperation::RemoveOthersPunishment,
            );
            self.authorize_hub_or_staff(
                context,
                "RevokeRestriction",
                scope,
                hub_permission,
                operation,
                Permission::HandleLobbyReports,
                target_staff_id,
            )
            .await?;
        } else if self.staff_authorization_mode != crate::config::StaffAuthorizationMode::Enforce {
            self.authorize_scope(
                context,
                "RevokeRestriction",
                scope,
                hub_permission,
                Permission::HandleLobbyReports,
                Permission::ManageGlobalBlacklists,
            )
            .await?;
        }
        if matches!(
            v2::ScopeType::try_from(scope.r#type).unwrap_or_default(),
            v2::ScopeType::Product | v2::ScopeType::Platform
        ) {
            let legacy = if scope.r#type == v2::ScopeType::Platform as i32 {
                Permission::ManageGlobalBlacklists
            } else {
                Permission::HandleLobbyReports
            };
            let (operation, target_staff_id) = punishment_operation(
                &existing.created_by,
                &context.actor_id,
                StaffOperation::RemoveOwnPunishment,
                StaffOperation::RemoveOthersPunishment,
            );
            if self
                .authorize_staff(context, operation, legacy, target_staff_id, None, false)
                .await?
                != StaffDecision::Allow
            {
                return Err(Status::permission_denied("staff authorization denied"));
            }
        }
        let result = self
            .moderation
            .revoke_restriction(
                context,
                id,
                &request.reason,
                request.expected_version as i64,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(result))
    }
    async fn list_restrictions(
        &self,
        request: Request<v2::ListRestrictionsRequest>,
    ) -> Result<Response<v2::ListRestrictionsResponse>, Status> {
        authenticate_request!(self, request, context, false);
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "ListRestrictions",
                &scope,
                Permission::ViewLogs,
                StaffOperation::ViewModerationRecords,
                Permission::ViewLogs,
                None,
            )
            .await?;
        } else if context.actor_type != v2::ActorType::Service as i32
            && self
                .authorize_staff(
                    context,
                    StaffOperation::ViewModerationRecords,
                    Permission::ViewLogs,
                    None,
                    None,
                    false,
                )
                .await?
                != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let result = self
            .moderation
            .list_restrictions(
                &scope,
                request.subject.as_ref(),
                resource_status_filter(request.status)?,
                restriction_type_filter(request.restriction_type)?,
                optional_string_filter(&request.subject_type),
                optional_string_filter(&request.subject_id),
                optional_string_filter(&request.created_by),
                optional_string_filter(&request.query),
                &request.sort,
                &page.cursor,
                i64::from(page.page_size.max(1)),
                request.include_total_count,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::ListRestrictionsResponse {
            restrictions: result.items,
            page: Some(v2::CursorPageResult {
                next_cursor: result.next_cursor,
            }),
            total_count: result.total_count,
        }))
    }
    async fn create_infraction(
        &self,
        request: Request<v2::CreateInfractionRequest>,
    ) -> Result<Response<v2::Infraction>, Status> {
        authenticate_request!(self, request, context, true);
        let infraction = request
            .infraction
            .ok_or_else(|| Status::invalid_argument("infraction is required"))?;
        let scope = infraction
            .scope
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("infraction scope is required"))?;
        let global_permission =
            if request.enforcement.as_ref().is_some_and(|restriction| {
                restriction.r#type == v2::RestrictionType::Blacklist as i32
            }) {
                Permission::ManageGlobalBlacklists
            } else {
                Permission::Administrator
            };
        let expires_at = infraction.expires_at.map(datetime).transpose()?;
        let duration = expires_at.map(|value| (value - Utc::now()).num_seconds().max(0) as u64);
        let permanent = expires_at.is_none();
        let staff_operation = if infraction.r#type == v2::InfractionType::Warning as i32
            && !infraction.source_report_id.is_empty()
        {
            Some((StaffOperation::Warn, Permission::HandleLobbyReports))
        } else if scope.r#type == v2::ScopeType::Hub as i32
            && !infraction.source_report_id.is_empty()
        {
            Some((
                StaffOperation::HandleModerationCase,
                Permission::HandleLobbyReports,
            ))
        } else if infraction.r#type == v2::InfractionType::Ban as i32
            && scope.r#type == v2::ScopeType::Product as i32
            && scope.product == v2::Product::Lobby as i32
            && scope.id.is_empty()
        {
            Some((
                StaffOperation::CreateLobbyBan,
                Permission::HandleLobbyReports,
            ))
        } else if infraction.r#type == v2::InfractionType::Ban as i32
            && scope.r#type == v2::ScopeType::Platform as i32
            && request.enforcement.as_ref().is_some_and(|restriction| {
                restriction.r#type == v2::RestrictionType::Blacklist as i32
            })
        {
            Some((
                StaffOperation::CreateGlobalBlacklist,
                Permission::ManageGlobalBlacklists,
            ))
        } else {
            None
        };
        if scope.r#type == v2::ScopeType::Hub as i32
            && let Some((operation, legacy)) = staff_operation
        {
            self.authorize_hub_or_staff(
                context,
                "CreateInfraction",
                scope,
                Permission::ModerateHubMessages,
                operation,
                legacy,
                None,
            )
            .await?;
        } else if self.staff_authorization_mode != crate::config::StaffAuthorizationMode::Enforce
            || staff_operation.is_none()
        {
            self.authorize_scope_or_service(
                context,
                "CreateInfraction",
                scope,
                Permission::ModerateHubMessages,
                Permission::HandleLobbyReports,
                global_permission,
            )
            .await?;
        }
        if scope.r#type != v2::ScopeType::Hub as i32
            && let Some((operation, legacy)) = staff_operation
        {
            match self
                .authorize_staff(context, operation, legacy, None, duration, permanent)
                .await?
            {
                StaffDecision::Allow => {}
                StaffDecision::RequireApproval => {
                    return Err(Status::failed_precondition(
                        "staff action requires approval",
                    ));
                }
                _ => return Err(Status::permission_denied("staff authorization denied")),
            }
        }
        let result = self
            .moderation
            .create_infraction(context, infraction, request.enforcement)
            .await
            .map_err(resource_error)?;
        self.evaluate_current_safety(result.scope.as_ref(), result.subject.as_ref())
            .await?;
        Ok(Response::new(result))
    }
    async fn get_infraction(
        &self,
        request: Request<v2::GetInfractionRequest>,
    ) -> Result<Response<v2::Infraction>, Status> {
        authenticate_request!(self, request, context, false);
        let infraction = self
            .moderation
            .get_infraction(parse_uuid(&request.infraction_id, "infraction_id")?)
            .await
            .map_err(not_found_or_internal)?;
        let scope = infraction.scope.as_ref().expect("stored infraction scope");
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "GetInfraction",
                scope,
                Permission::ViewLogs,
                StaffOperation::ViewModerationRecords,
                Permission::ViewLogs,
                None,
            )
            .await?;
        } else if self
            .authorize_staff(
                context,
                StaffOperation::ViewModerationRecords,
                Permission::ViewLogs,
                None,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        Ok(Response::new(infraction))
    }
    async fn revoke_infraction(
        &self,
        request: Request<v2::RevokeInfractionRequest>,
    ) -> Result<Response<v2::Infraction>, Status> {
        authenticate_request!(self, request, context, true);
        let id = parse_uuid(&request.infraction_id, "infraction_id")?;
        let existing = self
            .moderation
            .get_infraction(id)
            .await
            .map_err(not_found_or_internal)?;
        let scope = existing.scope.as_ref().expect("stored infraction scope");
        if scope.r#type == v2::ScopeType::Hub as i32 {
            let (operation, target_staff_id) = punishment_operation(
                &existing.created_by,
                &context.actor_id,
                StaffOperation::RemoveOwnPunishment,
                StaffOperation::RemoveOthersPunishment,
            );
            self.authorize_hub_or_staff(
                context,
                "RevokeInfraction",
                scope,
                Permission::ModerateHubMessages,
                operation,
                Permission::HandleLobbyReports,
                target_staff_id,
            )
            .await?;
        } else if self.staff_authorization_mode != crate::config::StaffAuthorizationMode::Enforce {
            self.authorize_scope(
                context,
                "RevokeInfraction",
                scope,
                Permission::ModerateHubMessages,
                Permission::HandleLobbyReports,
                Permission::Administrator,
            )
            .await?;
        }
        if matches!(
            v2::ScopeType::try_from(scope.r#type).unwrap_or_default(),
            v2::ScopeType::Product | v2::ScopeType::Platform
        ) {
            let legacy = if scope.r#type == v2::ScopeType::Platform as i32 {
                Permission::ManageGlobalBlacklists
            } else {
                Permission::HandleLobbyReports
            };
            let (operation, target_staff_id) = punishment_operation(
                &existing.created_by,
                &context.actor_id,
                StaffOperation::RemoveOwnPunishment,
                StaffOperation::RemoveOthersPunishment,
            );
            if self
                .authorize_staff(context, operation, legacy, target_staff_id, None, false)
                .await?
                != StaffDecision::Allow
            {
                return Err(Status::permission_denied("staff authorization denied"));
            }
        }
        let result = self
            .moderation
            .revoke_infraction(
                context,
                id,
                &request.reason,
                request.expected_version as i64,
            )
            .await
            .map_err(resource_error)?;
        self.evaluate_current_safety(result.scope.as_ref(), result.subject.as_ref())
            .await?;
        Ok(Response::new(result))
    }
    async fn revoke_infractions_by_type(
        &self,
        request: Request<v2::RevokeInfractionsByTypeRequest>,
    ) -> Result<Response<v2::RevokeInfractionsByTypeResponse>, Status> {
        authenticate_request!(self, request, context, true);
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        let subject = request
            .subject
            .ok_or_else(|| Status::invalid_argument("subject is required"))?;
        self.authorize_scope(
            context,
            "RevokeInfractionsByType",
            &scope,
            Permission::ModerateHubMessages,
            Permission::HandleLobbyReports,
            Permission::Administrator,
        )
        .await?;
        let (revoked_infractions, revoked_restrictions) = self
            .moderation
            .revoke_infractions_by_type(
                context,
                &scope,
                &subject,
                &infraction_type_name(request.r#type)?,
                &request.reason,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::RevokeInfractionsByTypeResponse {
            revoked_infractions,
            revoked_restrictions,
        }))
    }
    async fn list_infractions(
        &self,
        request: Request<v2::ListInfractionsRequest>,
    ) -> Result<Response<v2::ListInfractionsResponse>, Status> {
        authenticate_request!(self, request, context, false);
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "ListInfractions",
                &scope,
                Permission::ViewLogs,
                StaffOperation::ViewModerationRecords,
                Permission::ViewLogs,
                None,
            )
            .await?;
        } else if self
            .authorize_staff(
                context,
                StaffOperation::ViewModerationRecords,
                Permission::ViewLogs,
                None,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let result = self
            .moderation
            .list_infractions(
                &scope,
                request.subject.as_ref(),
                resource_status_filter(request.status)?,
                optional_uuid_cursor(&page.cursor)?,
                i64::from(page.page_size.max(1)),
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::ListInfractionsResponse {
            infractions: result.items,
            page: Some(v2::CursorPageResult {
                next_cursor: result.next_cursor,
            }),
        }))
    }
    async fn list_my_infractions(
        &self,
        request: Request<v2::ListMyInfractionsRequest>,
    ) -> Result<Response<v2::ListInfractionsResponse>, Status> {
        authenticate_request!(self, request, context, false);
        self.authorizer
            .authorize_user_submission(context, "ListMyInfractions")?;
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let result = self
            .moderation
            .list_user_infractions(
                &context.actor_id,
                resource_status_filter(request.status)?,
                optional_uuid_cursor(&page.cursor)?,
                i64::from(page.page_size.max(1)),
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::ListInfractionsResponse {
            infractions: result.items,
            page: Some(v2::CursorPageResult {
                next_cursor: result.next_cursor,
            }),
        }))
    }
    async fn list_moderation_records(
        &self,
        request: Request<v2::ListModerationRecordsRequest>,
    ) -> Result<Response<v2::ListModerationRecordsResponse>, Status> {
        authenticate_request!(self, request, context, false);
        if context.actor_type == v2::ActorType::Service as i32 {
            self.authorizer
                .authorize(context, "ListModerationRecords", None, None)
                .await?;
        } else if self
            .authorize_staff(
                context,
                StaffOperation::ViewModerationRecords,
                Permission::ViewLogs,
                None,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let result = self
            .moderation
            .list_moderation_records(
                &request.kinds,
                moderation_subject_type_filter(&request.subject_type)?,
                optional_string_filter(&request.subject_id),
                optional_string_filter(&request.created_by),
                optional_string_filter(&request.query),
                resource_status_filter(request.status)?,
                &request.sort,
                &page.cursor,
                i64::from(page.page_size.max(1)),
                request.include_total_count,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::ListModerationRecordsResponse {
            records: result.items,
            page: Some(v2::CursorPageResult {
                next_cursor: result.next_cursor,
            }),
            total_count: result.total_count,
        }))
    }
    async fn link_moderation_record_report(
        &self,
        request: Request<v2::LinkModerationRecordReportRequest>,
    ) -> Result<Response<v2::ModerationRecord>, Status> {
        authenticate_request!(self, request, context, true);
        let resource_type = v2::ModerationResourceType::try_from(request.resource_type)
            .map_err(|_| Status::invalid_argument("invalid moderation resource type"))?;
        if resource_type == v2::ModerationResourceType::Unspecified {
            return Err(Status::invalid_argument(
                "moderation resource type is required",
            ));
        }
        let record_id = parse_uuid(&request.record_id, "record_id")?;
        let report_id = parse_uuid(&request.report_id, "report_id")?;
        let expected_version = i64::try_from(request.expected_version)
            .map_err(|_| Status::invalid_argument("expected_version is out of range"))?;
        let existing = self
            .moderation
            .get_moderation_record(resource_type, record_id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_moderation_record_link(context, &existing)
            .await?;
        let result = self
            .moderation
            .link_moderation_record_report(
                context,
                resource_type,
                record_id,
                report_id,
                expected_version,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(result))
    }
    async fn create_report(
        &self,
        request: Request<v2::CreateReportRequest>,
    ) -> Result<Response<v2::Report>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize_user_submission(context, "CreateReport")?;
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        let subject = request
            .subject
            .ok_or_else(|| Status::invalid_argument("subject is required"))?;
        let report = self
            .moderation
            .create_report(
                context,
                &scope,
                &subject,
                &request.r#type,
                &request.description,
                ReportSubmissionData {
                    context: request
                        .report_context
                        .map(struct_to_json)
                        .unwrap_or_else(|| serde_json::json!({})),
                    terminal_action_id: optional_uuid(
                        &request.terminal_action_id,
                        "terminal_action_id",
                    )?,
                },
            )
            .await
            .map_err(resource_error)?;
        self.evaluate_current_safety(report.scope.as_ref(), report.subject.as_ref())
            .await?;
        Ok(Response::new(report))
    }
    async fn get_report(
        &self,
        request: Request<v2::GetReportRequest>,
    ) -> Result<Response<v2::Report>, Status> {
        authenticate_request!(self, request, context, false);
        let report = self
            .moderation
            .get_report(parse_uuid(&request.report_id, "report_id")?)
            .await
            .map_err(not_found_or_internal)?;
        let scope = report.scope.as_ref().expect("stored report scope");
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "GetReport",
                scope,
                Permission::ViewLogs,
                StaffOperation::ViewModerationCases,
                Permission::HandleLobbyReports,
                None,
            )
            .await?;
        } else if self
            .authorize_staff(
                context,
                StaffOperation::ViewModerationCases,
                Permission::HandleLobbyReports,
                None,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        Ok(Response::new(report))
    }
    async fn list_reports(
        &self,
        request: Request<v2::ListReportsRequest>,
    ) -> Result<Response<v2::ListReportsResponse>, Status> {
        authenticate_request!(self, request, context, false);
        if let Some(scope) = request.scope.as_ref() {
            if scope.r#type == v2::ScopeType::Hub as i32 {
                self.authorize_hub_or_staff(
                    context,
                    "ListReports",
                    scope,
                    Permission::ViewLogs,
                    StaffOperation::ViewModerationCases,
                    Permission::HandleLobbyReports,
                    None,
                )
                .await?;
            } else if self
                .authorize_staff(
                    context,
                    StaffOperation::ViewModerationCases,
                    Permission::HandleLobbyReports,
                    None,
                    None,
                    false,
                )
                .await?
                != StaffDecision::Allow
            {
                return Err(Status::permission_denied("staff authorization denied"));
            }
        } else if self
            .authorize_staff(
                context,
                StaffOperation::ViewModerationCases,
                Permission::Administrator,
                None,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let result = self
            .moderation
            .list_reports(
                request.scope.as_ref(),
                resource_status_filter(request.status)?,
                optional_uuid_cursor(&page.cursor)?,
                i64::from(page.page_size.max(1)),
                if request.query.is_empty() {
                    None
                } else {
                    Some(request.query.as_str())
                },
                if request.reporter_id.is_empty() {
                    None
                } else {
                    Some(request.reporter_id.as_str())
                },
                if request.reported_user_id.is_empty() {
                    None
                } else {
                    Some(request.reported_user_id.as_str())
                },
                if request.reported_server_id.is_empty() {
                    None
                } else {
                    Some(request.reported_server_id.as_str())
                },
                if request.report_type.is_empty() {
                    None
                } else {
                    Some(request.report_type.as_str())
                },
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::ListReportsResponse {
            reports: result.items,
            page: Some(v2::CursorPageResult {
                next_cursor: result.next_cursor,
            }),
        }))
    }
    async fn list_report_transcript(
        &self,
        request: Request<v2::ListReportTranscriptRequest>,
    ) -> Result<Response<v2::ListReportTranscriptResponse>, Status> {
        authenticate_request!(self, request, context, false);
        let report_id = parse_uuid(&request.report_id, "report_id")?;
        let _report = self
            .moderation
            .get_report(report_id)
            .await
            .map_err(not_found_or_internal)?;
        if v2::ActorType::try_from(context.actor_type).unwrap_or_default() == v2::ActorType::Service
        {
            self.authorizer
                .authorize(context, "ListReportTranscript", None, None)
                .await?;
        } else if self
            .authorize_staff(
                context,
                StaffOperation::ViewModerationCases,
                Permission::HandleLobbyReports,
                None,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let cursor = if page.cursor.is_empty() {
            None
        } else {
            Some(
                page.cursor
                    .parse::<i64>()
                    .map_err(|_| Status::invalid_argument("cursor is invalid"))?,
            )
        };
        let evidence = self
            .moderation
            .list_report_evidence(report_id, cursor, i64::from(page.page_size.max(1)))
            .await
            .map_err(not_found_or_internal)?;
        let mut entries = Vec::with_capacity(evidence.action_ids.len());
        for (sequence, action_id) in evidence.action_ids {
            let action = self
                .repository
                .load_persisted_action(action_id)
                .await
                .map_err(internal)?;
            entries.push(transcript_entry_from_action(sequence, &action));
        }
        Ok(Response::new(v2::ListReportTranscriptResponse {
            entries,
            page: Some(v2::CursorPageResult {
                next_cursor: evidence.next_cursor,
            }),
            total_count: evidence.snapshot.entry_count,
            snapshot: Some(evidence.snapshot),
        }))
    }
    async fn resolve_report(
        &self,
        request: Request<v2::ResolveReportRequest>,
    ) -> Result<Response<v2::Report>, Status> {
        authenticate_request!(self, request, context, true);
        let id = parse_uuid(&request.report_id, "report_id")?;
        let existing = self
            .moderation
            .get_report(id)
            .await
            .map_err(not_found_or_internal)?;
        let scope = existing.scope.as_ref().expect("stored report scope");
        let operation = if request.resolution == v2::ResourceStatus::Dismissed as i32 {
            StaffOperation::DismissModerationCase
        } else {
            StaffOperation::CloseModerationCase
        };
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "ResolveReport",
                scope,
                Permission::ModerateHubMessages,
                operation,
                Permission::HandleLobbyReports,
                None,
            )
            .await?;
        } else if self.staff_authorization_mode != crate::config::StaffAuthorizationMode::Enforce {
            self.authorize_scope(
                context,
                "ResolveReport",
                scope,
                Permission::ModerateHubMessages,
                Permission::HandleLobbyReports,
                Permission::Administrator,
            )
            .await?;
        }
        if scope.r#type != v2::ScopeType::Hub as i32
            && self
                .authorize_staff(
                    context,
                    operation,
                    Permission::HandleLobbyReports,
                    None,
                    None,
                    false,
                )
                .await?
                != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        let result = self
            .moderation
            .resolve_report(
                context,
                id,
                resolution_name(request.resolution)?,
                request.expected_version as i64,
            )
            .await
            .map_err(resource_error)?;
        self.evaluate_current_safety(result.scope.as_ref(), result.subject.as_ref())
            .await?;
        Ok(Response::new(result))
    }
    async fn create_appeal(
        &self,
        request: Request<v2::CreateAppealRequest>,
    ) -> Result<Response<v2::Appeal>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize_user_submission(context, "CreateAppeal")?;
        let appeal = self
            .moderation
            .create_appeal(
                context,
                parse_uuid(&request.infraction_id, "infraction_id")?,
                &request.reason,
                request
                    .evidence
                    .map(struct_to_json)
                    .unwrap_or_else(|| serde_json::json!({})),
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(appeal))
    }
    async fn get_appeal(
        &self,
        request: Request<v2::GetAppealRequest>,
    ) -> Result<Response<v2::Appeal>, Status> {
        authenticate_request!(self, request, context, false);
        let id = parse_uuid(&request.appeal_id, "appeal_id")?;
        let appeal = self
            .moderation
            .get_appeal(id)
            .await
            .map_err(not_found_or_internal)?;
        let scope = self
            .moderation
            .appeal_scope(id)
            .await
            .map_err(not_found_or_internal)?;
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "GetAppeal",
                &scope,
                Permission::ViewLogs,
                StaffOperation::HandleAppeal,
                Permission::HandleLobbyReports,
                None,
            )
            .await?;
        } else {
            self.authorize_non_hub_staff_scope(
                context,
                &scope,
                StaffOperation::HandleAppeal,
                Permission::HandleLobbyReports,
                Permission::ViewLogs,
            )
            .await?;
        }
        Ok(Response::new(appeal))
    }
    async fn list_appeals(
        &self,
        request: Request<v2::ListAppealsRequest>,
    ) -> Result<Response<v2::ListAppealsResponse>, Status> {
        authenticate_request!(self, request, context, false);
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "ListAppeals",
                &scope,
                Permission::ViewLogs,
                StaffOperation::HandleAppeal,
                Permission::HandleLobbyReports,
                None,
            )
            .await?;
        } else {
            self.authorize_non_hub_staff_scope(
                context,
                &scope,
                StaffOperation::HandleAppeal,
                Permission::HandleLobbyReports,
                Permission::ViewLogs,
            )
            .await?;
        }
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let result = self
            .moderation
            .list_appeals(
                &scope,
                resource_status_filter(request.status)?,
                optional_uuid_cursor(&page.cursor)?,
                i64::from(page.page_size.max(1)),
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::ListAppealsResponse {
            appeals: result.items,
            page: Some(v2::CursorPageResult {
                next_cursor: result.next_cursor,
            }),
        }))
    }
    async fn resolve_appeal(
        &self,
        request: Request<v2::ResolveAppealRequest>,
    ) -> Result<Response<v2::Appeal>, Status> {
        authenticate_request!(self, request, context, true);
        let id = parse_uuid(&request.appeal_id, "appeal_id")?;
        let scope = self
            .moderation
            .appeal_scope(id)
            .await
            .map_err(not_found_or_internal)?;
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "ResolveAppeal",
                &scope,
                Permission::ModerateHubMessages,
                StaffOperation::HandleAppeal,
                Permission::HandleLobbyReports,
                None,
            )
            .await?;
        } else {
            self.authorize_non_hub_staff_scope(
                context,
                &scope,
                StaffOperation::HandleAppeal,
                Permission::HandleLobbyReports,
                Permission::Administrator,
            )
            .await?;
        }
        let result = self
            .moderation
            .resolve_appeal(
                context,
                id,
                resolution_name(request.resolution)?,
                &request.response,
                request.expected_version as i64,
            )
            .await
            .map_err(resource_error)?;
        if request.resolution == v2::ResourceStatus::Resolved as i32 {
            let infraction = self
                .moderation
                .get_infraction(parse_uuid(&result.infraction_id, "infraction_id")?)
                .await
                .map_err(internal)?;
            self.evaluate_current_safety(infraction.scope.as_ref(), infraction.subject.as_ref())
                .await?;
        }
        Ok(Response::new(result))
    }
    async fn list_review_items(
        &self,
        request: Request<v2::ListReviewItemsRequest>,
    ) -> Result<Response<v2::ListReviewItemsResponse>, Status> {
        authenticate_request!(self, request, context, false);
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "ListReviewItems",
                &scope,
                Permission::ViewLogs,
                StaffOperation::ViewHeldActions,
                Permission::HandleLobbyReports,
                None,
            )
            .await?;
        } else {
            self.authorize_non_hub_staff_scope(
                context,
                &scope,
                StaffOperation::ViewHeldActions,
                Permission::HandleLobbyReports,
                Permission::ViewLogs,
            )
            .await?;
        }
        let page = request.page.unwrap_or(v2::CursorPage {
            page_size: 50,
            cursor: String::new(),
        });
        let result = self
            .moderation
            .list_review_items(
                &scope,
                (!request.queue.is_empty()).then_some(request.queue.as_str()),
                resource_status_filter(request.status)?,
                optional_uuid_cursor(&page.cursor)?,
                i64::from(page.page_size.max(1)),
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(v2::ListReviewItemsResponse {
            items: result.items,
            page: Some(v2::CursorPageResult {
                next_cursor: result.next_cursor,
            }),
        }))
    }
    async fn resolve_review_item(
        &self,
        request: Request<v2::ResolveReviewItemRequest>,
    ) -> Result<Response<v2::ReviewItem>, Status> {
        authenticate_request!(self, request, context, true);
        let id = parse_uuid(&request.review_item_id, "review_item_id")?;
        let existing = self
            .moderation
            .get_review_item(id)
            .await
            .map_err(not_found_or_internal)?;
        self.authorize_scope(
            context,
            "ResolveReviewItem",
            existing.scope.as_ref().expect("stored review scope"),
            Permission::ModerateHubMessages,
            Permission::HandleLobbyReports,
            Permission::Administrator,
        )
        .await?;
        let result = self
            .moderation
            .resolve_review_item(
                context,
                id,
                resolution_name(request.resolution)?,
                request.expected_version as i64,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(result))
    }
    async fn adjudicate_held_action(
        &self,
        request: Request<v2::AdjudicateHeldActionRequest>,
    ) -> Result<Response<v2::HeldAction>, Status> {
        authenticate_request!(self, request, context, true);
        let action_id = match request.target {
            Some(v2::adjudicate_held_action_request::Target::ActionId(value)) => {
                parse_uuid(&value, "action_id")?
            }
            Some(v2::adjudicate_held_action_request::Target::ReviewItemId(value)) => {
                let review_item_id = parse_uuid(&value, "review_item_id")?;
                self.repository
                    .held_action_id_for_review_item(review_item_id)
                    .await
                    .map_err(not_found_or_internal)?
            }
            None => {
                return Err(Status::invalid_argument(
                    "action_id or review_item_id is required",
                ));
            }
        };
        let existing = self
            .repository
            .get_held_action(action_id)
            .await
            .map_err(not_found_or_internal)?;
        let scope = contract_scope_to_proto(&existing.scope);
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "AdjudicateHeldAction",
                &scope,
                Permission::ModerateHubMessages,
                StaffOperation::AdjudicateHeldAction,
                Permission::HandleLobbyReports,
                None,
            )
            .await?;
        } else {
            self.authorize_non_hub_staff_scope(
                context,
                &scope,
                StaffOperation::AdjudicateHeldAction,
                Permission::HandleLobbyReports,
                Permission::Administrator,
            )
            .await?;
        }
        let resolution = match v2::HeldActionResolution::try_from(request.resolution)
            .map_err(|_| Status::invalid_argument("invalid held action resolution"))?
        {
            v2::HeldActionResolution::Approve => HeldActionResolution::Approve,
            v2::HeldActionResolution::Reject => HeldActionResolution::Reject,
            v2::HeldActionResolution::Expire => HeldActionResolution::Expire,
            v2::HeldActionResolution::Unspecified => {
                return Err(Status::invalid_argument(
                    "held action resolution is required",
                ));
            }
        };
        let result = self
            .repository
            .adjudicate_held_action(
                context,
                action_id,
                resolution,
                request.reason.trim(),
                request.expected_version as i64,
            )
            .await
            .map_err(resource_error)?;
        Ok(Response::new(held_action_to_proto(result)?))
    }
    async fn get_safety_assessment(
        &self,
        request: Request<v2::GetSafetyAssessmentRequest>,
    ) -> Result<Response<v2::SafetyAssessment>, Status> {
        authenticate_request!(self, request, context, false);
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        if scope.r#type == v2::ScopeType::Hub as i32 {
            self.authorize_hub_or_staff(
                context,
                "GetSafetyAssessment",
                &scope,
                Permission::ViewLogs,
                StaffOperation::ViewModerationRecords,
                Permission::ViewLogs,
                None,
            )
            .await?;
        } else {
            self.authorize_non_hub_staff_scope(
                context,
                &scope,
                StaffOperation::ViewModerationRecords,
                Permission::HandleLobbyReports,
                Permission::ViewLogs,
            )
            .await?;
        }
        let subject = request
            .subject
            .ok_or_else(|| Status::invalid_argument("subject is required"))?;
        Ok(Response::new(
            self.moderation
                .get_safety_assessment(&scope, &subject)
                .await
                .map_err(not_found_or_internal)?,
        ))
    }
    async fn record_safety_observation(
        &self,
        request: Request<v2::RecordSafetyObservationRequest>,
    ) -> Result<Response<v2::SafetyAssessment>, Status> {
        authenticate_request!(self, request, context, true);
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        let subject = request
            .subject
            .ok_or_else(|| Status::invalid_argument("subject is required"))?;
        let signal = request
            .signal
            .ok_or_else(|| Status::invalid_argument("signal is required"))?;
        self.authorize_scope_or_service(
            context,
            "RecordSafetyObservation",
            &scope,
            Permission::ModerateHubMessages,
            Permission::HandleLobbyReports,
            Permission::Administrator,
        )
        .await?;
        let metadata = signal
            .metadata
            .clone()
            .map(struct_to_json)
            .unwrap_or_else(|| serde_json::json!({}));
        let assessment = self
            .moderation
            .record_safety_observation(context, &scope, &subject, signal, metadata)
            .await
            .map_err(resource_error)?;
        self.evaluate_safety_assessment_update(&assessment).await?;
        Ok(Response::new(assessment))
    }
    async fn recalculate_safety_assessment(
        &self,
        request: Request<v2::RecalculateSafetyAssessmentRequest>,
    ) -> Result<Response<v2::SafetyAssessment>, Status> {
        authenticate_request!(self, request, context, true);
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        let subject = request
            .subject
            .ok_or_else(|| Status::invalid_argument("subject is required"))?;
        self.authorize_scope_or_service(
            context,
            "RecalculateSafetyAssessment",
            &scope,
            Permission::ModerateHubMessages,
            Permission::HandleLobbyReports,
            Permission::Administrator,
        )
        .await?;
        let assessment = self
            .moderation
            .recalculate_safety_assessment(context, &scope, &subject)
            .await
            .map_err(resource_error)?;
        self.evaluate_safety_assessment_update(&assessment).await?;
        Ok(Response::new(assessment))
    }
    async fn get_moderation_statistics(
        &self,
        request: Request<v2::GetModerationStatisticsRequest>,
    ) -> Result<Response<v2::ModerationStatistics>, Status> {
        authenticate_request!(self, request, context, false);
        let scope = request
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        self.authorize_scope(
            context,
            "GetModerationStatistics",
            &scope,
            Permission::ViewLogs,
            Permission::HandleLobbyReports,
            Permission::ViewLogs,
        )
        .await?;
        let from = request
            .from
            .map(datetime)
            .transpose()?
            .ok_or_else(|| Status::invalid_argument("from is required"))?;
        let to = request
            .to
            .map(datetime)
            .transpose()?
            .ok_or_else(|| Status::invalid_argument("to is required"))?;
        Ok(Response::new(
            self.moderation
                .moderation_statistics(&scope, from, to)
                .await
                .map_err(resource_error)?,
        ))
    }

    async fn get_staff_action_request(
        &self,
        request: Request<v2::GetStaffActionRequestRequest>,
    ) -> Result<Response<v2::StaffActionRequest>, Status> {
        authenticate_request!(self, request, context, false);
        self.authorizer
            .authorize_user_submission(context, "GetStaffActionRequest")?;
        let decision = self
            .authorize_staff(
                context,
                StaffOperation::ViewHeldActions,
                Permission::HandleLobbyReports,
                None,
                None,
                false,
            )
            .await?;
        if decision != StaffDecision::Allow {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        Ok(Response::new(
            self.moderation
                .get_staff_action_request(parse_uuid(
                    &request.action_request_id,
                    "action_request_id",
                )?)
                .await
                .map_err(not_found_or_internal)?,
        ))
    }

    async fn list_staff_action_requests(
        &self,
        request: Request<v2::ListStaffActionRequestsRequest>,
    ) -> Result<Response<v2::ListStaffActionRequestsResponse>, Status> {
        authenticate_request!(self, request, context, false);
        self.authorizer
            .authorize_user_submission(context, "ListStaffActionRequests")?;
        let decision = self
            .authorize_staff(
                context,
                StaffOperation::ViewHeldActions,
                Permission::HandleLobbyReports,
                None,
                None,
                false,
            )
            .await?;
        if decision != StaffDecision::Allow {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        let status = v2::StaffActionRequestStatus::try_from(request.status)
            .unwrap_or(v2::StaffActionRequestStatus::Unspecified);
        let status = match status {
            v2::StaffActionRequestStatus::Unspecified => None,
            other => Some(
                other
                    .as_str_name()
                    .trim_start_matches("STAFF_ACTION_REQUEST_STATUS_"),
            ),
        };
        let requested_by =
            (!request.requested_by.is_empty()).then_some(request.requested_by.as_str());
        let items = self
            .moderation
            .list_staff_action_requests(status, requested_by, 100)
            .await
            .map_err(internal)?;
        Ok(Response::new(v2::ListStaffActionRequestsResponse {
            requests: items,
            page: Some(v2::CursorPageResult {
                next_cursor: String::new(),
            }),
        }))
    }

    async fn claim_report(
        &self,
        request: Request<v2::ClaimReportRequest>,
    ) -> Result<Response<v2::Report>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize_user_submission(context, "ClaimReport")?;
        let mut bypass = false;
        let decision = self
            .authorize_staff(
                context,
                StaffOperation::ClaimModerationCase,
                Permission::HandleLobbyReports,
                None,
                None,
                false,
            )
            .await?;
        if decision != StaffDecision::Allow {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        if !request.bypass_reason.trim().is_empty() {
            bypass = self
                .authorize_staff(
                    context,
                    StaffOperation::BypassClaimCooldown,
                    Permission::Administrator,
                    None,
                    None,
                    false,
                )
                .await?
                == StaffDecision::Allow;
        }
        Ok(Response::new(
            self.moderation
                .claim_report(
                    context,
                    parse_uuid(&request.report_id, "report_id")?,
                    request.expected_version as i64,
                    self.staff_case_claim_lease_seconds,
                    self.staff_case_transfer_cooldown_seconds,
                    bypass,
                )
                .await
                .map_err(resource_error)?,
        ))
    }

    async fn renew_report_claim(
        &self,
        request: Request<v2::RenewReportClaimRequest>,
    ) -> Result<Response<v2::Report>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize_user_submission(context, "RenewReportClaim")?;
        for operation in [
            StaffOperation::ViewModerationCases,
            StaffOperation::HandleModerationCase,
        ] {
            if self
                .authorize_staff(
                    context,
                    operation,
                    Permission::HandleLobbyReports,
                    None,
                    None,
                    false,
                )
                .await?
                != StaffDecision::Allow
            {
                return Err(Status::permission_denied("staff authorization denied"));
            }
        }
        Ok(Response::new(
            self.moderation
                .renew_report_claim(
                    context,
                    parse_uuid(&request.report_id, "report_id")?,
                    request.expected_version as i64,
                    self.staff_case_claim_lease_seconds,
                )
                .await
                .map_err(resource_error)?,
        ))
    }

    async fn unclaim_report(
        &self,
        request: Request<v2::UnclaimReportRequest>,
    ) -> Result<Response<v2::Report>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize_user_submission(context, "UnclaimReport")?;
        if self
            .authorize_staff(
                context,
                StaffOperation::UnclaimModerationCase,
                Permission::HandleLobbyReports,
                None,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        Ok(Response::new(
            self.moderation
                .unclaim_report(
                    context,
                    parse_uuid(&request.report_id, "report_id")?,
                    request.expected_version as i64,
                )
                .await
                .map_err(resource_error)?,
        ))
    }

    async fn assign_report(
        &self,
        request: Request<v2::AssignReportRequest>,
    ) -> Result<Response<v2::Report>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize_user_submission(context, "AssignReport")?;
        if self
            .authorize_staff(
                context,
                StaffOperation::AssignModerationCase,
                Permission::Administrator,
                Some(&request.assignee_id),
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        Ok(Response::new(
            self.moderation
                .transfer_report(
                    context,
                    parse_uuid(&request.report_id, "report_id")?,
                    &request.assignee_id,
                    request.expected_version as i64,
                    self.staff_case_claim_lease_seconds,
                    self.staff_case_transfer_cooldown_seconds,
                    true,
                    false,
                )
                .await
                .map_err(resource_error)?,
        ))
    }

    async fn transfer_report(
        &self,
        request: Request<v2::TransferReportRequest>,
    ) -> Result<Response<v2::Report>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize_user_submission(context, "TransferReport")?;
        if request.reason.trim().is_empty() {
            return Err(Status::invalid_argument("transfer reason is required"));
        }
        if self
            .authorize_staff(
                context,
                StaffOperation::TransferModerationCase,
                Permission::Administrator,
                Some(&request.assignee_id),
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        let bypass_cooldown = if request.bypass_reason.trim().is_empty() {
            false
        } else {
            self.authorize_staff(
                context,
                StaffOperation::BypassClaimCooldown,
                Permission::Administrator,
                None,
                None,
                false,
            )
            .await?
                == StaffDecision::Allow
        };
        Ok(Response::new(
            self.moderation
                .transfer_report(
                    context,
                    parse_uuid(&request.report_id, "report_id")?,
                    &request.assignee_id,
                    request.expected_version as i64,
                    self.staff_case_claim_lease_seconds,
                    self.staff_case_transfer_cooldown_seconds,
                    false,
                    bypass_cooldown,
                )
                .await
                .map_err(resource_error)?,
        ))
    }

    async fn create_staff_action_request(
        &self,
        request: Request<v2::CreateStaffActionRequestRequest>,
    ) -> Result<Response<v2::StaffActionRequest>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize_user_submission(context, "CreateStaffActionRequest")?;
        let action_type = v2::StaffActionType::try_from(request.action_type)
            .map_err(|_| Status::invalid_argument("invalid action type"))?;
        let subject = request
            .subject
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("subject is required"))?;
        let scope = request
            .scope
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        let (operation, legacy, name) = match action_type {
            v2::StaffActionType::LobbyBan => (
                StaffOperation::CreateLobbyBan,
                Permission::HandleLobbyReports,
                "LOBBY_BAN",
            ),
            v2::StaffActionType::GlobalBlacklist => (
                StaffOperation::CreateGlobalBlacklist,
                Permission::ManageGlobalBlacklists,
                "GLOBAL_BLACKLIST",
            ),
            v2::StaffActionType::Unspecified => {
                return Err(Status::invalid_argument("action type is required"));
            }
        };
        let expiry = request.requested_expires_at.map(datetime).transpose()?;
        let duration = expiry.map(|value| (value - Utc::now()).num_seconds().max(0) as u64);
        let permanent = expiry.is_none();
        if self
            .authorize_staff(context, operation, legacy, None, duration, permanent)
            .await?
            != StaffDecision::RequireApproval
        {
            return Err(Status::failed_precondition(
                "this action does not require approval",
            ));
        }
        let (subject_type, subject_id) = if !subject.user_id.is_empty() {
            ("USER", subject.user_id.as_str())
        } else if !subject.server_id.is_empty() {
            ("SERVER", subject.server_id.as_str())
        } else {
            return Err(Status::invalid_argument(
                "user or server subject is required",
            ));
        };
        let report_id = if request.report_id.is_empty() {
            None
        } else {
            Some(parse_uuid(&request.report_id, "report_id")?)
        };
        Ok(Response::new(
            self.moderation
                .create_staff_action_request(
                    context,
                    name,
                    subject_type,
                    subject_id,
                    staff_scope_name(scope.r#type)?,
                    &scope.id,
                    report_id,
                    request.reason.trim(),
                    expiry,
                )
                .await
                .map_err(resource_error)?,
        ))
    }

    async fn resolve_staff_action_request(
        &self,
        request: Request<v2::ResolveStaffActionRequestRequest>,
    ) -> Result<Response<v2::StaffActionRequest>, Status> {
        authenticate_request!(self, request, context, true);
        self.authorizer
            .authorize_user_submission(context, "ResolveStaffActionRequest")?;
        let existing = self
            .moderation
            .get_staff_action_request(parse_uuid(&request.action_request_id, "action_request_id")?)
            .await
            .map_err(not_found_or_internal)?;
        let operation = match v2::StaffActionType::try_from(existing.action_type)
            .unwrap_or(v2::StaffActionType::Unspecified)
        {
            v2::StaffActionType::LobbyBan => StaffOperation::ApproveLobbyBan,
            v2::StaffActionType::GlobalBlacklist => StaffOperation::ApproveGlobalBlacklist,
            v2::StaffActionType::Unspecified => {
                return Err(Status::invalid_argument("invalid stored action type"));
            }
        };
        if self
            .authorize_staff(
                context,
                StaffOperation::AdjudicateHeldAction,
                Permission::Administrator,
                None,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        if self
            .authorize_staff(
                context,
                operation,
                Permission::Administrator,
                None,
                None,
                false,
            )
            .await?
            != StaffDecision::Allow
        {
            return Err(Status::permission_denied("staff authorization denied"));
        }
        Ok(Response::new(
            self.moderation
                .resolve_staff_action_request(
                    context,
                    parse_uuid(&request.action_request_id, "action_request_id")?,
                    request.approve,
                    request.reason.trim(),
                    request.expected_version as i64,
                )
                .await
                .map_err(resource_error)?,
        ))
    }
}

fn staff_scope_name(value: i32) -> Result<&'static str, Status> {
    match v2::ScopeType::try_from(value)
        .map_err(|_| Status::invalid_argument("invalid scope type"))?
    {
        v2::ScopeType::Platform => Ok("PLATFORM"),
        v2::ScopeType::Product => Ok("PRODUCT"),
        v2::ScopeType::Hub => Ok("HUB"),
        v2::ScopeType::Lobby => Ok("LOBBY"),
        v2::ScopeType::IncidentOverlay => Ok("INCIDENT_OVERLAY"),
        v2::ScopeType::Unspecified => Err(Status::invalid_argument("scope type is required")),
    }
}

fn validate_context<'a>(
    context: Option<&'a v2::RequestContext>,
    mutation: bool,
    authenticated_principal: &str,
) -> Result<&'a v2::RequestContext, Status> {
    let context = context.ok_or_else(|| Status::unauthenticated("request context is required"))?;
    if context.request_id.is_empty() || context.actor_id.is_empty() {
        return Err(Status::unauthenticated(
            "request_id and actor_id are required",
        ));
    }
    if context.service_principal != authenticated_principal {
        return Err(Status::unauthenticated(
            "service principal does not match the authenticated client certificate",
        ));
    }
    if mutation && context.idempotency_key.is_empty() {
        return Err(Status::invalid_argument(
            "idempotency_key is required for mutations",
        ));
    }
    Ok(context)
}

#[cfg(test)]
mod authentication_tests {
    use super::*;

    fn context(principal: &str, idempotency_key: &str) -> v2::RequestContext {
        v2::RequestContext {
            request_id: Uuid::now_v7().to_string(),
            actor_id: "actor-1".to_owned(),
            actor_type: v2::ActorType::Human as i32,
            service_principal: principal.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            trace_id: String::new(),
        }
    }

    #[test]
    fn request_context_must_match_authenticated_certificate_principal() {
        let request_context = context("winter", "");
        let status = validate_context(Some(&request_context), false, "interchat-bot")
            .expect_err("mismatched principal must fail");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn mutation_requires_idempotency_after_identity_validation() {
        let request_context = context("interchat-bot", "");
        let status = validate_context(Some(&request_context), true, "interchat-bot")
            .expect_err("mutation without idempotency must fail");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn restriction_update_mask_accepts_only_mutable_fields() {
        let mask = prost_types::FieldMask {
            paths: vec!["reason".to_owned(), "expires_at".to_owned()],
        };

        assert_eq!(restriction_update_paths(Some(&mask)).unwrap(), (true, true));

        let immutable = prost_types::FieldMask {
            paths: vec!["scope".to_owned()],
        };
        let status = restriction_update_paths(Some(&immutable))
            .expect_err("immutable fields must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn restriction_update_requires_a_field_mask() {
        let empty = prost_types::FieldMask { paths: Vec::new() };
        assert_eq!(
            restriction_update_paths(None).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            restriction_update_paths(Some(&empty)).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn nsfw_override_update_mask_accepts_only_mutable_fields() {
        let mask = prost_types::FieldMask {
            paths: vec!["classification".to_owned(), "reason".to_owned()],
        };
        let parsed = nsfw_override_update_mask(Some(&mask)).expect("mutable fields");
        assert!(parsed.classification);
        assert!(parsed.reason);
        assert!(!parsed.exact_sha256);

        let immutable = prost_types::FieldMask {
            paths: vec!["created_by".to_owned()],
        };
        assert_eq!(
            nsfw_override_update_mask(Some(&immutable))
                .expect_err("server fields are immutable")
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn repository_version_conflicts_are_aborted() {
        let status = resource_error(anyhow::anyhow!("restriction version conflict"));
        assert_eq!(status.code(), tonic::Code::Aborted);
    }

    #[test]
    fn moderation_record_subject_filter_accepts_known_subject_types_only() {
        assert_eq!(moderation_subject_type_filter("").unwrap(), None);
        assert_eq!(
            moderation_subject_type_filter("USER").unwrap(),
            Some("USER")
        );
        assert_eq!(
            moderation_subject_type_filter("MESSAGE").unwrap(),
            Some("MESSAGE")
        );
        assert_eq!(
            moderation_subject_type_filter("CHANNEL")
                .expect_err("unsupported subject types must be rejected")
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn policy_bundle_update_mask_rejects_immutable_fields() {
        let mutable = prost_types::FieldMask {
            paths: vec!["name".into(), "priority".into()],
        };
        let parsed = policy_bundle_update_paths(Some(&mutable)).expect("mutable fields");
        assert!(parsed.name && parsed.priority);
        assert!(!parsed.description && !parsed.mandatory);

        let immutable = prost_types::FieldMask {
            paths: vec!["scope".into()],
        };
        assert_eq!(
            policy_bundle_update_paths(Some(&immutable))
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn policy_bundle_scope_requires_matching_typed_product() {
        let hub = policy_scope_from_proto(v2::Scope {
            r#type: v2::ScopeType::Hub as i32,
            id: "hub-1".into(),
            product: v2::Product::Hub as i32,
        })
        .expect("valid hub scope");
        assert_eq!(hub.product, Some(Product::Hub));

        let invalid = policy_scope_from_proto(v2::Scope {
            r#type: v2::ScopeType::Lobby as i32,
            id: "lobby-1".into(),
            product: v2::Product::Hub as i32,
        });
        assert_eq!(invalid.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn held_action_response_preserves_state_version_and_review_ids() {
        let action_id = Uuid::now_v7();
        let review_id = Uuid::now_v7();
        let response = held_action_to_proto(HeldActionRecord {
            action_id,
            decision_id: Uuid::now_v7(),
            scope: Scope {
                scope_type: ScopeType::Hub,
                id: "hub-1".into(),
                product: Some(Product::Hub),
            },
            state: "BLOCKED".into(),
            hold_until: None,
            version: 2,
            resolved_by: Some("moderator-1".into()),
            resolution_reason: Some("confirmed violation".into()),
            resolved_review_item_ids: vec![review_id],
        })
        .expect("valid held action");
        assert_eq!(response.action_id, action_id.to_string());
        assert_eq!(response.state, v2::MessageState::Blocked as i32);
        assert_eq!(response.version, 2);
        assert_eq!(response.resolved_review_item_ids, [review_id.to_string()]);
    }
}

pub(crate) fn action_from_proto(action: v2::Action) -> Result<Action, Status> {
    let scope = action
        .scope
        .ok_or_else(|| Status::invalid_argument("action.scope is required"))?;
    let scope_type = match v2::ScopeType::try_from(scope.r#type)
        .map_err(|_| Status::invalid_argument("invalid scope type"))?
    {
        v2::ScopeType::Platform => ScopeType::Platform,
        v2::ScopeType::Product => ScopeType::Product,
        v2::ScopeType::Hub => ScopeType::Hub,
        v2::ScopeType::Lobby => ScopeType::Lobby,
        v2::ScopeType::IncidentOverlay => ScopeType::IncidentOverlay,
        v2::ScopeType::Unspecified => {
            return Err(Status::invalid_argument("scope type is required"));
        }
    };
    let product = match v2::Product::try_from(scope.product).unwrap_or(v2::Product::Unspecified) {
        v2::Product::Hub => Some(Product::Hub),
        v2::Product::Lobby => Some(Product::Lobby),
        v2::Product::Unspecified => None,
    };
    let subject = action.subject.unwrap_or_default();
    let occurred_at = action
        .occurred_at
        .map(datetime)
        .transpose()?
        .unwrap_or_else(Utc::now);
    let data_handling = match v2::DataHandlingClass::try_from(action.data_handling)
        .unwrap_or(v2::DataHandlingClass::Unspecified)
    {
        v2::DataHandlingClass::Public => DataHandlingClass::Public,
        v2::DataHandlingClass::Internal => DataHandlingClass::Internal,
        v2::DataHandlingClass::Sensitive => DataHandlingClass::Sensitive,
        v2::DataHandlingClass::Restricted => DataHandlingClass::Restricted,
        v2::DataHandlingClass::Unspecified => {
            return Err(Status::invalid_argument("data handling class is required"));
        }
    };
    Ok(Action {
        id: parse_uuid(&action.id, "action.id")?,
        action_type: action.r#type,
        schema_version: action.schema_version,
        scope: Scope {
            scope_type,
            id: scope.id,
            product,
        },
        subject: Subject {
            user_id: nonempty(subject.user_id),
            server_id: nonempty(subject.server_id),
            message_id: nonempty(subject.message_id),
            channel_id: nonempty(subject.channel_id),
            report_id: nonempty(subject.report_id),
        },
        occurred_at,
        attributes: action
            .attributes
            .map(struct_to_json)
            .unwrap_or_else(|| serde_json::json!({})),
        data_handling,
        prism_payload: None,
    })
}

fn decision_to_proto(result: &crate::policy::model::EvaluationResult) -> v2::PolicyDecision {
    let decision = match result.decision {
        crate::policy::model::Decision::Allow => v2::Decision::Allow,
        crate::policy::model::Decision::Censor => v2::Decision::Censor,
        crate::policy::model::Decision::Hold => v2::Decision::Hold,
        crate::policy::model::Decision::Block => v2::Decision::Block,
    };
    v2::PolicyDecision {
        id: result.id.to_string(),
        action_id: result.action_id.to_string(),
        decision: decision as i32,
        reason_codes: result.reason_codes.clone(),
        accepted_effects: result
            .accepted_effects
            .iter()
            .map(contract_effect_to_proto)
            .collect(),
        rejected_effects: result
            .rejected_effects
            .iter()
            .map(|rejected| v2::RejectedEffect {
                effect: Some(contract_effect_to_proto(&rejected.effect)),
                reason: rejected.reason.clone(),
                superseded_by_effect_id: rejected.superseded_by.clone().unwrap_or_default(),
            })
            .collect(),
        execution_trace_id: result.trace.id.to_string(),
        decided_at: Some(timestamp(Utc::now())),
        shadow: result.shadow,
    }
}

fn bundle_to_proto(bundle: &crate::policy::model::PolicyBundle) -> v2::PolicyBundle {
    v2::PolicyBundle {
        id: bundle.id.to_string(),
        name: bundle.name.clone(),
        description: bundle.description.clone(),
        scope: Some(v2::Scope {
            r#type: match bundle.scope.scope_type {
                ScopeType::Platform => v2::ScopeType::Platform,
                ScopeType::Product => v2::ScopeType::Product,
                ScopeType::Hub => v2::ScopeType::Hub,
                ScopeType::Lobby => v2::ScopeType::Lobby,
                ScopeType::IncidentOverlay => v2::ScopeType::IncidentOverlay,
            } as i32,
            id: bundle.scope.id.clone(),
            product: match bundle.scope.product {
                Some(Product::Hub) => v2::Product::Hub,
                Some(Product::Lobby) => v2::Product::Lobby,
                None => v2::Product::Unspecified,
            } as i32,
        }),
        mandatory: bundle.mandatory,
        priority: bundle.priority,
        active_version_id: bundle
            .active_version_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        shadow_version_id: bundle
            .shadow_version_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        version: bundle.version as u64,
        created_at: Some(timestamp(bundle.created_at)),
        updated_at: Some(timestamp(bundle.updated_at)),
        state: match bundle.state {
            crate::policy::model::PolicyBundleState::Active => v2::PolicyBundleState::Active,
            crate::policy::model::PolicyBundleState::Disabled => v2::PolicyBundleState::Disabled,
            crate::policy::model::PolicyBundleState::Retired => v2::PolicyBundleState::Retired,
        } as i32,
    }
}

fn struct_to_json(value: prost_types::Struct) -> serde_json::Value {
    serde_json::Value::Object(
        value
            .fields
            .into_iter()
            .map(|(key, value)| (key, value_to_json(value)))
            .collect(),
    )
}

fn value_to_json(value: prost_types::Value) -> serde_json::Value {
    match value.kind {
        Some(prost_types::value::Kind::NullValue(_)) | None => serde_json::Value::Null,
        Some(prost_types::value::Kind::NumberValue(value)) => serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Some(prost_types::value::Kind::StringValue(value)) => serde_json::Value::String(value),
        Some(prost_types::value::Kind::BoolValue(value)) => serde_json::Value::Bool(value),
        Some(prost_types::value::Kind::StructValue(value)) => struct_to_json(value),
        Some(prost_types::value::Kind::ListValue(value)) => {
            serde_json::Value::Array(value.values.into_iter().map(value_to_json).collect())
        }
    }
}

fn json_to_struct(value: &serde_json::Value) -> prost_types::Struct {
    let fields = value
        .as_object()
        .map(|object| {
            object
                .iter()
                .map(|(key, value)| (key.clone(), json_to_value(value)))
                .collect()
        })
        .unwrap_or_default();
    prost_types::Struct { fields }
}

fn json_to_value(value: &serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(value) => Kind::BoolValue(*value),
        serde_json::Value::Number(value) => Kind::NumberValue(value.as_f64().unwrap_or_default()),
        serde_json::Value::String(value) => Kind::StringValue(value.clone()),
        serde_json::Value::Array(values) => Kind::ListValue(prost_types::ListValue {
            values: values.iter().map(json_to_value).collect(),
        }),
        serde_json::Value::Object(_) => Kind::StructValue(json_to_struct(value)),
    };
    prost_types::Value { kind: Some(kind) }
}

fn language_from_proto(language: i32) -> Result<PolicyLanguage, Status> {
    match v2::PolicyLanguage::try_from(language)
        .map_err(|_| Status::invalid_argument("invalid policy language"))?
    {
        v2::PolicyLanguage::IrV1 => Ok(PolicyLanguage::PolicyIrV1),
        v2::PolicyLanguage::LuauV1 => Ok(PolicyLanguage::LuauV1),
        v2::PolicyLanguage::Unspecified => {
            Err(Status::invalid_argument("policy language is required"))
        }
    }
}

fn manifest_from_proto(manifest: v2::PolicyManifest) -> Result<PolicyManifest, Status> {
    let required_features = manifest
        .required_features
        .into_iter()
        .map(|requirement| {
            Ok(crate::policy::model::FeatureRequirement {
                name: requirement.name,
                error_behavior: error_behavior_from_proto(requirement.error_behavior)?,
                deadline_ms: requirement
                    .deadline
                    .map(duration_to_millis)
                    .transpose()?
                    .unwrap_or(25),
                maximum_data_handling: data_handling_from_proto(requirement.maximum_data_handling)?,
                configuration: requirement
                    .configuration
                    .map(struct_to_json)
                    .unwrap_or_else(|| serde_json::json!({})),
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    Ok(PolicyManifest {
        accepted_action_types: manifest.accepted_action_types.into_iter().collect(),
        accepted_schema_versions: manifest.accepted_schema_versions.into_iter().collect(),
        required_features,
        capabilities: manifest.capabilities.into_iter().collect(),
        runtime_error_behavior: error_behavior_from_proto(manifest.runtime_error_behavior)?,
    })
}

fn error_behavior_from_proto(value: i32) -> Result<ErrorBehavior, Status> {
    match v2::ErrorBehavior::try_from(value)
        .map_err(|_| Status::invalid_argument("invalid error behavior"))?
    {
        v2::ErrorBehavior::Hold => Ok(ErrorBehavior::Hold),
        v2::ErrorBehavior::Review => Ok(ErrorBehavior::Review),
        v2::ErrorBehavior::Continue => Ok(ErrorBehavior::Continue),
        v2::ErrorBehavior::Unspecified => {
            Err(Status::invalid_argument("error behavior is required"))
        }
    }
}

fn data_handling_from_proto(value: i32) -> Result<DataHandlingClass, Status> {
    match v2::DataHandlingClass::try_from(value)
        .map_err(|_| Status::invalid_argument("invalid data handling class"))?
    {
        v2::DataHandlingClass::Public => Ok(DataHandlingClass::Public),
        v2::DataHandlingClass::Internal => Ok(DataHandlingClass::Internal),
        v2::DataHandlingClass::Sensitive => Ok(DataHandlingClass::Sensitive),
        v2::DataHandlingClass::Restricted => Ok(DataHandlingClass::Restricted),
        v2::DataHandlingClass::Unspecified => Err(Status::invalid_argument(
            "maximum data handling class is required",
        )),
    }
}

fn policy_version_to_proto(version: &crate::policy::model::PolicyVersion) -> v2::PolicyVersion {
    v2::PolicyVersion {
        id: version.id.to_string(),
        bundle_id: version.bundle_id.to_string(),
        version: version.version as u32,
        language: match version.language {
            PolicyLanguage::PolicyIrV1 => v2::PolicyLanguage::IrV1,
            PolicyLanguage::LuauV1 => v2::PolicyLanguage::LuauV1,
        } as i32,
        runtime_version: version.runtime_version.clone(),
        source: version.source.clone(),
        compiled_artifact: version.compiled_artifact.clone(),
        source_sha256: version.source_sha256.clone(),
        artifact_sha256: version.artifact_sha256.clone(),
        manifest: Some(manifest_to_proto(&version.manifest)),
        state: match version.state {
            PolicyState::Draft => v2::PolicyVersionState::Draft,
            PolicyState::Validated => v2::PolicyVersionState::Validated,
            PolicyState::Shadow => v2::PolicyVersionState::Shadow,
            PolicyState::Active => v2::PolicyVersionState::Active,
            PolicyState::Disabled => v2::PolicyVersionState::Disabled,
            PolicyState::Retired => v2::PolicyVersionState::Retired,
        } as i32,
        created_by: String::new(),
        created_at: None,
        published_at: None,
    }
}

fn stored_fixture_from_proto(
    fixture: v2::PolicyFixture,
) -> Result<(Uuid, String, Action, FeatureSnapshot, Vec<Effect>), Status> {
    let policy_version_id = parse_uuid(&fixture.policy_version_id, "policy_version_id")?;
    let name = fixture.name.trim().to_owned();
    if name.is_empty() {
        return Err(Status::invalid_argument("fixture name is required"));
    }
    let action = action_from_proto(
        fixture
            .action
            .ok_or_else(|| Status::invalid_argument("fixture action is required"))?,
    )?;
    let features = feature_snapshot_from_proto(fixture.features.unwrap_or_default())?;
    let expected_effects = fixture
        .expected_effects
        .into_iter()
        .map(effect_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((policy_version_id, name, action, features, expected_effects))
}

fn stored_fixture_to_proto(
    fixture: &crate::policy::repository::StoredFixture,
) -> v2::PolicyFixture {
    v2::PolicyFixture {
        id: fixture.id.to_string(),
        policy_version_id: fixture.policy_version_id.to_string(),
        name: fixture.name.clone(),
        action: Some(action_to_proto(&fixture.action)),
        features: Some(feature_snapshot_to_proto(&fixture.features)),
        expected_effects: fixture
            .expected_effects
            .iter()
            .map(contract_fixture_effect_to_proto)
            .collect(),
        created_at: Some(timestamp(fixture.created_at)),
        version: fixture.version as u64,
        updated_at: Some(timestamp(fixture.updated_at)),
    }
}

fn action_to_proto(action: &Action) -> v2::Action {
    v2::Action {
        id: action.id.to_string(),
        r#type: action.action_type.clone(),
        schema_version: action.schema_version,
        scope: Some(contract_scope_to_proto(&action.scope)),
        subject: Some(contract_subject_to_proto(&action.subject)),
        occurred_at: Some(timestamp(action.occurred_at)),
        attributes: Some(json_to_struct(&action.attributes)),
        data_handling: data_handling_to_proto(action.data_handling) as i32,
    }
}

fn manifest_to_proto(manifest: &PolicyManifest) -> v2::PolicyManifest {
    v2::PolicyManifest {
        accepted_action_types: manifest.accepted_action_types.iter().cloned().collect(),
        accepted_schema_versions: manifest.accepted_schema_versions.iter().copied().collect(),
        required_features: manifest
            .required_features
            .iter()
            .map(|requirement| v2::FeatureRequirement {
                name: requirement.name.clone(),
                error_behavior: error_behavior_to_proto(requirement.error_behavior) as i32,
                deadline: Some(duration_from_millis(requirement.deadline_ms)),
                maximum_data_handling: data_handling_to_proto(requirement.maximum_data_handling)
                    as i32,
                configuration: Some(json_to_struct(&requirement.configuration)),
            })
            .collect(),
        capabilities: manifest.capabilities.iter().cloned().collect(),
        runtime_error_behavior: error_behavior_to_proto(manifest.runtime_error_behavior) as i32,
    }
}

fn error_behavior_to_proto(value: ErrorBehavior) -> v2::ErrorBehavior {
    match value {
        ErrorBehavior::Hold => v2::ErrorBehavior::Hold,
        ErrorBehavior::Review => v2::ErrorBehavior::Review,
        ErrorBehavior::Continue => v2::ErrorBehavior::Continue,
    }
}

fn data_handling_to_proto(value: DataHandlingClass) -> v2::DataHandlingClass {
    match value {
        DataHandlingClass::Public => v2::DataHandlingClass::Public,
        DataHandlingClass::Internal => v2::DataHandlingClass::Internal,
        DataHandlingClass::Sensitive => v2::DataHandlingClass::Sensitive,
        DataHandlingClass::Restricted => v2::DataHandlingClass::Restricted,
    }
}

fn held_action_to_proto(record: HeldActionRecord) -> Result<v2::HeldAction, Status> {
    let state = match record.state.as_str() {
        "PENDING_MODERATION" => v2::MessageState::PendingModeration,
        "APPROVED_PENDING_DELIVERY" => v2::MessageState::ApprovedPendingDelivery,
        "ACTIVE" => v2::MessageState::Active,
        "BLOCKED" => v2::MessageState::Blocked,
        "HELD" => v2::MessageState::Held,
        "EXPIRED" => v2::MessageState::Expired,
        "DELIVERY_FAILED" => v2::MessageState::DeliveryFailed,
        _ => return Err(Status::internal("stored held action has an invalid state")),
    };
    Ok(v2::HeldAction {
        action_id: record.action_id.to_string(),
        decision_id: record.decision_id.to_string(),
        scope: Some(contract_scope_to_proto(&record.scope)),
        state: state as i32,
        hold_until: record.hold_until.map(timestamp),
        version: record.version as u64,
        resolved_by: record.resolved_by.unwrap_or_default(),
        resolution_reason: record.resolution_reason.unwrap_or_default(),
        resolved_review_item_ids: record
            .resolved_review_item_ids
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
    })
}

fn diagnostic_to_proto(diagnostic: &RuntimeDiagnostic) -> v2::Diagnostic {
    v2::Diagnostic {
        severity: match diagnostic.severity {
            DiagnosticSeverity::Info => v2::DiagnosticSeverity::Info,
            DiagnosticSeverity::Warning => v2::DiagnosticSeverity::Warning,
            DiagnosticSeverity::Error => v2::DiagnosticSeverity::Error,
        } as i32,
        code: diagnostic.code.clone(),
        message: diagnostic.message.clone(),
        line: diagnostic.line.unwrap_or_default(),
        column: diagnostic.column.unwrap_or_default(),
    }
}

fn duration_to_millis(value: prost_types::Duration) -> Result<u64, Status> {
    if value.seconds < 0 || value.nanos < 0 {
        return Err(Status::invalid_argument("duration cannot be negative"));
    }
    Ok((value.seconds as u64)
        .saturating_mul(1_000)
        .saturating_add(value.nanos as u64 / 1_000_000))
}

fn duration_from_millis(value: u64) -> prost_types::Duration {
    prost_types::Duration {
        seconds: (value / 1_000).min(i64::MAX as u64) as i64,
        nanos: ((value % 1_000) * 1_000_000) as i32,
    }
}

fn duration_from_micros(value: u64) -> prost_types::Duration {
    prost_types::Duration {
        seconds: (value / 1_000_000).min(i64::MAX as u64) as i64,
        nanos: ((value % 1_000_000) * 1_000) as i32,
    }
}

fn feature_snapshot_from_proto(snapshot: v2::FeatureSnapshot) -> Result<FeatureSnapshot, Status> {
    snapshot
        .values
        .into_iter()
        .map(|feature| {
            if feature.name.is_empty() {
                return Err(Status::invalid_argument("feature name is required"));
            }
            let error = feature.error.map(|failure| {
                let code = v2::FeatureErrorCode::try_from(failure.code)
                    .unwrap_or(v2::FeatureErrorCode::Internal)
                    .as_str_name()
                    .trim_start_matches("FEATURE_ERROR_CODE_")
                    .to_owned();
                FeatureFailure {
                    code,
                    safe_message: failure.safe_message,
                    retryable: failure.retryable,
                }
            });
            let name = feature.name.clone();
            Ok((
                name,
                FeatureValue {
                    provider: feature.name,
                    provider_version: feature.provider_version,
                    value: feature.value.map(value_to_json),
                    error,
                    latency_micros: feature
                        .latency
                        .map(duration_to_micros)
                        .transpose()?
                        .unwrap_or_default(),
                    cache_hit: feature.cache_hit,
                    input_hash: nonempty(feature.input_hash),
                },
            ))
        })
        .collect()
}

fn feature_snapshot_to_proto(snapshot: &FeatureSnapshot) -> v2::FeatureSnapshot {
    v2::FeatureSnapshot {
        values: snapshot
            .iter()
            .map(|(name, feature)| v2::FeatureValue {
                name: name.clone(),
                provider_version: feature.provider_version.clone(),
                value: feature.value.as_ref().map(json_to_value),
                error: feature.error.as_ref().map(|error| v2::FeatureError {
                    code: feature_error_code_to_proto(&error.code) as i32,
                    safe_message: error.safe_message.clone(),
                    retryable: error.retryable,
                }),
                latency: Some(duration_from_micros(feature.latency_micros)),
                cache_hit: feature.cache_hit,
                input_hash: feature.input_hash.clone().unwrap_or_default(),
            })
            .collect(),
    }
}

fn feature_error_code_to_proto(code: &str) -> v2::FeatureErrorCode {
    match code {
        "UNAVAILABLE" => v2::FeatureErrorCode::Unavailable,
        "TIMEOUT" => v2::FeatureErrorCode::Timeout,
        "RATE_LIMITED" => v2::FeatureErrorCode::RateLimited,
        "INVALID_INPUT" => v2::FeatureErrorCode::InvalidInput,
        "PROVIDER_REJECTED" => v2::FeatureErrorCode::ProviderRejected,
        _ => v2::FeatureErrorCode::Internal,
    }
}

fn duration_to_micros(value: prost_types::Duration) -> Result<u64, Status> {
    if value.seconds < 0 || value.nanos < 0 {
        return Err(Status::invalid_argument("duration cannot be negative"));
    }
    Ok((value.seconds as u64)
        .saturating_mul(1_000_000)
        .saturating_add(value.nanos as u64 / 1_000))
}

fn subject_from_proto(subject: Option<v2::Subject>) -> Subject {
    let subject = subject.unwrap_or_default();
    Subject {
        user_id: nonempty(subject.user_id),
        server_id: nonempty(subject.server_id),
        message_id: nonempty(subject.message_id),
        channel_id: nonempty(subject.channel_id),
        report_id: nonempty(subject.report_id),
    }
}

fn scope_from_proto(scope: Option<v2::Scope>) -> Result<Scope, Status> {
    let scope = scope.ok_or_else(|| Status::invalid_argument("scope is required"))?;
    let scope_type = match v2::ScopeType::try_from(scope.r#type)
        .map_err(|_| Status::invalid_argument("invalid scope type"))?
    {
        v2::ScopeType::Platform => ScopeType::Platform,
        v2::ScopeType::Product => ScopeType::Product,
        v2::ScopeType::Hub => ScopeType::Hub,
        v2::ScopeType::Lobby => ScopeType::Lobby,
        v2::ScopeType::IncidentOverlay => ScopeType::IncidentOverlay,
        v2::ScopeType::Unspecified => {
            return Err(Status::invalid_argument("scope type is required"));
        }
    };
    let product = match v2::Product::try_from(scope.product).unwrap_or_default() {
        v2::Product::Hub => Some(Product::Hub),
        v2::Product::Lobby => Some(Product::Lobby),
        v2::Product::Unspecified => None,
    };
    Ok(Scope {
        scope_type,
        id: scope.id,
        product,
    })
}

fn effect_from_proto(effect: v2::PolicyEffect) -> Result<Effect, Status> {
    use v2::policy_effect::Effect as ProtoEffect;
    let effect_id = if effect.id.is_empty() {
        Uuid::now_v7().to_string()
    } else {
        effect.id
    };
    match effect
        .effect
        .ok_or_else(|| Status::invalid_argument("policy effect body is required"))?
    {
        ProtoEffect::Allow(value) => Ok(Effect::Allow {
            effect_id,
            reason_codes: value.reason_codes,
        }),
        ProtoEffect::Block(value) => Ok(Effect::Block {
            effect_id,
            reason_codes: value.reason_codes,
            public_reason: nonempty(value.public_reason),
            active_restriction: None,
        }),
        ProtoEffect::Hold(value) => Ok(Effect::Hold {
            effect_id,
            reason_codes: value.reason_codes,
            maximum_duration_ms: value.maximum_duration.map(duration_to_millis).transpose()?,
        }),
        ProtoEffect::Censor(value) => Ok(Effect::Censor {
            effect_id,
            spans: value
                .spans
                .into_iter()
                .map(|span| TextSpan {
                    start_character: span.start_character,
                    end_character: span.end_character,
                })
                .collect(),
            replacement: value.replacement,
            reason_codes: value.reason_codes,
        }),
        ProtoEffect::Flag(value) => Ok(Effect::Flag {
            effect_id,
            flag_type: value.flag_type,
            severity: value.severity,
            evidence: value
                .evidence
                .map(struct_to_json)
                .unwrap_or_else(|| serde_json::json!({})),
        }),
        ProtoEffect::Notify(value) => Ok(Effect::Notify {
            effect_id,
            recipient: value.recipient,
            template: value.template,
            parameters: value
                .parameters
                .map(struct_to_json)
                .unwrap_or_else(|| serde_json::json!({})),
        }),
        ProtoEffect::CreateInfraction(value) => Ok(Effect::CreateInfraction {
            effect_id,
            subject: subject_from_proto(value.subject),
            infraction_type: infraction_type_name(value.r#type)?,
            reason: value.reason,
            duration_ms: value.duration.map(duration_to_millis).transpose()?,
            enforcement: value
                .enforcement
                .map(|enforcement| {
                    Ok::<_, Status>(crate::policy::model::Enforcement {
                        subject: subject_from_proto(enforcement.subject),
                        restriction_type: restriction_type_name(enforcement.r#type)?,
                        reason: enforcement.reason,
                        duration_ms: enforcement.duration.map(duration_to_millis).transpose()?,
                    })
                })
                .transpose()?,
        }),
        ProtoEffect::CreateRestriction(value) => Ok(Effect::CreateRestriction {
            effect_id,
            subject: subject_from_proto(value.subject),
            restriction_type: restriction_type_name(value.r#type)?,
            reason: value.reason,
            duration_ms: value.duration.map(duration_to_millis).transpose()?,
        }),
        ProtoEffect::RouteReview(value) => Ok(Effect::RouteReview {
            effect_id,
            queue: value.queue,
            priority: value.priority,
            reason_codes: value.reason_codes,
        }),
        ProtoEffect::LabelEntity(value) => Ok(Effect::LabelEntity {
            effect_id,
            subject: subject_from_proto(value.subject),
            label: value.label,
            value: value
                .value
                .map(value_to_json)
                .unwrap_or(serde_json::Value::Null),
        }),
        ProtoEffect::IncrementCounter(value) => Ok(Effect::IncrementCounter {
            effect_id,
            subject: subject_from_proto(value.subject),
            scope: scope_from_proto(value.scope)?,
            counter_type: value.counter_type,
            delta: value.delta,
            window_ms: value
                .window
                .map(duration_to_millis)
                .transpose()?
                .unwrap_or_default(),
            reset: value.reset,
        }),
        ProtoEffect::Delete(value) => Ok(Effect::Delete {
            effect_id,
            message_id: value.message_id,
            channel_id: value.channel_id,
            reason_codes: value.reason_codes,
        }),
        ProtoEffect::Kick(value) => Ok(Effect::Kick {
            effect_id,
            user_id: value.user_id,
            server_id: value.server_id,
            reason_codes: value.reason_codes,
        }),
    }
}

fn infraction_type_name(value: i32) -> Result<String, Status> {
    match v2::InfractionType::try_from(value)
        .map_err(|_| Status::invalid_argument("invalid infraction type"))?
    {
        v2::InfractionType::Warning => Ok("WARNING".into()),
        v2::InfractionType::Mute => Ok("MUTE".into()),
        v2::InfractionType::Ban => Ok("BAN".into()),
        v2::InfractionType::Content => Ok("CONTENT".into()),
        v2::InfractionType::Unspecified => {
            Err(Status::invalid_argument("infraction type is required"))
        }
    }
}

fn restriction_type_name(value: i32) -> Result<String, Status> {
    match v2::RestrictionType::try_from(value)
        .map_err(|_| Status::invalid_argument("invalid restriction type"))?
    {
        v2::RestrictionType::Mute => Ok("MUTE".into()),
        v2::RestrictionType::Ban => Ok("BAN".into()),
        v2::RestrictionType::Blacklist => Ok("BLACKLIST".into()),
        v2::RestrictionType::ContentQuarantine => Ok("CONTENT_QUARANTINE".into()),
        v2::RestrictionType::Unspecified => {
            Err(Status::invalid_argument("restriction type is required"))
        }
    }
}

fn compare_effects(expected: &[Effect], actual: &[Effect]) -> (bool, Vec<String>) {
    let expected = expected
        .iter()
        .map(|effect| (effect.id(), effect))
        .collect::<BTreeMap<_, _>>();
    let actual = actual
        .iter()
        .map(|effect| (effect.id(), effect))
        .collect::<BTreeMap<_, _>>();
    let mut differences = Vec::new();
    for (id, effect) in &expected {
        match actual.get(id) {
            None => differences.push(format!("missing expected effect {id}")),
            Some(actual) if *actual != *effect => {
                differences.push(format!("effect {id} differs from expected"));
            }
            Some(_) => {}
        }
    }
    for id in actual.keys() {
        if !expected.contains_key(id) {
            differences.push(format!("unexpected effect {id}"));
        }
    }
    (differences.is_empty(), differences)
}

fn fixture_results_from_json(value: serde_json::Value) -> Result<Vec<v2::FixtureResult>, Status> {
    let values = value
        .as_array()
        .ok_or_else(|| Status::internal("stored policy test result is invalid"))?;
    values
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| Status::internal("stored policy fixture result is invalid"))?;
            let fixture_id = object
                .get("fixture_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Status::internal("stored policy fixture id is invalid"))?;
            let passed = object
                .get("passed")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| Status::internal("stored policy fixture outcome is invalid"))?;
            let differences = object
                .get("differences")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| Status::internal("stored policy fixture differences are invalid"))?
                .iter()
                .map(|difference| {
                    difference.as_str().map(str::to_owned).ok_or_else(|| {
                        Status::internal("stored policy fixture difference is invalid")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(v2::FixtureResult {
                fixture_id: fixture_id.to_owned(),
                passed,
                differences,
                trace: None,
            })
        })
        .collect()
}

fn execution_trace_to_proto(trace: &crate::policy::model::ExecutionTrace) -> v2::ExecutionTrace {
    v2::ExecutionTrace {
        id: trace.id.to_string(),
        action_id: trace.action_id.to_string(),
        action_schema_version: trace.action_schema_version,
        rules: trace
            .rules
            .iter()
            .map(|rule| v2::RuleTrace {
                policy_version_id: rule.policy_version_id.to_string(),
                rule_id: rule.rule_id.clone(),
                skipped: rule.skipped,
                skip_reason: rule.skip_reason.clone().unwrap_or_default(),
                conditions: rule
                    .conditions
                    .iter()
                    .map(|condition| v2::ConditionTrace {
                        path: condition.path.clone(),
                        result: Some(json_to_value(&condition.result)),
                    })
                    .collect(),
                emitted_effects: rule
                    .emitted_effects
                    .iter()
                    .map(contract_effect_to_proto)
                    .collect(),
                rejected_effects: trace
                    .rejected_effects
                    .iter()
                    .filter(|effect| effect.effect.origin.rule_id == rule.rule_id)
                    .map(|rejected| v2::RejectedEffect {
                        effect: Some(contract_effect_to_proto(&rejected.effect)),
                        reason: rejected.reason.clone(),
                        superseded_by_effect_id: rejected.superseded_by.clone().unwrap_or_default(),
                    })
                    .collect(),
                error: rule.error.clone().unwrap_or_default(),
                latency: Some(duration_from_micros(rule.latency_micros)),
            })
            .collect(),
        feature_snapshot: Some(feature_snapshot_to_proto(&trace.features)),
        final_decision: match trace.final_decision {
            crate::policy::model::Decision::Allow => v2::Decision::Allow,
            crate::policy::model::Decision::Censor => v2::Decision::Censor,
            crate::policy::model::Decision::Hold => v2::Decision::Hold,
            crate::policy::model::Decision::Block => v2::Decision::Block,
        } as i32,
        reason_codes: trace.reason_codes.clone(),
        total_latency: Some(duration_from_micros(trace.total_latency_micros)),
        created_at: Some(timestamp(trace.created_at)),
        sampled: trace.sampled,
    }
}

async fn ensure_required_providers_healthy(
    engine: &PolicyEngine,
    version: &crate::policy::model::PolicyVersion,
) -> Result<(), Status> {
    let issues = engine.provider_activation_issues(version).await;
    if issues.is_empty() {
        Ok(())
    } else {
        Err(Status::failed_precondition(format!(
            "required providers are not healthy: {}",
            issues.join(", ")
        )))
    }
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(value).map_err(|_| Status::invalid_argument(format!("{field} must be a UUID")))
}
fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}
fn datetime(value: prost_types::Timestamp) -> Result<chrono::DateTime<Utc>, Status> {
    Utc.timestamp_opt(value.seconds, value.nanos as u32)
        .single()
        .ok_or_else(|| Status::invalid_argument("timestamp is out of range"))
}
fn timestamp(value: chrono::DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: value.timestamp(),
        nanos: value.timestamp_subsec_nanos() as i32,
    }
}

fn policy_scope_from_proto(scope: v2::Scope) -> Result<Scope, Status> {
    let scope_type = match v2::ScopeType::try_from(scope.r#type)
        .map_err(|_| Status::invalid_argument("invalid scope type"))?
    {
        v2::ScopeType::Platform => ScopeType::Platform,
        v2::ScopeType::Product => ScopeType::Product,
        v2::ScopeType::Hub => ScopeType::Hub,
        v2::ScopeType::Lobby => ScopeType::Lobby,
        v2::ScopeType::IncidentOverlay => ScopeType::IncidentOverlay,
        v2::ScopeType::Unspecified => {
            return Err(Status::invalid_argument("scope type is required"));
        }
    };
    let product = match v2::Product::try_from(scope.product)
        .map_err(|_| Status::invalid_argument("invalid product"))?
    {
        v2::Product::Hub => Some(Product::Hub),
        v2::Product::Lobby => Some(Product::Lobby),
        v2::Product::Unspecified => None,
    };
    let result = Scope {
        scope_type,
        id: scope.id,
        product,
    };
    let valid = match result.scope_type {
        ScopeType::Platform => result.id.is_empty() && result.product.is_none(),
        ScopeType::Product => result.id.is_empty() && result.product.is_some(),
        ScopeType::Hub => !result.id.trim().is_empty() && result.product == Some(Product::Hub),
        ScopeType::Lobby => !result.id.trim().is_empty() && result.product == Some(Product::Lobby),
        ScopeType::IncidentOverlay => !result.id.trim().is_empty(),
    };
    if !valid {
        return Err(Status::invalid_argument(
            "scope id and product do not match the scope type",
        ));
    }
    Ok(result)
}

fn policy_bundle_state_from_proto(
    value: i32,
) -> Result<Option<crate::policy::model::PolicyBundleState>, Status> {
    Ok(
        match v2::PolicyBundleState::try_from(value)
            .map_err(|_| Status::invalid_argument("invalid policy bundle state"))?
        {
            v2::PolicyBundleState::Active => Some(crate::policy::model::PolicyBundleState::Active),
            v2::PolicyBundleState::Disabled => {
                Some(crate::policy::model::PolicyBundleState::Disabled)
            }
            v2::PolicyBundleState::Retired => {
                Some(crate::policy::model::PolicyBundleState::Retired)
            }
            v2::PolicyBundleState::Unspecified => None,
        },
    )
}

#[derive(Debug, Default)]
struct PolicyBundleUpdatePaths {
    name: bool,
    description: bool,
    mandatory: bool,
    priority: bool,
}

fn policy_bundle_update_paths(
    update_mask: Option<&prost_types::FieldMask>,
) -> Result<PolicyBundleUpdatePaths, Status> {
    let paths = update_mask
        .map(|mask| mask.paths.as_slice())
        .filter(|paths| !paths.is_empty())
        .ok_or_else(|| Status::invalid_argument("update_mask is required"))?;
    let mut result = PolicyBundleUpdatePaths::default();
    for path in paths {
        match path.as_str() {
            "name" => result.name = true,
            "description" => result.description = true,
            "mandatory" => result.mandatory = true,
            "priority" => result.priority = true,
            _ => {
                return Err(Status::invalid_argument(format!(
                    "unsupported policy bundle update path: {path}"
                )));
            }
        }
    }
    Ok(result)
}
fn restriction_update_paths(
    update_mask: Option<&prost_types::FieldMask>,
) -> Result<(bool, bool), Status> {
    let paths = update_mask
        .map(|mask| mask.paths.as_slice())
        .filter(|paths| !paths.is_empty())
        .ok_or_else(|| Status::invalid_argument("update_mask is required"))?;
    let mut update_reason = false;
    let mut update_expires_at = false;
    for path in paths {
        match path.as_str() {
            "reason" => update_reason = true,
            "expires_at" => update_expires_at = true,
            _ => {
                return Err(Status::invalid_argument(format!(
                    "unsupported restriction update path: {path}"
                )));
            }
        }
    }
    Ok((update_reason, update_expires_at))
}

fn nsfw_override_update_mask(
    update_mask: Option<&prost_types::FieldMask>,
) -> Result<NsfwOverrideUpdateMask, Status> {
    let paths = update_mask
        .map(|mask| mask.paths.as_slice())
        .filter(|paths| !paths.is_empty())
        .ok_or_else(|| Status::invalid_argument("update_mask is required"))?;
    let mut result = NsfwOverrideUpdateMask {
        exact_sha256: false,
        perceptual_hash: false,
        classification: false,
        reason: false,
    };
    for path in paths {
        match path.as_str() {
            "exact_sha256" => result.exact_sha256 = true,
            "perceptual_hash" => result.perceptual_hash = true,
            "classification" => result.classification = true,
            "reason" => result.reason = true,
            _ => {
                return Err(Status::invalid_argument(format!(
                    "unsupported NSFW override update path: {path}"
                )));
            }
        }
    }
    Ok(result)
}
fn internal(error: anyhow::Error) -> Status {
    tracing::error!(error = %error, "request failed");
    Status::internal("internal service error")
}
fn command_error(error: CommandRepositoryError) -> Status {
    match error {
        CommandRepositoryError::NotFound => Status::not_found("command not found"),
        CommandRepositoryError::LeaseMismatch | CommandRepositoryError::VersionMismatch => {
            Status::aborted("command claim no longer owns the active lease")
        }
        CommandRepositoryError::RecoveryRequired => {
            Status::failed_precondition("command requires operator recovery")
        }
        CommandRepositoryError::ConflictingCompletion => {
            Status::already_exists("command already has a different durable outcome")
        }
        CommandRepositoryError::CorruptCommand | CommandRepositoryError::Database(_) => {
            tracing::error!(error = %error, "command repository request failed");
            Status::internal("internal service error")
        }
    }
}

fn command_result_to_proto(
    command: &v2::CommandEnvelope,
    outcome: &CommandOutcome,
) -> v2::CommandResult {
    let command_type = match command.command.as_ref() {
        Some(v2::command_envelope::Command::Notify(_)) => "NOTIFY",
        Some(v2::command_envelope::Command::Delete(_)) => "DELETE",
        Some(v2::command_envelope::Command::Kick(_)) => "KICK",
        Some(v2::command_envelope::Command::ModerationNotice(_)) => "MODERATION_NOTICE",
        None => "UNSPECIFIED",
    };
    v2::CommandResult {
        command_id: command.id.clone(),
        decision_id: command.decision_id.clone(),
        idempotency_key: command.idempotency_key.clone(),
        success: outcome.success,
        result_code: outcome.result_code.clone(),
        occurred_at: Some(timestamp(outcome.occurred_at)),
        command_type: command_type.to_owned(),
    }
}

fn completion_result_to_proto(
    command_id: Uuid,
    completion: &CommandCompletion,
) -> v2::CommandResult {
    v2::CommandResult {
        command_id: command_id.to_string(),
        decision_id: completion
            .decision_id
            .map(|value| value.to_string())
            .unwrap_or_default(),
        idempotency_key: completion.idempotency_key.clone(),
        success: completion.outcome.success,
        result_code: completion.outcome.result_code.clone(),
        occurred_at: Some(timestamp(completion.outcome.occurred_at)),
        command_type: completion.command_type.clone(),
    }
}

fn content_policy_scope_from_proto(scope: v2::ContentPolicyScope) -> Result<PolicyScope, Status> {
    let authority = match v2::ContentPolicyAuthority::try_from(scope.authority)
        .map_err(|_| Status::invalid_argument("invalid content policy authority"))?
    {
        v2::ContentPolicyAuthority::Global => ContentAuthority::Global,
        v2::ContentPolicyAuthority::Hub => ContentAuthority::Hub,
        v2::ContentPolicyAuthority::Server => ContentAuthority::Server,
        v2::ContentPolicyAuthority::Unspecified => {
            return Err(Status::invalid_argument(
                "content policy authority is required",
            ));
        }
    };
    let scope = PolicyScope {
        authority,
        id: scope.id,
    };
    scope.validate().map_err(Status::invalid_argument)?;
    Ok(scope)
}

fn content_policy_from_proto(
    policy: v2::NativeContentPolicy,
    actor_id: &str,
) -> Result<ContentPolicy, Status> {
    let scope = content_policy_scope_from_proto(
        policy
            .scope
            .ok_or_else(|| Status::invalid_argument("policy scope is required"))?,
    )?;
    Ok(ContentPolicy {
        id: parse_uuid(&policy.id, "policy.id")?,
        scope,
        enabled: policy.enabled,
        version: policy.version,
        rules: policy
            .rules
            .into_iter()
            .map(|rule| content_rule_from_proto(rule, actor_id))
            .collect::<Result<_, _>>()?,
    })
}

fn content_rule_from_proto(
    rule: v2::NativeContentRule,
    actor_id: &str,
) -> Result<PolicyRule, Status> {
    let surfaces = rule
        .surfaces
        .into_iter()
        .map(content_surface_from_proto)
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(PolicyRule {
        id: parse_uuid(&rule.id, "rule.id")?,
        name: rule.name,
        description: rule.description,
        enabled: rule.enabled,
        custom_reason: (!rule.custom_reason.trim().is_empty()).then_some(rule.custom_reason),
        created_by: if rule.created_by.trim().is_empty() {
            actor_id.to_owned()
        } else {
            rule.created_by
        },
        patterns: rule
            .patterns
            .into_iter()
            .map(|pattern| {
                Ok(RulePattern {
                    id: parse_uuid(&pattern.id, "pattern.id")?,
                    pattern: pattern.pattern,
                    // The repository validates and atomically reclassifies authored syntax.
                    pattern_type: WildcardPatternType::ExactWord,
                })
            })
            .collect::<Result<_, Status>>()?,
        surfaces,
        actions: rule
            .actions
            .into_iter()
            .map(content_action_from_proto)
            .collect::<Result<_, _>>()?,
    })
}

fn content_action_from_proto(action: v2::NativeContentAction) -> Result<PolicyAction, Status> {
    let action_type = match v2::ContentPolicyActionType::try_from(action.r#type)
        .map_err(|_| Status::invalid_argument("invalid content policy action"))?
    {
        v2::ContentPolicyActionType::Allow => PolicyActionType::Allow,
        v2::ContentPolicyActionType::Block => PolicyActionType::Block,
        v2::ContentPolicyActionType::CensorMatch => PolicyActionType::CensorMatch,
        v2::ContentPolicyActionType::StripLink => PolicyActionType::StripLink,
        v2::ContentPolicyActionType::SuppressLinks => PolicyActionType::SuppressLinks,
        v2::ContentPolicyActionType::ReplaceName => PolicyActionType::ReplaceName,
        v2::ContentPolicyActionType::Log => PolicyActionType::Log,
        v2::ContentPolicyActionType::LobbyWarn => PolicyActionType::LobbyWarn,
        v2::ContentPolicyActionType::LobbyBan => PolicyActionType::LobbyBan,
        v2::ContentPolicyActionType::Blacklist => PolicyActionType::Blacklist,
        v2::ContentPolicyActionType::HubWarn => PolicyActionType::HubWarn,
        v2::ContentPolicyActionType::HubMute => PolicyActionType::HubMute,
        v2::ContentPolicyActionType::HubBan => PolicyActionType::HubBan,
        v2::ContentPolicyActionType::Unspecified => {
            return Err(Status::invalid_argument(
                "content policy action is required",
            ));
        }
    };
    let duration_seconds = action
        .duration
        .map(|duration| {
            if duration.seconds <= 0 || duration.nanos != 0 {
                return Err(Status::invalid_argument(
                    "content policy action duration must be positive whole seconds",
                ));
            }
            u64::try_from(duration.seconds)
                .map_err(|_| Status::invalid_argument("action duration is out of range"))
        })
        .transpose()?;
    Ok(PolicyAction {
        id: parse_uuid(&action.id, "action.id")?,
        action_type,
        duration_seconds,
        replacement: (!action.replacement.trim().is_empty()).then_some(action.replacement),
    })
}

fn content_surface_from_proto(value: i32) -> Result<ContentSurface, Status> {
    match v2::ContentPolicySurface::try_from(value)
        .map_err(|_| Status::invalid_argument("invalid content policy surface"))?
    {
        v2::ContentPolicySurface::MessageContent => Ok(ContentSurface::MessageContent),
        v2::ContentPolicySurface::DisplayName => Ok(ContentSurface::DisplayName),
        v2::ContentPolicySurface::Username => Ok(ContentSurface::Username),
        v2::ContentPolicySurface::ServerName => Ok(ContentSurface::ServerName),
        v2::ContentPolicySurface::HubName => Ok(ContentSurface::HubName),
        v2::ContentPolicySurface::UrlDomain => Ok(ContentSurface::UrlDomain),
        v2::ContentPolicySurface::Unspecified => Err(Status::invalid_argument(
            "content policy surface is required",
        )),
    }
}

fn content_policy_to_proto(policy: &ContentPolicy) -> v2::NativeContentPolicy {
    v2::NativeContentPolicy {
        id: policy.id.to_string(),
        scope: Some(v2::ContentPolicyScope {
            authority: match policy.scope.authority {
                ContentAuthority::Global => v2::ContentPolicyAuthority::Global,
                ContentAuthority::Hub => v2::ContentPolicyAuthority::Hub,
                ContentAuthority::Server => v2::ContentPolicyAuthority::Server,
            } as i32,
            id: policy.scope.id.clone(),
        }),
        enabled: policy.enabled,
        version: policy.version,
        rules: policy.rules.iter().map(content_rule_to_proto).collect(),
    }
}

fn content_rule_to_proto(rule: &PolicyRule) -> v2::NativeContentRule {
    v2::NativeContentRule {
        id: rule.id.to_string(),
        name: rule.name.clone(),
        description: rule.description.clone(),
        enabled: rule.enabled,
        custom_reason: rule.custom_reason.clone().unwrap_or_default(),
        created_by: rule.created_by.clone(),
        patterns: rule
            .patterns
            .iter()
            .map(|pattern| v2::NativeContentPattern {
                id: pattern.id.to_string(),
                pattern: pattern.pattern.clone(),
                pattern_type: match pattern.pattern_type {
                    WildcardPatternType::ExactWord => v2::ContentPatternType::ExactWord,
                    WildcardPatternType::Prefix => v2::ContentPatternType::Prefix,
                    WildcardPatternType::Suffix => v2::ContentPatternType::Suffix,
                    WildcardPatternType::Contains => v2::ContentPatternType::Contains,
                    WildcardPatternType::Phrase => v2::ContentPatternType::Phrase,
                } as i32,
            })
            .collect(),
        surfaces: rule
            .surfaces
            .iter()
            .map(|surface| match surface {
                ContentSurface::MessageContent => v2::ContentPolicySurface::MessageContent,
                ContentSurface::DisplayName => v2::ContentPolicySurface::DisplayName,
                ContentSurface::Username => v2::ContentPolicySurface::Username,
                ContentSurface::ServerName => v2::ContentPolicySurface::ServerName,
                ContentSurface::HubName => v2::ContentPolicySurface::HubName,
                ContentSurface::UrlDomain => v2::ContentPolicySurface::UrlDomain,
            } as i32)
            .collect(),
        actions: rule
            .actions
            .iter()
            .map(|action| v2::NativeContentAction {
                id: action.id.to_string(),
                r#type: match action.action_type {
                    PolicyActionType::Allow => v2::ContentPolicyActionType::Allow,
                    PolicyActionType::Block => v2::ContentPolicyActionType::Block,
                    PolicyActionType::CensorMatch => v2::ContentPolicyActionType::CensorMatch,
                    PolicyActionType::StripLink => v2::ContentPolicyActionType::StripLink,
                    PolicyActionType::SuppressLinks => v2::ContentPolicyActionType::SuppressLinks,
                    PolicyActionType::ReplaceName => v2::ContentPolicyActionType::ReplaceName,
                    PolicyActionType::Log => v2::ContentPolicyActionType::Log,
                    PolicyActionType::LobbyWarn => v2::ContentPolicyActionType::LobbyWarn,
                    PolicyActionType::LobbyBan => v2::ContentPolicyActionType::LobbyBan,
                    PolicyActionType::Blacklist => v2::ContentPolicyActionType::Blacklist,
                    PolicyActionType::HubWarn => v2::ContentPolicyActionType::HubWarn,
                    PolicyActionType::HubMute => v2::ContentPolicyActionType::HubMute,
                    PolicyActionType::HubBan => v2::ContentPolicyActionType::HubBan,
                } as i32,
                duration: action
                    .duration_seconds
                    .map(|seconds| prost_types::Duration {
                        seconds: seconds.min(i64::MAX as u64) as i64,
                        nanos: 0,
                    }),
                replacement: action.replacement.clone().unwrap_or_default(),
            })
            .collect(),
    }
}

fn content_policy_error(error: anyhow::Error) -> Status {
    let message = error.to_string();
    if message.contains("conflict") || message.contains("already exists") {
        Status::aborted("content policy changed while it was being edited")
    } else if message.contains("does not exist") || message.contains("immutable") {
        Status::failed_precondition(message)
    } else if message.contains("pattern")
        || message.contains("rule")
        || message.contains("action")
        || message.contains("scope")
        || message.contains("duration")
        || message.contains("replacement")
        || message.contains("version")
    {
        Status::invalid_argument(message)
    } else {
        internal(error)
    }
}

#[cfg(test)]
mod command_service_tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn native_content_policy_conversion_preserves_authored_rule_data() {
        let policy_id = Uuid::new_v4();
        let rule_id = Uuid::new_v4();
        let pattern_id = Uuid::new_v4();
        let action_id = Uuid::new_v4();
        let policy = v2::NativeContentPolicy {
            id: policy_id.to_string(),
            scope: Some(v2::ContentPolicyScope {
                authority: v2::ContentPolicyAuthority::Hub as i32,
                id: "hub-1".to_owned(),
            }),
            enabled: true,
            version: 7,
            rules: vec![v2::NativeContentRule {
                id: rule_id.to_string(),
                name: "Invites".to_owned(),
                description: "Blocks invite domains".to_owned(),
                enabled: false,
                custom_reason: "No invites".to_owned(),
                created_by: String::new(),
                patterns: vec![v2::NativeContentPattern {
                    id: pattern_id.to_string(),
                    pattern: "discord.gg/*".to_owned(),
                    pattern_type: v2::ContentPatternType::Contains as i32,
                }],
                surfaces: vec![v2::ContentPolicySurface::UrlDomain as i32],
                actions: vec![v2::NativeContentAction {
                    id: action_id.to_string(),
                    r#type: v2::ContentPolicyActionType::Block as i32,
                    duration: None,
                    replacement: String::new(),
                }],
            }],
        };

        let domain = content_policy_from_proto(policy, "actor-1").expect("valid policy");
        assert_eq!(domain.rules[0].created_by, "actor-1");
        assert_eq!(domain.rules[0].patterns[0].pattern, "discord.gg/*");
        let round_trip = content_policy_to_proto(&domain);
        assert_eq!(round_trip.id, policy_id.to_string());
        assert_eq!(round_trip.version, 7);
        assert_eq!(round_trip.rules[0].name, "Invites");
        assert_eq!(round_trip.rules[0].custom_reason, "No invites");
    }

    #[test]
    fn content_policy_conflicts_have_aborted_status() {
        assert_eq!(
            content_policy_error(anyhow::anyhow!("content policy version conflict")).code(),
            Code::Aborted
        );
    }

    #[test]
    fn command_repository_states_have_safe_rpc_codes() {
        assert_eq!(
            command_error(CommandRepositoryError::NotFound).code(),
            Code::NotFound
        );
        assert_eq!(
            command_error(CommandRepositoryError::LeaseMismatch).code(),
            Code::Aborted
        );
        assert_eq!(
            command_error(CommandRepositoryError::VersionMismatch).code(),
            Code::Aborted
        );
        assert_eq!(
            command_error(CommandRepositoryError::RecoveryRequired).code(),
            Code::FailedPrecondition
        );
    }
}

fn conflict_or_internal(error: anyhow::Error) -> Status {
    if error.to_string().contains("conflict") {
        Status::aborted("resource version conflict")
    } else {
        internal(error)
    }
}

fn transcript_entry_from_action(sequence: u64, action: &Action) -> v2::TranscriptEntry {
    let attribute = |name: &str| {
        action
            .attributes
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let system_event_type = match action.action_type.as_str() {
        "lobby.call.connected" => v2::LobbySystemEventType::CallConnected,
        "lobby.participant.joined" => v2::LobbySystemEventType::ParticipantJoined,
        "lobby.participant.left" => v2::LobbySystemEventType::ParticipantLeft,
        "lobby.report.submitted" => v2::LobbySystemEventType::ReportSubmitted,
        "lobby.call.ended" => v2::LobbySystemEventType::CallEnded,
        _ => v2::LobbySystemEventType::Unspecified,
    };
    let is_system = system_event_type != v2::LobbySystemEventType::Unspecified
        || attribute("message_kind") == "system";
    v2::TranscriptEntry {
        sequence,
        action_id: action.id.to_string(),
        kind: if is_system {
            v2::TranscriptEntryKind::SystemEvent
        } else {
            v2::TranscriptEntryKind::UserMessage
        } as i32,
        occurred_at: Some(timestamp(action.occurred_at)),
        message_id: action.subject.message_id.clone().unwrap_or_default(),
        author_id: action.subject.user_id.clone().unwrap_or_default(),
        author_display_name: attribute("author_display_name"),
        author_username: attribute("author_username"),
        original_content: {
            let original = attribute("original_content");
            if original.is_empty() {
                attribute("content")
            } else {
                original
            }
        },
        approved_content: attribute("content"),
        delivery_content: attribute("delivery_content"),
        reply_to_message_id: attribute("reply_to_message_id"),
        reply_author_id: attribute("reply_author_id"),
        reply_author_display_name: attribute("reply_author_display_name"),
        reply_content: attribute("reply_content"),
        system_event_type: system_event_type as i32,
        system_event_reason: attribute("reason"),
    }
}

fn optional_uuid(value: &str, field: &str) -> Result<Option<Uuid>, Status> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_uuid(value, field).map(Some)
    }
}

fn not_found_or_internal(error: anyhow::Error) -> Status {
    if error
        .downcast_ref::<sqlx::Error>()
        .is_some_and(|error| matches!(error, sqlx::Error::RowNotFound))
    {
        Status::not_found("resource not found")
    } else {
        internal(error)
    }
}
fn resource_error(error: anyhow::Error) -> Status {
    let message = error.to_string();
    if message.contains("conflict") || message.contains("already used") {
        Status::aborted(message)
    } else if message.contains("terminal call evidence is not available yet")
        || message.contains("call evidence has a sequence gap")
        || message.contains("illegal policy bundle state transition")
        || message.contains("retired policy bundle")
        || message.contains("cannot change after versions are activated")
        || message.contains("must match")
    {
        Status::failed_precondition(message)
    } else if error
        .downcast_ref::<sqlx::Error>()
        .and_then(|error| error.as_database_error())
        .is_some_and(|error| error.code().as_deref() == Some("23505"))
    {
        Status::already_exists("an active resource already exists for this subject and scope")
    } else if message.contains("required")
        || message.contains("invalid")
        || message.contains("supported identifier")
    {
        Status::invalid_argument(message)
    } else if error
        .downcast_ref::<sqlx::Error>()
        .is_some_and(|error| matches!(error, sqlx::Error::RowNotFound))
    {
        Status::not_found("resource not found")
    } else {
        internal(error)
    }
}
fn optional_uuid_cursor(value: &str) -> Result<Option<Uuid>, Status> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_uuid(value, "cursor").map(Some)
    }
}

fn optional_string_filter(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn moderation_subject_type_filter(value: &str) -> Result<Option<&str>, Status> {
    if value.is_empty() {
        return Ok(None);
    }
    match value {
        "USER" | "SERVER" | "MESSAGE" => Ok(Some(value)),
        _ => Err(Status::invalid_argument(
            "subject_type must be USER, SERVER, or MESSAGE",
        )),
    }
}

fn moderation_record_authorization_fields(
    record: &v2::ModerationRecord,
) -> Result<(&str, &v2::Scope, v2::ModerationRecordKind), Status> {
    let kind = v2::ModerationRecordKind::try_from(record.kind)
        .map_err(|_| Status::invalid_argument("invalid moderation record kind"))?;
    let resource = record
        .resource
        .as_ref()
        .ok_or_else(|| Status::internal("moderation record resource is missing"))?;
    let (created_by, scope) = match resource {
        v2::moderation_record::Resource::Restriction(restriction) => (
            restriction.created_by.as_str(),
            restriction
                .scope
                .as_ref()
                .ok_or_else(|| Status::internal("moderation record scope is missing"))?,
        ),
        v2::moderation_record::Resource::Infraction(infraction) => (
            infraction.created_by.as_str(),
            infraction
                .scope
                .as_ref()
                .ok_or_else(|| Status::internal("moderation record scope is missing"))?,
        ),
    };
    Ok((created_by, scope, kind))
}

fn moderation_record_legacy_permission(
    kind: v2::ModerationRecordKind,
    scope: &v2::Scope,
) -> Permission {
    if kind == v2::ModerationRecordKind::Blacklist || scope.r#type == v2::ScopeType::Platform as i32
    {
        Permission::ManageGlobalBlacklists
    } else {
        Permission::HandleLobbyReports
    }
}

fn restriction_type_filter(value: i32) -> Result<Option<&'static str>, Status> {
    Ok(
        match v2::RestrictionType::try_from(value)
            .map_err(|_| Status::invalid_argument("invalid restriction type"))?
        {
            v2::RestrictionType::Mute => Some("MUTE"),
            v2::RestrictionType::Ban => Some("BAN"),
            v2::RestrictionType::Blacklist => Some("BLACKLIST"),
            v2::RestrictionType::ContentQuarantine => Some("CONTENT_QUARANTINE"),
            v2::RestrictionType::Unspecified => None,
        },
    )
}

fn resource_status_filter(value: i32) -> Result<Option<&'static str>, Status> {
    Ok(
        match v2::ResourceStatus::try_from(value)
            .map_err(|_| Status::invalid_argument("invalid resource status"))?
        {
            v2::ResourceStatus::Active => Some("ACTIVE"),
            v2::ResourceStatus::Revoked => Some("REVOKED"),
            v2::ResourceStatus::Expired => Some("EXPIRED"),
            v2::ResourceStatus::Pending => Some("PENDING"),
            v2::ResourceStatus::Resolved => Some("RESOLVED"),
            v2::ResourceStatus::Dismissed => Some("DISMISSED"),
            v2::ResourceStatus::Unspecified => None,
        },
    )
}
fn resolution_name(value: i32) -> Result<&'static str, Status> {
    match v2::ResourceStatus::try_from(value)
        .map_err(|_| Status::invalid_argument("invalid resolution"))?
    {
        v2::ResourceStatus::Resolved => Ok("RESOLVED"),
        v2::ResourceStatus::Dismissed => Ok("DISMISSED"),
        _ => Err(Status::invalid_argument(
            "resolution must be RESOLVED or DISMISSED",
        )),
    }
}
