// @generated
/// Generated client implementations.
pub mod trust_and_safety_service_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct TrustAndSafetyServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl TrustAndSafetyServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> TrustAndSafetyServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> TrustAndSafetyServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            TrustAndSafetyServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        pub async fn evaluate_action(
            &mut self,
            request: impl tonic::IntoRequest<super::EvaluateActionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::EvaluateActionResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/EvaluateAction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "EvaluateAction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn claim_command(
            &mut self,
            request: impl tonic::IntoRequest<super::ClaimCommandRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ClaimCommandResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ClaimCommand",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ClaimCommand",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn complete_command(
            &mut self,
            request: impl tonic::IntoRequest<super::CompleteCommandRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CompleteCommandResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CompleteCommand",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "CompleteCommand",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_content_policy(
            &mut self,
            request: impl tonic::IntoRequest<super::GetContentPolicyRequest>,
        ) -> std::result::Result<
            tonic::Response<super::GetContentPolicyResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetContentPolicy",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetContentPolicy",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn replace_content_policy(
            &mut self,
            request: impl tonic::IntoRequest<super::ReplaceContentPolicyRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ReplaceContentPolicyResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ReplaceContentPolicy",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ReplaceContentPolicy",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn create_policy_bundle(
            &mut self,
            request: impl tonic::IntoRequest<super::CreatePolicyBundleRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreatePolicyBundle",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "CreatePolicyBundle",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_policy_bundle(
            &mut self,
            request: impl tonic::IntoRequest<super::GetPolicyBundleRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetPolicyBundle",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetPolicyBundle",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_policy_bundles(
            &mut self,
            request: impl tonic::IntoRequest<super::ListPolicyBundlesRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListPolicyBundlesResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListPolicyBundles",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListPolicyBundles",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn update_policy_bundle(
            &mut self,
            request: impl tonic::IntoRequest<super::UpdatePolicyBundleRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/UpdatePolicyBundle",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "UpdatePolicyBundle",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn disable_policy_bundle(
            &mut self,
            request: impl tonic::IntoRequest<super::DisablePolicyBundleRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/DisablePolicyBundle",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "DisablePolicyBundle",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn retire_policy_bundle(
            &mut self,
            request: impl tonic::IntoRequest<super::RetirePolicyBundleRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RetirePolicyBundle",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "RetirePolicyBundle",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn create_policy_draft(
            &mut self,
            request: impl tonic::IntoRequest<super::CreatePolicyDraftRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyVersion>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreatePolicyDraft",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "CreatePolicyDraft",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn validate_policy(
            &mut self,
            request: impl tonic::IntoRequest<super::ValidatePolicyRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ValidatePolicyResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ValidatePolicy",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ValidatePolicy",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn run_policy_tests(
            &mut self,
            request: impl tonic::IntoRequest<super::RunPolicyTestsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::RunPolicyTestsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RunPolicyTests",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "RunPolicyTests",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn create_policy_fixture(
            &mut self,
            request: impl tonic::IntoRequest<super::CreatePolicyFixtureRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyFixture>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreatePolicyFixture",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "CreatePolicyFixture",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn update_policy_fixture(
            &mut self,
            request: impl tonic::IntoRequest<super::UpdatePolicyFixtureRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyFixture>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/UpdatePolicyFixture",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "UpdatePolicyFixture",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn delete_policy_fixture(
            &mut self,
            request: impl tonic::IntoRequest<super::DeletePolicyFixtureRequest>,
        ) -> std::result::Result<tonic::Response<()>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/DeletePolicyFixture",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "DeletePolicyFixture",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_policy_fixtures(
            &mut self,
            request: impl tonic::IntoRequest<super::ListPolicyFixturesRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListPolicyFixturesResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListPolicyFixtures",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListPolicyFixtures",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn set_shadow_mode(
            &mut self,
            request: impl tonic::IntoRequest<super::SetShadowModeRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/SetShadowMode",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "SetShadowMode",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn publish_policy_version(
            &mut self,
            request: impl tonic::IntoRequest<super::PublishPolicyVersionRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyVersion>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/PublishPolicyVersion",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "PublishPolicyVersion",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn approve_policy_version(
            &mut self,
            request: impl tonic::IntoRequest<super::ApprovePolicyVersionRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyApproval>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ApprovePolicyVersion",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ApprovePolicyVersion",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn activate_policy_version(
            &mut self,
            request: impl tonic::IntoRequest<super::ActivatePolicyVersionRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ActivatePolicyVersion",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ActivatePolicyVersion",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn rollback_policy(
            &mut self,
            request: impl tonic::IntoRequest<super::RollbackPolicyRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RollbackPolicy",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "RollbackPolicy",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_policy_versions(
            &mut self,
            request: impl tonic::IntoRequest<super::ListPolicyVersionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListPolicyVersionsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListPolicyVersions",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListPolicyVersions",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_execution_trace(
            &mut self,
            request: impl tonic::IntoRequest<super::GetExecutionTraceRequest>,
        ) -> std::result::Result<tonic::Response<super::ExecutionTrace>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetExecutionTrace",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetExecutionTrace",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_execution_traces(
            &mut self,
            request: impl tonic::IntoRequest<super::ListExecutionTracesRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListExecutionTracesResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListExecutionTraces",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListExecutionTraces",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_provider_health(
            &mut self,
            request: impl tonic::IntoRequest<super::GetProviderHealthRequest>,
        ) -> std::result::Result<
            tonic::Response<super::GetProviderHealthResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetProviderHealth",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetProviderHealth",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn create_nsfw_override(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateNsfwOverrideRequest>,
        ) -> std::result::Result<tonic::Response<super::NsfwOverride>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateNsfwOverride",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "CreateNsfwOverride",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_nsfw_override(
            &mut self,
            request: impl tonic::IntoRequest<super::GetNsfwOverrideRequest>,
        ) -> std::result::Result<tonic::Response<super::NsfwOverride>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetNsfwOverride",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetNsfwOverride",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_nsfw_overrides(
            &mut self,
            request: impl tonic::IntoRequest<super::ListNsfwOverridesRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListNsfwOverridesResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListNsfwOverrides",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListNsfwOverrides",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn update_nsfw_override(
            &mut self,
            request: impl tonic::IntoRequest<super::UpdateNsfwOverrideRequest>,
        ) -> std::result::Result<tonic::Response<super::NsfwOverride>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/UpdateNsfwOverride",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "UpdateNsfwOverride",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn delete_nsfw_override(
            &mut self,
            request: impl tonic::IntoRequest<super::DeleteNsfwOverrideRequest>,
        ) -> std::result::Result<tonic::Response<()>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/DeleteNsfwOverride",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "DeleteNsfwOverride",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn create_restriction(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateRestrictionRequest>,
        ) -> std::result::Result<tonic::Response<super::Restriction>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateRestriction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "CreateRestriction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_restriction(
            &mut self,
            request: impl tonic::IntoRequest<super::GetRestrictionRequest>,
        ) -> std::result::Result<tonic::Response<super::Restriction>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetRestriction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetRestriction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn update_restriction(
            &mut self,
            request: impl tonic::IntoRequest<super::UpdateRestrictionRequest>,
        ) -> std::result::Result<tonic::Response<super::Restriction>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/UpdateRestriction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "UpdateRestriction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn revoke_restriction(
            &mut self,
            request: impl tonic::IntoRequest<super::RevokeRestrictionRequest>,
        ) -> std::result::Result<tonic::Response<super::Restriction>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RevokeRestriction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "RevokeRestriction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_restrictions(
            &mut self,
            request: impl tonic::IntoRequest<super::ListRestrictionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListRestrictionsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListRestrictions",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListRestrictions",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn create_infraction(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateInfractionRequest>,
        ) -> std::result::Result<tonic::Response<super::Infraction>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateInfraction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "CreateInfraction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_infraction(
            &mut self,
            request: impl tonic::IntoRequest<super::GetInfractionRequest>,
        ) -> std::result::Result<tonic::Response<super::Infraction>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetInfraction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetInfraction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn revoke_infraction(
            &mut self,
            request: impl tonic::IntoRequest<super::RevokeInfractionRequest>,
        ) -> std::result::Result<tonic::Response<super::Infraction>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RevokeInfraction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "RevokeInfraction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn revoke_infractions_by_type(
            &mut self,
            request: impl tonic::IntoRequest<super::RevokeInfractionsByTypeRequest>,
        ) -> std::result::Result<
            tonic::Response<super::RevokeInfractionsByTypeResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RevokeInfractionsByType",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "RevokeInfractionsByType",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_infractions(
            &mut self,
            request: impl tonic::IntoRequest<super::ListInfractionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListInfractionsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListInfractions",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListInfractions",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_my_infractions(
            &mut self,
            request: impl tonic::IntoRequest<super::ListMyInfractionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListInfractionsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListMyInfractions",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListMyInfractions",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_moderation_records(
            &mut self,
            request: impl tonic::IntoRequest<super::ListModerationRecordsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListModerationRecordsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListModerationRecords",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListModerationRecords",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn link_moderation_record_report(
            &mut self,
            request: impl tonic::IntoRequest<super::LinkModerationRecordReportRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ModerationRecord>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/LinkModerationRecordReport",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "LinkModerationRecordReport",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn create_report(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateReport",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "CreateReport",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_report(
            &mut self,
            request: impl tonic::IntoRequest<super::GetReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetReport",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetReport",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_reports(
            &mut self,
            request: impl tonic::IntoRequest<super::ListReportsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListReportsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListReports",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListReports",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_report_transcript(
            &mut self,
            request: impl tonic::IntoRequest<super::ListReportTranscriptRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListReportTranscriptResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListReportTranscript",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListReportTranscript",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn resolve_report(
            &mut self,
            request: impl tonic::IntoRequest<super::ResolveReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ResolveReport",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ResolveReport",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn create_appeal(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateAppealRequest>,
        ) -> std::result::Result<tonic::Response<super::Appeal>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateAppeal",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "CreateAppeal",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_appeal(
            &mut self,
            request: impl tonic::IntoRequest<super::GetAppealRequest>,
        ) -> std::result::Result<tonic::Response<super::Appeal>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetAppeal",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetAppeal",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_appeals(
            &mut self,
            request: impl tonic::IntoRequest<super::ListAppealsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListAppealsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListAppeals",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListAppeals",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn resolve_appeal(
            &mut self,
            request: impl tonic::IntoRequest<super::ResolveAppealRequest>,
        ) -> std::result::Result<tonic::Response<super::Appeal>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ResolveAppeal",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ResolveAppeal",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_review_items(
            &mut self,
            request: impl tonic::IntoRequest<super::ListReviewItemsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListReviewItemsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListReviewItems",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListReviewItems",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn resolve_review_item(
            &mut self,
            request: impl tonic::IntoRequest<super::ResolveReviewItemRequest>,
        ) -> std::result::Result<tonic::Response<super::ReviewItem>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ResolveReviewItem",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ResolveReviewItem",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn adjudicate_held_action(
            &mut self,
            request: impl tonic::IntoRequest<super::AdjudicateHeldActionRequest>,
        ) -> std::result::Result<tonic::Response<super::HeldAction>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/AdjudicateHeldAction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "AdjudicateHeldAction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_safety_assessment(
            &mut self,
            request: impl tonic::IntoRequest<super::GetSafetyAssessmentRequest>,
        ) -> std::result::Result<
            tonic::Response<super::SafetyAssessment>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetSafetyAssessment",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetSafetyAssessment",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn record_safety_observation(
            &mut self,
            request: impl tonic::IntoRequest<super::RecordSafetyObservationRequest>,
        ) -> std::result::Result<
            tonic::Response<super::SafetyAssessment>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RecordSafetyObservation",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "RecordSafetyObservation",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn recalculate_safety_assessment(
            &mut self,
            request: impl tonic::IntoRequest<super::RecalculateSafetyAssessmentRequest>,
        ) -> std::result::Result<
            tonic::Response<super::SafetyAssessment>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RecalculateSafetyAssessment",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "RecalculateSafetyAssessment",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_moderation_statistics(
            &mut self,
            request: impl tonic::IntoRequest<super::GetModerationStatisticsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ModerationStatistics>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetModerationStatistics",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetModerationStatistics",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_staff_action_request(
            &mut self,
            request: impl tonic::IntoRequest<super::GetStaffActionRequestRequest>,
        ) -> std::result::Result<
            tonic::Response<super::StaffActionRequest>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetStaffActionRequest",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "GetStaffActionRequest",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_staff_action_requests(
            &mut self,
            request: impl tonic::IntoRequest<super::ListStaffActionRequestsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListStaffActionRequestsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListStaffActionRequests",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ListStaffActionRequests",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn claim_report(
            &mut self,
            request: impl tonic::IntoRequest<super::ClaimReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ClaimReport",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ClaimReport",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn renew_report_claim(
            &mut self,
            request: impl tonic::IntoRequest<super::RenewReportClaimRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RenewReportClaim",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "RenewReportClaim",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn unclaim_report(
            &mut self,
            request: impl tonic::IntoRequest<super::UnclaimReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/UnclaimReport",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "UnclaimReport",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn assign_report(
            &mut self,
            request: impl tonic::IntoRequest<super::AssignReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/AssignReport",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "AssignReport",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn transfer_report(
            &mut self,
            request: impl tonic::IntoRequest<super::TransferReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/TransferReport",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "TransferReport",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn create_staff_action_request(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateStaffActionRequestRequest>,
        ) -> std::result::Result<
            tonic::Response<super::StaffActionRequest>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateStaffActionRequest",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "CreateStaffActionRequest",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn resolve_staff_action_request(
            &mut self,
            request: impl tonic::IntoRequest<super::ResolveStaffActionRequestRequest>,
        ) -> std::result::Result<
            tonic::Response<super::StaffActionRequest>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ResolveStaffActionRequest",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "interchat.trust_and_safety.v2.TrustAndSafetyService",
                        "ResolveStaffActionRequest",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod trust_and_safety_service_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with TrustAndSafetyServiceServer.
    #[async_trait]
    pub trait TrustAndSafetyService: Send + Sync + 'static {
        async fn evaluate_action(
            &self,
            request: tonic::Request<super::EvaluateActionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::EvaluateActionResponse>,
            tonic::Status,
        >;
        async fn claim_command(
            &self,
            request: tonic::Request<super::ClaimCommandRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ClaimCommandResponse>,
            tonic::Status,
        >;
        async fn complete_command(
            &self,
            request: tonic::Request<super::CompleteCommandRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CompleteCommandResponse>,
            tonic::Status,
        >;
        async fn get_content_policy(
            &self,
            request: tonic::Request<super::GetContentPolicyRequest>,
        ) -> std::result::Result<
            tonic::Response<super::GetContentPolicyResponse>,
            tonic::Status,
        >;
        async fn replace_content_policy(
            &self,
            request: tonic::Request<super::ReplaceContentPolicyRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ReplaceContentPolicyResponse>,
            tonic::Status,
        >;
        async fn create_policy_bundle(
            &self,
            request: tonic::Request<super::CreatePolicyBundleRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status>;
        async fn get_policy_bundle(
            &self,
            request: tonic::Request<super::GetPolicyBundleRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status>;
        async fn list_policy_bundles(
            &self,
            request: tonic::Request<super::ListPolicyBundlesRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListPolicyBundlesResponse>,
            tonic::Status,
        >;
        async fn update_policy_bundle(
            &self,
            request: tonic::Request<super::UpdatePolicyBundleRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status>;
        async fn disable_policy_bundle(
            &self,
            request: tonic::Request<super::DisablePolicyBundleRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status>;
        async fn retire_policy_bundle(
            &self,
            request: tonic::Request<super::RetirePolicyBundleRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status>;
        async fn create_policy_draft(
            &self,
            request: tonic::Request<super::CreatePolicyDraftRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyVersion>, tonic::Status>;
        async fn validate_policy(
            &self,
            request: tonic::Request<super::ValidatePolicyRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ValidatePolicyResponse>,
            tonic::Status,
        >;
        async fn run_policy_tests(
            &self,
            request: tonic::Request<super::RunPolicyTestsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::RunPolicyTestsResponse>,
            tonic::Status,
        >;
        async fn create_policy_fixture(
            &self,
            request: tonic::Request<super::CreatePolicyFixtureRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyFixture>, tonic::Status>;
        async fn update_policy_fixture(
            &self,
            request: tonic::Request<super::UpdatePolicyFixtureRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyFixture>, tonic::Status>;
        async fn delete_policy_fixture(
            &self,
            request: tonic::Request<super::DeletePolicyFixtureRequest>,
        ) -> std::result::Result<tonic::Response<()>, tonic::Status>;
        async fn list_policy_fixtures(
            &self,
            request: tonic::Request<super::ListPolicyFixturesRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListPolicyFixturesResponse>,
            tonic::Status,
        >;
        async fn set_shadow_mode(
            &self,
            request: tonic::Request<super::SetShadowModeRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status>;
        async fn publish_policy_version(
            &self,
            request: tonic::Request<super::PublishPolicyVersionRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyVersion>, tonic::Status>;
        async fn approve_policy_version(
            &self,
            request: tonic::Request<super::ApprovePolicyVersionRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyApproval>, tonic::Status>;
        async fn activate_policy_version(
            &self,
            request: tonic::Request<super::ActivatePolicyVersionRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status>;
        async fn rollback_policy(
            &self,
            request: tonic::Request<super::RollbackPolicyRequest>,
        ) -> std::result::Result<tonic::Response<super::PolicyBundle>, tonic::Status>;
        async fn list_policy_versions(
            &self,
            request: tonic::Request<super::ListPolicyVersionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListPolicyVersionsResponse>,
            tonic::Status,
        >;
        async fn get_execution_trace(
            &self,
            request: tonic::Request<super::GetExecutionTraceRequest>,
        ) -> std::result::Result<tonic::Response<super::ExecutionTrace>, tonic::Status>;
        async fn list_execution_traces(
            &self,
            request: tonic::Request<super::ListExecutionTracesRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListExecutionTracesResponse>,
            tonic::Status,
        >;
        async fn get_provider_health(
            &self,
            request: tonic::Request<super::GetProviderHealthRequest>,
        ) -> std::result::Result<
            tonic::Response<super::GetProviderHealthResponse>,
            tonic::Status,
        >;
        async fn create_nsfw_override(
            &self,
            request: tonic::Request<super::CreateNsfwOverrideRequest>,
        ) -> std::result::Result<tonic::Response<super::NsfwOverride>, tonic::Status>;
        async fn get_nsfw_override(
            &self,
            request: tonic::Request<super::GetNsfwOverrideRequest>,
        ) -> std::result::Result<tonic::Response<super::NsfwOverride>, tonic::Status>;
        async fn list_nsfw_overrides(
            &self,
            request: tonic::Request<super::ListNsfwOverridesRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListNsfwOverridesResponse>,
            tonic::Status,
        >;
        async fn update_nsfw_override(
            &self,
            request: tonic::Request<super::UpdateNsfwOverrideRequest>,
        ) -> std::result::Result<tonic::Response<super::NsfwOverride>, tonic::Status>;
        async fn delete_nsfw_override(
            &self,
            request: tonic::Request<super::DeleteNsfwOverrideRequest>,
        ) -> std::result::Result<tonic::Response<()>, tonic::Status>;
        async fn create_restriction(
            &self,
            request: tonic::Request<super::CreateRestrictionRequest>,
        ) -> std::result::Result<tonic::Response<super::Restriction>, tonic::Status>;
        async fn get_restriction(
            &self,
            request: tonic::Request<super::GetRestrictionRequest>,
        ) -> std::result::Result<tonic::Response<super::Restriction>, tonic::Status>;
        async fn update_restriction(
            &self,
            request: tonic::Request<super::UpdateRestrictionRequest>,
        ) -> std::result::Result<tonic::Response<super::Restriction>, tonic::Status>;
        async fn revoke_restriction(
            &self,
            request: tonic::Request<super::RevokeRestrictionRequest>,
        ) -> std::result::Result<tonic::Response<super::Restriction>, tonic::Status>;
        async fn list_restrictions(
            &self,
            request: tonic::Request<super::ListRestrictionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListRestrictionsResponse>,
            tonic::Status,
        >;
        async fn create_infraction(
            &self,
            request: tonic::Request<super::CreateInfractionRequest>,
        ) -> std::result::Result<tonic::Response<super::Infraction>, tonic::Status>;
        async fn get_infraction(
            &self,
            request: tonic::Request<super::GetInfractionRequest>,
        ) -> std::result::Result<tonic::Response<super::Infraction>, tonic::Status>;
        async fn revoke_infraction(
            &self,
            request: tonic::Request<super::RevokeInfractionRequest>,
        ) -> std::result::Result<tonic::Response<super::Infraction>, tonic::Status>;
        async fn revoke_infractions_by_type(
            &self,
            request: tonic::Request<super::RevokeInfractionsByTypeRequest>,
        ) -> std::result::Result<
            tonic::Response<super::RevokeInfractionsByTypeResponse>,
            tonic::Status,
        >;
        async fn list_infractions(
            &self,
            request: tonic::Request<super::ListInfractionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListInfractionsResponse>,
            tonic::Status,
        >;
        async fn list_my_infractions(
            &self,
            request: tonic::Request<super::ListMyInfractionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListInfractionsResponse>,
            tonic::Status,
        >;
        async fn list_moderation_records(
            &self,
            request: tonic::Request<super::ListModerationRecordsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListModerationRecordsResponse>,
            tonic::Status,
        >;
        async fn link_moderation_record_report(
            &self,
            request: tonic::Request<super::LinkModerationRecordReportRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ModerationRecord>,
            tonic::Status,
        >;
        async fn create_report(
            &self,
            request: tonic::Request<super::CreateReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status>;
        async fn get_report(
            &self,
            request: tonic::Request<super::GetReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status>;
        async fn list_reports(
            &self,
            request: tonic::Request<super::ListReportsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListReportsResponse>,
            tonic::Status,
        >;
        async fn list_report_transcript(
            &self,
            request: tonic::Request<super::ListReportTranscriptRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListReportTranscriptResponse>,
            tonic::Status,
        >;
        async fn resolve_report(
            &self,
            request: tonic::Request<super::ResolveReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status>;
        async fn create_appeal(
            &self,
            request: tonic::Request<super::CreateAppealRequest>,
        ) -> std::result::Result<tonic::Response<super::Appeal>, tonic::Status>;
        async fn get_appeal(
            &self,
            request: tonic::Request<super::GetAppealRequest>,
        ) -> std::result::Result<tonic::Response<super::Appeal>, tonic::Status>;
        async fn list_appeals(
            &self,
            request: tonic::Request<super::ListAppealsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListAppealsResponse>,
            tonic::Status,
        >;
        async fn resolve_appeal(
            &self,
            request: tonic::Request<super::ResolveAppealRequest>,
        ) -> std::result::Result<tonic::Response<super::Appeal>, tonic::Status>;
        async fn list_review_items(
            &self,
            request: tonic::Request<super::ListReviewItemsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListReviewItemsResponse>,
            tonic::Status,
        >;
        async fn resolve_review_item(
            &self,
            request: tonic::Request<super::ResolveReviewItemRequest>,
        ) -> std::result::Result<tonic::Response<super::ReviewItem>, tonic::Status>;
        async fn adjudicate_held_action(
            &self,
            request: tonic::Request<super::AdjudicateHeldActionRequest>,
        ) -> std::result::Result<tonic::Response<super::HeldAction>, tonic::Status>;
        async fn get_safety_assessment(
            &self,
            request: tonic::Request<super::GetSafetyAssessmentRequest>,
        ) -> std::result::Result<
            tonic::Response<super::SafetyAssessment>,
            tonic::Status,
        >;
        async fn record_safety_observation(
            &self,
            request: tonic::Request<super::RecordSafetyObservationRequest>,
        ) -> std::result::Result<
            tonic::Response<super::SafetyAssessment>,
            tonic::Status,
        >;
        async fn recalculate_safety_assessment(
            &self,
            request: tonic::Request<super::RecalculateSafetyAssessmentRequest>,
        ) -> std::result::Result<
            tonic::Response<super::SafetyAssessment>,
            tonic::Status,
        >;
        async fn get_moderation_statistics(
            &self,
            request: tonic::Request<super::GetModerationStatisticsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ModerationStatistics>,
            tonic::Status,
        >;
        async fn get_staff_action_request(
            &self,
            request: tonic::Request<super::GetStaffActionRequestRequest>,
        ) -> std::result::Result<
            tonic::Response<super::StaffActionRequest>,
            tonic::Status,
        >;
        async fn list_staff_action_requests(
            &self,
            request: tonic::Request<super::ListStaffActionRequestsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListStaffActionRequestsResponse>,
            tonic::Status,
        >;
        async fn claim_report(
            &self,
            request: tonic::Request<super::ClaimReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status>;
        async fn renew_report_claim(
            &self,
            request: tonic::Request<super::RenewReportClaimRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status>;
        async fn unclaim_report(
            &self,
            request: tonic::Request<super::UnclaimReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status>;
        async fn assign_report(
            &self,
            request: tonic::Request<super::AssignReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status>;
        async fn transfer_report(
            &self,
            request: tonic::Request<super::TransferReportRequest>,
        ) -> std::result::Result<tonic::Response<super::Report>, tonic::Status>;
        async fn create_staff_action_request(
            &self,
            request: tonic::Request<super::CreateStaffActionRequestRequest>,
        ) -> std::result::Result<
            tonic::Response<super::StaffActionRequest>,
            tonic::Status,
        >;
        async fn resolve_staff_action_request(
            &self,
            request: tonic::Request<super::ResolveStaffActionRequestRequest>,
        ) -> std::result::Result<
            tonic::Response<super::StaffActionRequest>,
            tonic::Status,
        >;
    }
    #[derive(Debug)]
    pub struct TrustAndSafetyServiceServer<T: TrustAndSafetyService> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    impl<T: TrustAndSafetyService> TrustAndSafetyServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>>
    for TrustAndSafetyServiceServer<T>
    where
        T: TrustAndSafetyService,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            match req.uri().path() {
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/EvaluateAction" => {
                    #[allow(non_camel_case_types)]
                    struct EvaluateActionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::EvaluateActionRequest>
                    for EvaluateActionSvc<T> {
                        type Response = super::EvaluateActionResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::EvaluateActionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::evaluate_action(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = EvaluateActionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ClaimCommand" => {
                    #[allow(non_camel_case_types)]
                    struct ClaimCommandSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ClaimCommandRequest>
                    for ClaimCommandSvc<T> {
                        type Response = super::ClaimCommandResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ClaimCommandRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::claim_command(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ClaimCommandSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CompleteCommand" => {
                    #[allow(non_camel_case_types)]
                    struct CompleteCommandSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::CompleteCommandRequest>
                    for CompleteCommandSvc<T> {
                        type Response = super::CompleteCommandResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CompleteCommandRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::complete_command(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CompleteCommandSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetContentPolicy" => {
                    #[allow(non_camel_case_types)]
                    struct GetContentPolicySvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetContentPolicyRequest>
                    for GetContentPolicySvc<T> {
                        type Response = super::GetContentPolicyResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetContentPolicyRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_content_policy(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetContentPolicySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ReplaceContentPolicy" => {
                    #[allow(non_camel_case_types)]
                    struct ReplaceContentPolicySvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ReplaceContentPolicyRequest>
                    for ReplaceContentPolicySvc<T> {
                        type Response = super::ReplaceContentPolicyResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ReplaceContentPolicyRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::replace_content_policy(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ReplaceContentPolicySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreatePolicyBundle" => {
                    #[allow(non_camel_case_types)]
                    struct CreatePolicyBundleSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::CreatePolicyBundleRequest>
                    for CreatePolicyBundleSvc<T> {
                        type Response = super::PolicyBundle;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreatePolicyBundleRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::create_policy_bundle(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CreatePolicyBundleSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetPolicyBundle" => {
                    #[allow(non_camel_case_types)]
                    struct GetPolicyBundleSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetPolicyBundleRequest>
                    for GetPolicyBundleSvc<T> {
                        type Response = super::PolicyBundle;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetPolicyBundleRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_policy_bundle(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetPolicyBundleSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListPolicyBundles" => {
                    #[allow(non_camel_case_types)]
                    struct ListPolicyBundlesSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListPolicyBundlesRequest>
                    for ListPolicyBundlesSvc<T> {
                        type Response = super::ListPolicyBundlesResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListPolicyBundlesRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_policy_bundles(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListPolicyBundlesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/UpdatePolicyBundle" => {
                    #[allow(non_camel_case_types)]
                    struct UpdatePolicyBundleSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::UpdatePolicyBundleRequest>
                    for UpdatePolicyBundleSvc<T> {
                        type Response = super::PolicyBundle;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::UpdatePolicyBundleRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::update_policy_bundle(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = UpdatePolicyBundleSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/DisablePolicyBundle" => {
                    #[allow(non_camel_case_types)]
                    struct DisablePolicyBundleSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::DisablePolicyBundleRequest>
                    for DisablePolicyBundleSvc<T> {
                        type Response = super::PolicyBundle;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DisablePolicyBundleRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::disable_policy_bundle(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = DisablePolicyBundleSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RetirePolicyBundle" => {
                    #[allow(non_camel_case_types)]
                    struct RetirePolicyBundleSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::RetirePolicyBundleRequest>
                    for RetirePolicyBundleSvc<T> {
                        type Response = super::PolicyBundle;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RetirePolicyBundleRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::retire_policy_bundle(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RetirePolicyBundleSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreatePolicyDraft" => {
                    #[allow(non_camel_case_types)]
                    struct CreatePolicyDraftSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::CreatePolicyDraftRequest>
                    for CreatePolicyDraftSvc<T> {
                        type Response = super::PolicyVersion;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreatePolicyDraftRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::create_policy_draft(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CreatePolicyDraftSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ValidatePolicy" => {
                    #[allow(non_camel_case_types)]
                    struct ValidatePolicySvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ValidatePolicyRequest>
                    for ValidatePolicySvc<T> {
                        type Response = super::ValidatePolicyResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ValidatePolicyRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::validate_policy(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ValidatePolicySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RunPolicyTests" => {
                    #[allow(non_camel_case_types)]
                    struct RunPolicyTestsSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::RunPolicyTestsRequest>
                    for RunPolicyTestsSvc<T> {
                        type Response = super::RunPolicyTestsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RunPolicyTestsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::run_policy_tests(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RunPolicyTestsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreatePolicyFixture" => {
                    #[allow(non_camel_case_types)]
                    struct CreatePolicyFixtureSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::CreatePolicyFixtureRequest>
                    for CreatePolicyFixtureSvc<T> {
                        type Response = super::PolicyFixture;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreatePolicyFixtureRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::create_policy_fixture(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CreatePolicyFixtureSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/UpdatePolicyFixture" => {
                    #[allow(non_camel_case_types)]
                    struct UpdatePolicyFixtureSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::UpdatePolicyFixtureRequest>
                    for UpdatePolicyFixtureSvc<T> {
                        type Response = super::PolicyFixture;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::UpdatePolicyFixtureRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::update_policy_fixture(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = UpdatePolicyFixtureSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/DeletePolicyFixture" => {
                    #[allow(non_camel_case_types)]
                    struct DeletePolicyFixtureSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::DeletePolicyFixtureRequest>
                    for DeletePolicyFixtureSvc<T> {
                        type Response = ();
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DeletePolicyFixtureRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::delete_policy_fixture(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = DeletePolicyFixtureSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListPolicyFixtures" => {
                    #[allow(non_camel_case_types)]
                    struct ListPolicyFixturesSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListPolicyFixturesRequest>
                    for ListPolicyFixturesSvc<T> {
                        type Response = super::ListPolicyFixturesResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListPolicyFixturesRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_policy_fixtures(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListPolicyFixturesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/SetShadowMode" => {
                    #[allow(non_camel_case_types)]
                    struct SetShadowModeSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::SetShadowModeRequest>
                    for SetShadowModeSvc<T> {
                        type Response = super::PolicyBundle;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SetShadowModeRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::set_shadow_mode(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = SetShadowModeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/PublishPolicyVersion" => {
                    #[allow(non_camel_case_types)]
                    struct PublishPolicyVersionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::PublishPolicyVersionRequest>
                    for PublishPolicyVersionSvc<T> {
                        type Response = super::PolicyVersion;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::PublishPolicyVersionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::publish_policy_version(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = PublishPolicyVersionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ApprovePolicyVersion" => {
                    #[allow(non_camel_case_types)]
                    struct ApprovePolicyVersionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ApprovePolicyVersionRequest>
                    for ApprovePolicyVersionSvc<T> {
                        type Response = super::PolicyApproval;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ApprovePolicyVersionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::approve_policy_version(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ApprovePolicyVersionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ActivatePolicyVersion" => {
                    #[allow(non_camel_case_types)]
                    struct ActivatePolicyVersionSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ActivatePolicyVersionRequest>
                    for ActivatePolicyVersionSvc<T> {
                        type Response = super::PolicyBundle;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ActivatePolicyVersionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::activate_policy_version(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ActivatePolicyVersionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RollbackPolicy" => {
                    #[allow(non_camel_case_types)]
                    struct RollbackPolicySvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::RollbackPolicyRequest>
                    for RollbackPolicySvc<T> {
                        type Response = super::PolicyBundle;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RollbackPolicyRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::rollback_policy(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RollbackPolicySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListPolicyVersions" => {
                    #[allow(non_camel_case_types)]
                    struct ListPolicyVersionsSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListPolicyVersionsRequest>
                    for ListPolicyVersionsSvc<T> {
                        type Response = super::ListPolicyVersionsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListPolicyVersionsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_policy_versions(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListPolicyVersionsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetExecutionTrace" => {
                    #[allow(non_camel_case_types)]
                    struct GetExecutionTraceSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetExecutionTraceRequest>
                    for GetExecutionTraceSvc<T> {
                        type Response = super::ExecutionTrace;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetExecutionTraceRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_execution_trace(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetExecutionTraceSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListExecutionTraces" => {
                    #[allow(non_camel_case_types)]
                    struct ListExecutionTracesSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListExecutionTracesRequest>
                    for ListExecutionTracesSvc<T> {
                        type Response = super::ListExecutionTracesResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListExecutionTracesRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_execution_traces(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListExecutionTracesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetProviderHealth" => {
                    #[allow(non_camel_case_types)]
                    struct GetProviderHealthSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetProviderHealthRequest>
                    for GetProviderHealthSvc<T> {
                        type Response = super::GetProviderHealthResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetProviderHealthRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_provider_health(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetProviderHealthSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateNsfwOverride" => {
                    #[allow(non_camel_case_types)]
                    struct CreateNsfwOverrideSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::CreateNsfwOverrideRequest>
                    for CreateNsfwOverrideSvc<T> {
                        type Response = super::NsfwOverride;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreateNsfwOverrideRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::create_nsfw_override(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CreateNsfwOverrideSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetNsfwOverride" => {
                    #[allow(non_camel_case_types)]
                    struct GetNsfwOverrideSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetNsfwOverrideRequest>
                    for GetNsfwOverrideSvc<T> {
                        type Response = super::NsfwOverride;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetNsfwOverrideRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_nsfw_override(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetNsfwOverrideSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListNsfwOverrides" => {
                    #[allow(non_camel_case_types)]
                    struct ListNsfwOverridesSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListNsfwOverridesRequest>
                    for ListNsfwOverridesSvc<T> {
                        type Response = super::ListNsfwOverridesResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListNsfwOverridesRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_nsfw_overrides(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListNsfwOverridesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/UpdateNsfwOverride" => {
                    #[allow(non_camel_case_types)]
                    struct UpdateNsfwOverrideSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::UpdateNsfwOverrideRequest>
                    for UpdateNsfwOverrideSvc<T> {
                        type Response = super::NsfwOverride;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::UpdateNsfwOverrideRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::update_nsfw_override(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = UpdateNsfwOverrideSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/DeleteNsfwOverride" => {
                    #[allow(non_camel_case_types)]
                    struct DeleteNsfwOverrideSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::DeleteNsfwOverrideRequest>
                    for DeleteNsfwOverrideSvc<T> {
                        type Response = ();
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DeleteNsfwOverrideRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::delete_nsfw_override(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = DeleteNsfwOverrideSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateRestriction" => {
                    #[allow(non_camel_case_types)]
                    struct CreateRestrictionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::CreateRestrictionRequest>
                    for CreateRestrictionSvc<T> {
                        type Response = super::Restriction;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreateRestrictionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::create_restriction(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CreateRestrictionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetRestriction" => {
                    #[allow(non_camel_case_types)]
                    struct GetRestrictionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetRestrictionRequest>
                    for GetRestrictionSvc<T> {
                        type Response = super::Restriction;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetRestrictionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_restriction(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetRestrictionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/UpdateRestriction" => {
                    #[allow(non_camel_case_types)]
                    struct UpdateRestrictionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::UpdateRestrictionRequest>
                    for UpdateRestrictionSvc<T> {
                        type Response = super::Restriction;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::UpdateRestrictionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::update_restriction(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = UpdateRestrictionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RevokeRestriction" => {
                    #[allow(non_camel_case_types)]
                    struct RevokeRestrictionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::RevokeRestrictionRequest>
                    for RevokeRestrictionSvc<T> {
                        type Response = super::Restriction;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RevokeRestrictionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::revoke_restriction(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RevokeRestrictionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListRestrictions" => {
                    #[allow(non_camel_case_types)]
                    struct ListRestrictionsSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListRestrictionsRequest>
                    for ListRestrictionsSvc<T> {
                        type Response = super::ListRestrictionsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListRestrictionsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_restrictions(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListRestrictionsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateInfraction" => {
                    #[allow(non_camel_case_types)]
                    struct CreateInfractionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::CreateInfractionRequest>
                    for CreateInfractionSvc<T> {
                        type Response = super::Infraction;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreateInfractionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::create_infraction(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CreateInfractionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetInfraction" => {
                    #[allow(non_camel_case_types)]
                    struct GetInfractionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetInfractionRequest>
                    for GetInfractionSvc<T> {
                        type Response = super::Infraction;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetInfractionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_infraction(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetInfractionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RevokeInfraction" => {
                    #[allow(non_camel_case_types)]
                    struct RevokeInfractionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::RevokeInfractionRequest>
                    for RevokeInfractionSvc<T> {
                        type Response = super::Infraction;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RevokeInfractionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::revoke_infraction(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RevokeInfractionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RevokeInfractionsByType" => {
                    #[allow(non_camel_case_types)]
                    struct RevokeInfractionsByTypeSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::RevokeInfractionsByTypeRequest>
                    for RevokeInfractionsByTypeSvc<T> {
                        type Response = super::RevokeInfractionsByTypeResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::RevokeInfractionsByTypeRequest,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::revoke_infractions_by_type(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RevokeInfractionsByTypeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListInfractions" => {
                    #[allow(non_camel_case_types)]
                    struct ListInfractionsSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListInfractionsRequest>
                    for ListInfractionsSvc<T> {
                        type Response = super::ListInfractionsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListInfractionsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_infractions(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListInfractionsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListMyInfractions" => {
                    #[allow(non_camel_case_types)]
                    struct ListMyInfractionsSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListMyInfractionsRequest>
                    for ListMyInfractionsSvc<T> {
                        type Response = super::ListInfractionsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListMyInfractionsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_my_infractions(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListMyInfractionsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListModerationRecords" => {
                    #[allow(non_camel_case_types)]
                    struct ListModerationRecordsSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListModerationRecordsRequest>
                    for ListModerationRecordsSvc<T> {
                        type Response = super::ListModerationRecordsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListModerationRecordsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_moderation_records(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListModerationRecordsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/LinkModerationRecordReport" => {
                    #[allow(non_camel_case_types)]
                    struct LinkModerationRecordReportSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<
                        super::LinkModerationRecordReportRequest,
                    > for LinkModerationRecordReportSvc<T> {
                        type Response = super::ModerationRecord;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::LinkModerationRecordReportRequest,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::link_moderation_record_report(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = LinkModerationRecordReportSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateReport" => {
                    #[allow(non_camel_case_types)]
                    struct CreateReportSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::CreateReportRequest>
                    for CreateReportSvc<T> {
                        type Response = super::Report;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreateReportRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::create_report(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CreateReportSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetReport" => {
                    #[allow(non_camel_case_types)]
                    struct GetReportSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetReportRequest>
                    for GetReportSvc<T> {
                        type Response = super::Report;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetReportRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_report(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetReportSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListReports" => {
                    #[allow(non_camel_case_types)]
                    struct ListReportsSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListReportsRequest>
                    for ListReportsSvc<T> {
                        type Response = super::ListReportsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListReportsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_reports(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListReportsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListReportTranscript" => {
                    #[allow(non_camel_case_types)]
                    struct ListReportTranscriptSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListReportTranscriptRequest>
                    for ListReportTranscriptSvc<T> {
                        type Response = super::ListReportTranscriptResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListReportTranscriptRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_report_transcript(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListReportTranscriptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ResolveReport" => {
                    #[allow(non_camel_case_types)]
                    struct ResolveReportSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ResolveReportRequest>
                    for ResolveReportSvc<T> {
                        type Response = super::Report;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ResolveReportRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::resolve_report(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ResolveReportSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateAppeal" => {
                    #[allow(non_camel_case_types)]
                    struct CreateAppealSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::CreateAppealRequest>
                    for CreateAppealSvc<T> {
                        type Response = super::Appeal;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreateAppealRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::create_appeal(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CreateAppealSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetAppeal" => {
                    #[allow(non_camel_case_types)]
                    struct GetAppealSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetAppealRequest>
                    for GetAppealSvc<T> {
                        type Response = super::Appeal;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetAppealRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_appeal(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetAppealSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListAppeals" => {
                    #[allow(non_camel_case_types)]
                    struct ListAppealsSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListAppealsRequest>
                    for ListAppealsSvc<T> {
                        type Response = super::ListAppealsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListAppealsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_appeals(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListAppealsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ResolveAppeal" => {
                    #[allow(non_camel_case_types)]
                    struct ResolveAppealSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ResolveAppealRequest>
                    for ResolveAppealSvc<T> {
                        type Response = super::Appeal;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ResolveAppealRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::resolve_appeal(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ResolveAppealSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListReviewItems" => {
                    #[allow(non_camel_case_types)]
                    struct ListReviewItemsSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListReviewItemsRequest>
                    for ListReviewItemsSvc<T> {
                        type Response = super::ListReviewItemsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListReviewItemsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_review_items(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListReviewItemsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ResolveReviewItem" => {
                    #[allow(non_camel_case_types)]
                    struct ResolveReviewItemSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ResolveReviewItemRequest>
                    for ResolveReviewItemSvc<T> {
                        type Response = super::ReviewItem;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ResolveReviewItemRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::resolve_review_item(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ResolveReviewItemSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/AdjudicateHeldAction" => {
                    #[allow(non_camel_case_types)]
                    struct AdjudicateHeldActionSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::AdjudicateHeldActionRequest>
                    for AdjudicateHeldActionSvc<T> {
                        type Response = super::HeldAction;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::AdjudicateHeldActionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::adjudicate_held_action(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = AdjudicateHeldActionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetSafetyAssessment" => {
                    #[allow(non_camel_case_types)]
                    struct GetSafetyAssessmentSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetSafetyAssessmentRequest>
                    for GetSafetyAssessmentSvc<T> {
                        type Response = super::SafetyAssessment;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetSafetyAssessmentRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_safety_assessment(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetSafetyAssessmentSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RecordSafetyObservation" => {
                    #[allow(non_camel_case_types)]
                    struct RecordSafetyObservationSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::RecordSafetyObservationRequest>
                    for RecordSafetyObservationSvc<T> {
                        type Response = super::SafetyAssessment;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::RecordSafetyObservationRequest,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::record_safety_observation(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RecordSafetyObservationSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RecalculateSafetyAssessment" => {
                    #[allow(non_camel_case_types)]
                    struct RecalculateSafetyAssessmentSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<
                        super::RecalculateSafetyAssessmentRequest,
                    > for RecalculateSafetyAssessmentSvc<T> {
                        type Response = super::SafetyAssessment;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::RecalculateSafetyAssessmentRequest,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::recalculate_safety_assessment(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RecalculateSafetyAssessmentSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetModerationStatistics" => {
                    #[allow(non_camel_case_types)]
                    struct GetModerationStatisticsSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetModerationStatisticsRequest>
                    for GetModerationStatisticsSvc<T> {
                        type Response = super::ModerationStatistics;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::GetModerationStatisticsRequest,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_moderation_statistics(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetModerationStatisticsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/GetStaffActionRequest" => {
                    #[allow(non_camel_case_types)]
                    struct GetStaffActionRequestSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::GetStaffActionRequestRequest>
                    for GetStaffActionRequestSvc<T> {
                        type Response = super::StaffActionRequest;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetStaffActionRequestRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::get_staff_action_request(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetStaffActionRequestSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ListStaffActionRequests" => {
                    #[allow(non_camel_case_types)]
                    struct ListStaffActionRequestsSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ListStaffActionRequestsRequest>
                    for ListStaffActionRequestsSvc<T> {
                        type Response = super::ListStaffActionRequestsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::ListStaffActionRequestsRequest,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::list_staff_action_requests(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListStaffActionRequestsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ClaimReport" => {
                    #[allow(non_camel_case_types)]
                    struct ClaimReportSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::ClaimReportRequest>
                    for ClaimReportSvc<T> {
                        type Response = super::Report;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ClaimReportRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::claim_report(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ClaimReportSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/RenewReportClaim" => {
                    #[allow(non_camel_case_types)]
                    struct RenewReportClaimSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::RenewReportClaimRequest>
                    for RenewReportClaimSvc<T> {
                        type Response = super::Report;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RenewReportClaimRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::renew_report_claim(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RenewReportClaimSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/UnclaimReport" => {
                    #[allow(non_camel_case_types)]
                    struct UnclaimReportSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::UnclaimReportRequest>
                    for UnclaimReportSvc<T> {
                        type Response = super::Report;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::UnclaimReportRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::unclaim_report(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = UnclaimReportSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/AssignReport" => {
                    #[allow(non_camel_case_types)]
                    struct AssignReportSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::AssignReportRequest>
                    for AssignReportSvc<T> {
                        type Response = super::Report;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::AssignReportRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::assign_report(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = AssignReportSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/TransferReport" => {
                    #[allow(non_camel_case_types)]
                    struct TransferReportSvc<T: TrustAndSafetyService>(pub Arc<T>);
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::TransferReportRequest>
                    for TransferReportSvc<T> {
                        type Response = super::Report;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::TransferReportRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::transfer_report(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = TransferReportSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/CreateStaffActionRequest" => {
                    #[allow(non_camel_case_types)]
                    struct CreateStaffActionRequestSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<super::CreateStaffActionRequestRequest>
                    for CreateStaffActionRequestSvc<T> {
                        type Response = super::StaffActionRequest;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::CreateStaffActionRequestRequest,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::create_staff_action_request(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CreateStaffActionRequestSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/interchat.trust_and_safety.v2.TrustAndSafetyService/ResolveStaffActionRequest" => {
                    #[allow(non_camel_case_types)]
                    struct ResolveStaffActionRequestSvc<T: TrustAndSafetyService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: TrustAndSafetyService,
                    > tonic::server::UnaryService<
                        super::ResolveStaffActionRequestRequest,
                    > for ResolveStaffActionRequestSvc<T> {
                        type Response = super::StaffActionRequest;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::ResolveStaffActionRequestRequest,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as TrustAndSafetyService>::resolve_staff_action_request(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ResolveStaffActionRequestSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", tonic::Code::Unimplemented as i32)
                                .header(
                                    http::header::CONTENT_TYPE,
                                    tonic::metadata::GRPC_CONTENT_TYPE,
                                )
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: TrustAndSafetyService> Clone for TrustAndSafetyServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    impl<T: TrustAndSafetyService> tonic::server::NamedService
    for TrustAndSafetyServiceServer<T> {
        const NAME: &'static str = "interchat.trust_and_safety.v2.TrustAndSafetyService";
    }
}
