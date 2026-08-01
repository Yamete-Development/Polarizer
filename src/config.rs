use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    net::IpAddr,
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone)]
pub struct MigrationConfig {
    pub database_url: String,
    pub database_max_connections: u32,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaffAuthorizationMode {
    Legacy,
    Shadow,
    Enforce,
}

impl std::str::FromStr for StaffAuthorizationMode {
    type Err = std::io::Error;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "legacy" => Ok(Self::Legacy),
            "shadow" => Ok(Self::Shadow),
            "enforce" => Ok(Self::Enforce),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "STAFF_AUTHORIZATION_MODE must be legacy, shadow, or enforce",
            )),
        }
    }
}

impl MigrationConfig {
    pub fn from_env() -> Result<Self> {
        let timeout_seconds = parse("POLARIZER_MIGRATION_TIMEOUT_SECONDS", "120")?;
        if timeout_seconds == 0 {
            bail!("POLARIZER_MIGRATION_TIMEOUT_SECONDS must be greater than zero");
        }
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            database_max_connections: parse("DATABASE_MAX_CONNECTIONS", "20")?,
            timeout: Duration::from_secs(timeout_seconds),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub database_max_connections: u32,
    pub auto_migrate: bool,
    pub migration_timeout: Duration,
    pub kafka_brokers: String,
    pub action_topic: String,
    pub decision_topic: String,
    pub command_topic: String,
    pub command_result_topic: String,
    pub policy_invalidation_topic: String,
    pub staff_authorization_change_topic: String,
    pub prism_topic: String,
    pub delivery_callback_topic: String,
    pub dlq_topic: String,
    pub delivery_dlq_topic: String,
    pub kafka_group_id: String,
    pub http_host: IpAddr,
    pub http_port: u16,
    pub grpc_host: IpAddr,
    pub grpc_port: u16,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub tls_client_ca_path: Option<PathBuf>,
    pub iris_endpoint: String,
    pub iris_tls_domain: String,
    pub iris_tls_ca_path: Option<PathBuf>,
    pub iris_tls_cert_path: Option<PathBuf>,
    pub iris_tls_key_path: Option<PathBuf>,
    pub iris_timeout: Duration,
    pub staff_authorization_mode: StaffAuthorizationMode,
    pub staff_case_claim_lease: Duration,
    pub staff_case_transfer_cooldown: Duration,
    pub service_principal_allowlist: BTreeMap<String, BTreeSet<String>>,
    pub service_principal_cert_sha256: BTreeMap<String, BTreeSet<String>>,
    pub encryption_key_id: String,
    pub encryption_key: Option<Vec<u8>>,
    pub policy_worker_bin: PathBuf,
    pub policy_worker_count: usize,
    pub luau_source_limit: usize,
    pub luau_heap_limit: usize,
    pub luau_instruction_limit: u64,
    pub luau_wall_timeout: Duration,
    pub luau_output_limit: usize,
    pub clean_allow_trace_sample_rate: f64,
    pub openai_api_key: Option<String>,
    pub openai_model: String,
    pub openai_connect_timeout: Duration,
    pub openai_request_timeout: Duration,
    pub openai_concurrency: usize,
    pub openai_external_images: bool,
    pub attachment_allowed_hosts: Vec<String>,
    pub attachment_max_bytes: u64,
    pub attachment_max_pixels: u64,
    pub nsfw_model_path: Option<PathBuf>,
    pub nsfw_model_input_name: String,
    pub nsfw_model_image_size: u32,
    pub nsfw_model_mean: [f32; 3],
    pub nsfw_model_std: [f32; 3],
    pub nsfw_model_labels: Vec<String>,
    pub nsfw_model_threads: usize,
    pub log_level: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let migration = MigrationConfig::from_env()?;
        let worker_bin = env::var_os("POLARIZER_POLICY_WORKER_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("polarizer-policy-worker"));
        let sample_rate = parse("CLEAN_ALLOW_TRACE_SAMPLE_RATE", "0.01")?;
        if !(0.0..=1.0).contains(&sample_rate) {
            bail!("CLEAN_ALLOW_TRACE_SAMPLE_RATE must be between 0 and 1");
        }

        let encryption_key = env::var("ACTION_ENCRYPTION_KEY_HEX")
            .ok()
            .map(|raw| hex::decode(raw).context("ACTION_ENCRYPTION_KEY_HEX must be hexadecimal"))
            .transpose()?;
        if let Some(key) = &encryption_key
            && key.len() != 32
        {
            bail!("ACTION_ENCRYPTION_KEY_HEX must decode to exactly 32 bytes");
        }

        let service_principal_allowlist: BTreeMap<String, BTreeSet<String>> =
            serde_json::from_str(&required("SERVICE_PRINCIPAL_ALLOWLIST_JSON")?)
                .context("SERVICE_PRINCIPAL_ALLOWLIST_JSON must map principals to method names")?;
        let mut service_principal_cert_sha256: BTreeMap<String, BTreeSet<String>> =
            serde_json::from_str(&required("SERVICE_PRINCIPAL_CERT_SHA256_JSON")?).context(
                "SERVICE_PRINCIPAL_CERT_SHA256_JSON must map principals to certificate fingerprints",
            )?;
        validate_service_principals(
            &service_principal_allowlist,
            &mut service_principal_cert_sha256,
        )?;

        Ok(Self {
            database_url: migration.database_url,
            database_max_connections: migration.database_max_connections,
            auto_migrate: parse("POLARIZER_AUTO_MIGRATE", "true")?,
            migration_timeout: migration.timeout,
            kafka_brokers: optional("KAFKA_BROKERS", "localhost:9092"),
            action_topic: optional(
                "KAFKA_ACTION_TOPIC",
                "events.trust-safety.action.requested.v2",
            ),
            decision_topic: optional("KAFKA_DECISION_TOPIC", "events.trust-safety.decision.v2"),
            command_topic: optional("KAFKA_COMMAND_TOPIC", "events.trust-safety.commands.v2"),
            command_result_topic: optional(
                "KAFKA_COMMAND_RESULT_TOPIC",
                "events.trust-safety.command-results.v2",
            ),
            policy_invalidation_topic: optional(
                "KAFKA_POLICY_INVALIDATION_TOPIC",
                "events.trust-safety.policy.invalidated.v2",
            ),
            staff_authorization_change_topic: optional(
                "KAFKA_STAFF_AUTHZ_CHANGE_TOPIC",
                "events.authz.staff.changed.v1",
            ),
            prism_topic: optional("KAFKA_PRISM_TOPIC", "prism.stream.jobs"),
            delivery_callback_topic: optional(
                "KAFKA_PRISM_DELIVERY_TOPIC",
                "events.prism.delivery.v2",
            ),
            dlq_topic: optional(
                "KAFKA_DLQ_TOPIC",
                "events.trust-safety.action.requested.v2.dlq",
            ),
            delivery_dlq_topic: optional(
                "KAFKA_PRISM_DELIVERY_DLQ_TOPIC",
                "events.prism.delivery.v2.dlq",
            ),
            kafka_group_id: optional("KAFKA_GROUP_ID", "polarizer-v2"),
            http_host: parse("HTTP_HOST", "0.0.0.0")?,
            http_port: parse("HTTP_PORT", "9090")?,
            grpc_host: parse("GRPC_HOST", "0.0.0.0")?,
            grpc_port: parse("GRPC_PORT", "50051")?,
            tls_cert_path: path("GRPC_TLS_CERT"),
            tls_key_path: path("GRPC_TLS_KEY"),
            tls_client_ca_path: path("GRPC_TLS_CLIENT_CA"),
            iris_endpoint: required("IRIS_ENDPOINT")?,
            iris_tls_domain: required("IRIS_TLS_DOMAIN")?,
            iris_tls_ca_path: path("IRIS_TLS_CA"),
            iris_tls_cert_path: path("IRIS_TLS_CERT"),
            iris_tls_key_path: path("IRIS_TLS_KEY"),
            iris_timeout: Duration::from_millis(parse("IRIS_TIMEOUT_MS", "2000")?),
            staff_authorization_mode: parse("STAFF_AUTHORIZATION_MODE", "enforce")?,
            staff_case_claim_lease: Duration::from_secs(parse(
                "STAFF_CASE_CLAIM_LEASE_SECONDS",
                "1800",
            )?),
            staff_case_transfer_cooldown: Duration::from_secs(parse(
                "STAFF_CASE_TRANSFER_COOLDOWN_SECONDS",
                "300",
            )?),
            service_principal_allowlist,
            service_principal_cert_sha256,
            encryption_key_id: optional("ACTION_ENCRYPTION_KEY_ID", "local-development"),
            encryption_key,
            policy_worker_bin: worker_bin,
            policy_worker_count: parse("POLICY_WORKER_COUNT", "4")?,
            luau_source_limit: parse("LUAU_SOURCE_LIMIT_BYTES", "65536")?,
            luau_heap_limit: parse("LUAU_HEAP_LIMIT_BYTES", "4194304")?,
            luau_instruction_limit: parse("LUAU_INSTRUCTION_LIMIT", "100000")?,
            luau_wall_timeout: Duration::from_millis(parse("LUAU_WALL_TIMEOUT_MS", "25")?),
            luau_output_limit: parse("LUAU_OUTPUT_LIMIT_BYTES", "262144")?,
            clean_allow_trace_sample_rate: sample_rate,
            openai_api_key: env::var("OPENAI_API_KEY").ok(),
            openai_model: optional("OPENAI_MODERATION_MODEL", "omni-moderation-2024-09-26"),
            openai_connect_timeout: Duration::from_millis(parse(
                "OPENAI_CONNECT_TIMEOUT_MS",
                "1000",
            )?),
            openai_request_timeout: Duration::from_millis(parse(
                "OPENAI_REQUEST_TIMEOUT_MS",
                "5000",
            )?),
            openai_concurrency: parse("OPENAI_MAX_CONCURRENCY", "16")?,
            openai_external_images: parse("OPENAI_EXTERNAL_IMAGES", "false")?,
            attachment_allowed_hosts: optional(
                "ATTACHMENT_ALLOWED_HOSTS",
                "cdn.discordapp.com,media.discordapp.net",
            )
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(str::to_ascii_lowercase)
            .collect(),
            attachment_max_bytes: parse("ATTACHMENT_MAX_BYTES", "20971520")?,
            attachment_max_pixels: parse("ATTACHMENT_MAX_PIXELS", "40000000")?,
            nsfw_model_path: path("NSFW_MODEL_PATH"),
            nsfw_model_input_name: optional("NSFW_MODEL_INPUT_NAME", "pixel_values"),
            nsfw_model_image_size: parse("NSFW_MODEL_IMAGE_SIZE", "224")?,
            nsfw_model_mean: parse_triple("NSFW_MODEL_MEAN", "0.5,0.5,0.5")?,
            nsfw_model_std: parse_triple("NSFW_MODEL_STD", "0.5,0.5,0.5")?,
            nsfw_model_labels: optional("NSFW_MODEL_LABELS", "nsfw,normal")
                .split(',')
                .map(str::trim)
                .map(str::to_owned)
                .collect(),
            nsfw_model_threads: parse("NSFW_MODEL_THREADS", "4")?,
            log_level: optional("LOG_LEVEL", "info,sqlx=warn,rdkafka=warn"),
        })
    }

    pub fn tls_is_complete(&self) -> bool {
        self.tls_cert_path.is_some()
            && self.tls_key_path.is_some()
            && self.tls_client_ca_path.is_some()
    }

    pub fn iris_tls_is_complete(&self) -> bool {
        self.iris_tls_ca_path.is_some()
            && self.iris_tls_cert_path.is_some()
            && self.iris_tls_key_path.is_some()
    }
}

fn required(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("{name} is required"))
}

fn optional(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn parse<T>(name: &str, default: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    optional(name, default)
        .parse()
        .with_context(|| format!("{name} has an invalid value"))
}

fn path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn parse_triple(name: &str, default: &str) -> Result<[f32; 3]> {
    let values = optional(name, default)
        .split(',')
        .map(str::trim)
        .map(str::parse::<f32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("{name} must contain three comma-separated numbers"))?;
    values
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain exactly three numbers"))
}

fn validate_service_principals(
    allowlist: &BTreeMap<String, BTreeSet<String>>,
    certificate_fingerprints: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    for (principal, methods) in allowlist {
        if methods.is_empty() {
            bail!("service principal {principal} has no allowed methods");
        }
        if methods.contains("*") {
            bail!("service principal {principal} must use an explicit method allowlist");
        }
        if !certificate_fingerprints.contains_key(principal) {
            bail!("service principal {principal} has no certificate fingerprints");
        }
    }
    for (principal, fingerprints) in certificate_fingerprints {
        if !allowlist.contains_key(principal) {
            bail!("certificate principal {principal} has no method allowlist");
        }
        if fingerprints.is_empty() {
            bail!("certificate principal {principal} has no fingerprints");
        }
        let normalized = fingerprints
            .iter()
            .map(|fingerprint| fingerprint.trim().to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        for fingerprint in &normalized {
            if fingerprint.len() != 64 || hex::decode(fingerprint).is_err() {
                bail!("certificate fingerprint for {principal} must be 64 hexadecimal characters");
            }
        }
        *fingerprints = normalized;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn service_principals_require_explicit_methods_and_certificates() {
        let allowlist = BTreeMap::from([(
            "winter".to_owned(),
            BTreeSet::from(["ListPolicyVersions".to_owned()]),
        )]);
        let mut certificates = BTreeMap::from([(
            "winter".to_owned(),
            BTreeSet::from([fingerprint().to_uppercase()]),
        )]);

        validate_service_principals(&allowlist, &mut certificates).expect("valid mapping");
        assert!(certificates["winter"].contains(&fingerprint()));
    }

    #[test]
    fn wildcard_service_principal_is_rejected() {
        let allowlist = BTreeMap::from([("winter".to_owned(), BTreeSet::from(["*".to_owned()]))]);
        let mut certificates =
            BTreeMap::from([("winter".to_owned(), BTreeSet::from([fingerprint()]))]);

        assert!(validate_service_principals(&allowlist, &mut certificates).is_err());
    }
}
