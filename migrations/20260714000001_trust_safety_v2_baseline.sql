-- Polarizer trust-and-safety v2 baseline.
-- Requires PostgreSQL 18 for native uuidv7(). This migration intentionally
-- replaces the never-deployed v1 migration series.

CREATE SCHEMA trust_safety;

CREATE TYPE trust_safety.scope_type AS ENUM (
    'PLATFORM', 'PRODUCT', 'HUB', 'LOBBY', 'INCIDENT_OVERLAY'
);
CREATE TYPE trust_safety.resource_status AS ENUM (
    'ACTIVE', 'REVOKED', 'EXPIRED', 'PENDING', 'RESOLVED', 'DISMISSED'
);
CREATE TYPE trust_safety.policy_state AS ENUM (
    'DRAFT', 'VALIDATED', 'SHADOW', 'ACTIVE', 'DISABLED', 'RETIRED'
);
CREATE TYPE trust_safety.policy_language AS ENUM ('policy-ir-v1', 'luau-v1');
CREATE TYPE trust_safety.policy_bundle_state AS ENUM ('ACTIVE', 'DISABLED', 'RETIRED');
CREATE TYPE trust_safety.error_behavior AS ENUM ('HOLD', 'REVIEW', 'CONTINUE');
CREATE TYPE trust_safety.decision AS ENUM ('ALLOW', 'CENSOR', 'HOLD', 'BLOCK');
CREATE TYPE trust_safety.outbox_status AS ENUM ('PENDING', 'CLAIMED', 'PUBLISHED', 'FAILED');
CREATE TYPE trust_safety.message_state AS ENUM (
    'PENDING_MODERATION', 'APPROVED_PENDING_DELIVERY', 'ACTIVE',
    'BLOCKED', 'HELD', 'EXPIRED', 'DELIVERY_FAILED'
);

CREATE TABLE trust_safety.restriction (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('USER', 'SERVER')),
    subject_id TEXT NOT NULL,
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    restriction_type TEXT NOT NULL CHECK (restriction_type IN ('MUTE', 'BAN', 'BLACKLIST', 'CONTENT_QUARANTINE')),
    status trust_safety.resource_status NOT NULL DEFAULT 'ACTIVE',
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
    source_action_id UUID,
    source_policy_version_id UUID,
    created_by TEXT NOT NULL,
    revoked_by TEXT,
    revoked_reason TEXT,
    starts_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1,
    CHECK (expires_at IS NULL OR expires_at > starts_at)
);
CREATE INDEX restriction_enforcement_idx
    ON trust_safety.restriction (subject_type, subject_id, scope_type, scope_id, status, expires_at);
CREATE UNIQUE INDEX restriction_active_identity_idx
    ON trust_safety.restriction (subject_type, subject_id, scope_type, scope_id, restriction_type)
    WHERE status = 'ACTIVE';

CREATE TABLE trust_safety.infraction (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('USER', 'SERVER', 'MESSAGE')),
    subject_id TEXT NOT NULL,
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    infraction_type TEXT NOT NULL CHECK (infraction_type IN ('WARNING', 'MUTE', 'BAN', 'CONTENT')),
    status trust_safety.resource_status NOT NULL DEFAULT 'ACTIVE',
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
    source_action_id UUID,
    source_policy_version_id UUID,
    enforcement_restriction_id UUID REFERENCES trust_safety.restriction(id),
    created_by TEXT NOT NULL,
    revoked_by TEXT,
    revoked_reason TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1
);
CREATE INDEX infraction_subject_idx
    ON trust_safety.infraction (subject_type, subject_id, scope_type, scope_id, status, created_at DESC);

CREATE TABLE trust_safety.report (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    reporter_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    report_type TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    status trust_safety.resource_status NOT NULL DEFAULT 'PENDING',
    resolution TEXT,
    resolved_by TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1
);
CREATE INDEX report_queue_idx
    ON trust_safety.report (scope_type, scope_id, status, created_at);

CREATE TABLE trust_safety.appeal (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    infraction_id UUID NOT NULL REFERENCES trust_safety.infraction(id),
    appellant_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    status trust_safety.resource_status NOT NULL DEFAULT 'PENDING',
    resolution TEXT,
    resolved_by TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1,
    UNIQUE (infraction_id, appellant_id)
);
CREATE INDEX appeal_queue_idx ON trust_safety.appeal (status, created_at);

CREATE TABLE trust_safety.policy_bundle (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    product TEXT CHECK (product IS NULL OR product IN ('HUB', 'LOBBY')),
    mandatory BOOLEAN NOT NULL DEFAULT FALSE,
    priority INTEGER NOT NULL DEFAULT 100,
    state trust_safety.policy_bundle_state NOT NULL DEFAULT 'ACTIVE',
    active_version_id UUID,
    shadow_version_id UUID,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1,
    UNIQUE NULLS NOT DISTINCT (scope_type, scope_id, product, name)
);
CREATE INDEX policy_bundle_scope_state_idx
    ON trust_safety.policy_bundle (scope_type, scope_id, state, id DESC);

CREATE TABLE trust_safety.policy_version (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    bundle_id UUID NOT NULL REFERENCES trust_safety.policy_bundle(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    language trust_safety.policy_language NOT NULL,
    runtime_version TEXT NOT NULL,
    source TEXT NOT NULL CHECK (octet_length(source) <= 65536),
    compiled_artifact BYTEA,
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
    artifact_sha256 TEXT CHECK (artifact_sha256 IS NULL OR length(artifact_sha256) = 64),
    manifest JSONB NOT NULL,
    state trust_safety.policy_state NOT NULL DEFAULT 'DRAFT',
    validation_diagnostics JSONB NOT NULL DEFAULT '[]'::jsonb,
    fixture_revision BIGINT NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    validated_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    UNIQUE (bundle_id, version),
    UNIQUE (bundle_id, source_sha256)
);
ALTER TABLE trust_safety.policy_bundle
    ADD CONSTRAINT policy_bundle_active_version_fk
    FOREIGN KEY (active_version_id) REFERENCES trust_safety.policy_version(id);
ALTER TABLE trust_safety.policy_bundle
    ADD CONSTRAINT policy_bundle_shadow_version_fk
    FOREIGN KEY (shadow_version_id) REFERENCES trust_safety.policy_version(id);
ALTER TABLE trust_safety.restriction
    ADD CONSTRAINT restriction_source_policy_version_fk
    FOREIGN KEY (source_policy_version_id) REFERENCES trust_safety.policy_version(id);
ALTER TABLE trust_safety.infraction
    ADD CONSTRAINT infraction_source_policy_version_fk
    FOREIGN KEY (source_policy_version_id) REFERENCES trust_safety.policy_version(id);
CREATE INDEX policy_version_bundle_idx
    ON trust_safety.policy_version (bundle_id, version DESC);

CREATE TABLE trust_safety.policy_fixture (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    policy_version_id UUID NOT NULL REFERENCES trust_safety.policy_version(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    action JSONB NOT NULL,
    feature_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    expected_effects JSONB NOT NULL,
    committed BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1,
    UNIQUE (policy_version_id, name)
);

CREATE TABLE trust_safety.policy_test_run (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    policy_version_id UUID NOT NULL REFERENCES trust_safety.policy_version(id) ON DELETE CASCADE,
    passed BOOLEAN NOT NULL,
    results JSONB NOT NULL,
    fixture_revision BIGINT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX policy_test_run_version_idx
    ON trust_safety.policy_test_run (policy_version_id, created_at DESC);

CREATE TABLE trust_safety.policy_approval (
    policy_version_id UUID NOT NULL REFERENCES trust_safety.policy_version(id) ON DELETE CASCADE,
    administrator_id TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (policy_version_id, administrator_id)
);

CREATE TABLE trust_safety.policy_activation (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    bundle_id UUID NOT NULL REFERENCES trust_safety.policy_bundle(id),
    from_version_id UUID REFERENCES trust_safety.policy_version(id),
    to_version_id UUID NOT NULL REFERENCES trust_safety.policy_version(id),
    activation_type TEXT NOT NULL CHECK (activation_type IN ('ACTIVATE', 'ROLLBACK', 'SHADOW_START', 'SHADOW_STOP')),
    activated_by TEXT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE trust_safety.scheduled_policy_activation (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    bundle_id UUID NOT NULL REFERENCES trust_safety.policy_bundle(id),
    policy_version_id UUID NOT NULL REFERENCES trust_safety.policy_version(id),
    expected_bundle_version BIGINT NOT NULL,
    activation_type TEXT NOT NULL CHECK (activation_type IN ('ACTIVATE', 'ROLLBACK')),
    activate_at TIMESTAMPTZ NOT NULL,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'APPLIED', 'FAILED', 'CANCELLED')),
    failure_code TEXT,
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    applied_at TIMESTAMPTZ
);
CREATE INDEX scheduled_policy_activation_due_idx
    ON trust_safety.scheduled_policy_activation (status, activate_at);

-- Safe boot policies. These are ordinary immutable policy-ir-v1 versions and
-- can be superseded through the same reviewed activation lifecycle as any
-- later policy.
WITH bundle AS (
    INSERT INTO trust_safety.policy_bundle
        (name, description, scope_type, scope_id, mandatory, priority, created_by)
    VALUES
        ('platform-active-restrictions', 'Enforce authoritative active user and server restrictions.',
         'PLATFORM', '', TRUE, 0, 'polarizer-bootstrap')
    RETURNING id
), version AS (
    INSERT INTO trust_safety.policy_version
        (bundle_id, version, language, runtime_version, source, compiled_artifact,
         source_sha256, artifact_sha256, manifest, state, validation_diagnostics,
         created_by, validated_at, published_at)
    SELECT id, 1, 'policy-ir-v1', 'policy-ir-v1.0.0', source,
           convert_to(source, 'UTF8'),
           '10584793fca13585f164955263086966361ed3c66656ef01d9d105952df491e5',
           '10584793fca13585f164955263086966361ed3c66656ef01d9d105952df491e5',
           '{"accepted_action_types":["hub.message.created","hub.message.edited","hub.reaction.created","lobby.message.created","lobby.message.edited"],"accepted_schema_versions":[1],"required_features":[{"name":"restrictions.active","error_behavior":"HOLD","deadline_ms":100,"maximum_data_handling":"RESTRICTED","configuration":{}}],"capabilities":[],"runtime_error_behavior":"HOLD"}'::jsonb,
           'ACTIVE', '[]'::jsonb, 'polarizer-bootstrap', clock_timestamp(), clock_timestamp()
    FROM bundle
    CROSS JOIN (VALUES ($policy${"rules":[{"id":"block-active-restriction","when":{"operator":"exists","value":{"source":"feature","name":"restrictions.active","path":"0"}},"effects":[{"type":"BLOCK","effect_id":"global-active-restriction","reason_codes":["ACTIVE_RESTRICTION"],"public_reason":"This account or server is restricted."}]}]}$policy$)) AS policy(source)
    RETURNING id, bundle_id
)
UPDATE trust_safety.policy_bundle AS policy_bundle
SET active_version_id = version.id
FROM version
WHERE policy_bundle.id = version.bundle_id;

WITH bundle AS (
    INSERT INTO trust_safety.policy_bundle
        (name, description, scope_type, scope_id, mandatory, priority, created_by)
    VALUES
        ('platform-safety-assessment-review', 'Route high-risk safety assessment changes to review.',
         'PLATFORM', '', TRUE, 5, 'polarizer-bootstrap')
    RETURNING id
), version AS (
    INSERT INTO trust_safety.policy_version
        (bundle_id, version, language, runtime_version, source, compiled_artifact,
         source_sha256, artifact_sha256, manifest, state, validation_diagnostics,
         created_by, validated_at, published_at)
    SELECT id, 1, 'policy-ir-v1', 'policy-ir-v1.0.0', source,
           convert_to(source, 'UTF8'),
           '4b1c866e05e98d720cd4025b0d2038f9743d32c08f7c8fb6b3569995526674d6',
           '4b1c866e05e98d720cd4025b0d2038f9743d32c08f7c8fb6b3569995526674d6',
           '{"accepted_action_types":["safety.assessment.updated"],"accepted_schema_versions":[1],"required_features":[],"capabilities":[],"runtime_error_behavior":"HOLD"}'::jsonb,
           'ACTIVE', '[]'::jsonb, 'polarizer-bootstrap', clock_timestamp(), clock_timestamp()
    FROM bundle
    CROSS JOIN (VALUES ($policy${"rules":[{"id":"route-high-risk-assessment","when":{"operator":"greater_than_or_equal","left":{"source":"action","path":"attributes.score"},"right":{"source":"literal","value":60}},"effects":[{"type":"ROUTE_REVIEW","effect_id":"high-risk-assessment-review","queue":"safety-assessments","priority":25,"reason_codes":["HIGH_RISK_SAFETY_ASSESSMENT"]}]}]}$policy$)) AS policy(source)
    RETURNING id, bundle_id
)
UPDATE trust_safety.policy_bundle AS policy_bundle
SET active_version_id = version.id
FROM version
WHERE policy_bundle.id = version.bundle_id;

WITH bundle AS (
    INSERT INTO trust_safety.policy_bundle
        (name, description, scope_type, scope_id, product, mandatory, priority, created_by)
    VALUES
        ('lobby-default-safety', 'Default Lobby attachment and deterministic content policy.',
         'PRODUCT', '', 'LOBBY', TRUE, 10, 'polarizer-bootstrap')
    RETURNING id
), version AS (
    INSERT INTO trust_safety.policy_version
        (bundle_id, version, language, runtime_version, source, compiled_artifact,
         source_sha256, artifact_sha256, manifest, state, validation_diagnostics,
         created_by, validated_at, published_at)
    SELECT id, 1, 'policy-ir-v1', 'policy-ir-v1.0.0', source,
           convert_to(source, 'UTF8'),
           '1d2de047b13f690fc23f85bdaa35077303a1d4c996598a429078c9b09d75d8a2',
           '1d2de047b13f690fc23f85bdaa35077303a1d4c996598a429078c9b09d75d8a2',
           '{"accepted_action_types":["lobby.message.created","lobby.message.edited"],"accepted_schema_versions":[1],"required_features":[{"name":"automod.matches","error_behavior":"HOLD","deadline_ms":25,"maximum_data_handling":"SENSITIVE","configuration":{"literals":[{"id":"slur-1","pattern":"nigger"},{"id":"slur-2","pattern":"nigga"},{"id":"slur-3","pattern":"faggot"},{"id":"discord-invite","pattern":"discord.gg/"}],"regexes":[],"whitelist_pattern_ids":[]}}],"capabilities":[],"runtime_error_behavior":"HOLD"}'::jsonb,
           'ACTIVE', '[]'::jsonb, 'polarizer-bootstrap', clock_timestamp(), clock_timestamp()
    FROM bundle
    CROSS JOIN (VALUES ($policy${"rules":[{"id":"block-lobby-attachments","when":{"operator":"exists","value":{"source":"action","path":"attributes.attachment_urls.0"}},"effects":[{"type":"BLOCK","effect_id":"lobby-attachments-prohibited","reason_codes":["LOBBY_ATTACHMENTS_PROHIBITED"],"public_reason":"Attachments are not allowed in Lobby messages."}]},{"id":"block-lobby-automod","when":{"operator":"exists","value":{"source":"feature","name":"automod.matches","path":"0"}},"effects":[{"type":"BLOCK","effect_id":"lobby-automod-block","reason_codes":["LOBBY_CONTENT_PROHIBITED"],"public_reason":"This content is not allowed in Lobby messages."}]}]}$policy$)) AS policy(source)
    RETURNING id, bundle_id
)
UPDATE trust_safety.policy_bundle AS policy_bundle
SET active_version_id = version.id
FROM version
WHERE policy_bundle.id = version.bundle_id;

CREATE TABLE trust_safety.provider_configuration (
    name TEXT NOT NULL,
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    data_handling_class TEXT NOT NULL DEFAULT 'SENSITIVE',
    version BIGINT NOT NULL DEFAULT 1,
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (name, scope_type, scope_id)
);

CREATE TABLE trust_safety.provider_version (
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    healthy BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'UNKNOWN',
    checked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (name, version)
);

CREATE TABLE trust_safety.entity_label (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL,
    value JSONB NOT NULL,
    source_policy_version_id UUID REFERENCES trust_safety.policy_version(id),
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (subject_type, subject_id, scope_type, scope_id, label)
);

CREATE TABLE trust_safety.policy_counter (
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    counter_type TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    value BIGINT NOT NULL DEFAULT 0,
    version BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (subject_type, subject_id, scope_type, scope_id, counter_type, window_start),
    CHECK (window_end > window_start)
);
CREATE INDEX policy_counter_expiry_idx ON trust_safety.policy_counter (window_end);

CREATE TABLE trust_safety.safety_observation (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('USER', 'SERVER')),
    subject_id TEXT NOT NULL CHECK (subject_id <> ''),
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    signal_type TEXT NOT NULL CHECK (length(signal_type) BETWEEN 1 AND 100),
    value DOUBLE PRECISION NOT NULL CHECK (value BETWEEN 0 AND 100),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    weight DOUBLE PRECISION NOT NULL CHECK (weight BETWEEN 0 AND 10),
    mitigating BOOLEAN NOT NULL DEFAULT FALSE,
    source_action_id UUID,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ,
    CHECK (expires_at IS NULL OR expires_at > observed_at)
);
CREATE INDEX safety_observation_subject_idx
    ON trust_safety.safety_observation (subject_type, subject_id, scope_type, scope_id, observed_at DESC);

CREATE TABLE trust_safety.safety_assessment (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('USER', 'SERVER')),
    subject_id TEXT NOT NULL CHECK (subject_id <> ''),
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    score DOUBLE PRECISION NOT NULL CHECK (score BETWEEN 0 AND 100),
    tier TEXT NOT NULL CHECK (tier IN ('SAFE', 'LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK')),
    signal_breakdown JSONB NOT NULL CHECK (jsonb_typeof(signal_breakdown) = 'object'),
    algorithm_version TEXT NOT NULL,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    UNIQUE (subject_type, subject_id, scope_type, scope_id)
);

CREATE TABLE trust_safety.safety_flag (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    assessment_id UUID NOT NULL REFERENCES trust_safety.safety_assessment(id),
    reason_codes TEXT[] NOT NULL,
    status trust_safety.resource_status NOT NULL DEFAULT 'PENDING',
    review_item_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    resolved_at TIMESTAMPTZ
);

CREATE TABLE trust_safety.content_hash (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    exact_hash TEXT NOT NULL,
    perceptual_hash TEXT,
    media_type TEXT NOT NULL,
    label TEXT NOT NULL,
    score DOUBLE PRECISION,
    model_version TEXT NOT NULL,
    reviewed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (exact_hash, model_version)
);
CREATE INDEX content_hash_perceptual_idx ON trust_safety.content_hash (perceptual_hash);

CREATE TABLE trust_safety.nsfw_override (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    exact_hash TEXT,
    perceptual_hash TEXT,
    classification TEXT NOT NULL CHECK (classification IN ('SAFE', 'UNSAFE')),
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1,
    CHECK (exact_hash IS NOT NULL OR perceptual_hash IS NOT NULL),
    CHECK (exact_hash IS NULL OR exact_hash ~ '^[0-9a-f]{64}$'),
    CHECK (perceptual_hash IS NULL OR length(perceptual_hash) BETWEEN 1 AND 512),
    CHECK (length(reason) BETWEEN 1 AND 2000)
);
CREATE UNIQUE INDEX nsfw_override_exact_hash_unique
    ON trust_safety.nsfw_override (exact_hash) WHERE exact_hash IS NOT NULL;
CREATE UNIQUE INDEX nsfw_override_perceptual_hash_unique
    ON trust_safety.nsfw_override (perceptual_hash) WHERE perceptual_hash IS NOT NULL;

CREATE TABLE trust_safety.action_inbox (
    action_id UUID PRIMARY KEY,
    action_type TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    subject_type TEXT,
    subject_id TEXT,
    partition_key TEXT NOT NULL,
    action_ciphertext BYTEA NOT NULL,
    prism_payload_ciphertext BYTEA,
    encryption_key_id TEXT NOT NULL,
    state trust_safety.message_state NOT NULL DEFAULT 'PENDING_MODERATION',
    hold_until TIMESTAMPTZ,
    resolved_by TEXT,
    resolution_reason TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    processed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_error_code TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    version BIGINT NOT NULL DEFAULT 1
);
CREATE INDEX action_inbox_state_idx ON trust_safety.action_inbox (state, hold_until, received_at);
CREATE INDEX action_inbox_subject_idx ON trust_safety.action_inbox (subject_type, subject_id, received_at DESC);
ALTER TABLE trust_safety.restriction
    ADD CONSTRAINT restriction_source_action_fk
    FOREIGN KEY (source_action_id) REFERENCES trust_safety.action_inbox(action_id);
ALTER TABLE trust_safety.infraction
    ADD CONSTRAINT infraction_source_action_fk
    FOREIGN KEY (source_action_id) REFERENCES trust_safety.action_inbox(action_id);
ALTER TABLE trust_safety.safety_observation
    ADD CONSTRAINT safety_observation_source_action_fk
    FOREIGN KEY (source_action_id) REFERENCES trust_safety.action_inbox(action_id);

CREATE TABLE trust_safety.decision_record (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    action_id UUID NOT NULL UNIQUE REFERENCES trust_safety.action_inbox(action_id),
    decision trust_safety.decision NOT NULL,
    reason_codes TEXT[] NOT NULL DEFAULT '{}',
    effects JSONB NOT NULL,
    policy_versions JSONB NOT NULL,
    provider_versions JSONB NOT NULL,
    shadow BOOLEAN NOT NULL DEFAULT FALSE,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE trust_safety.execution_trace (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    action_id UUID NOT NULL,
    decision_id UUID REFERENCES trust_safety.decision_record(id),
    trace JSONB NOT NULL,
    final_decision trust_safety.decision NOT NULL,
    sampled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX execution_trace_action_idx ON trust_safety.execution_trace (action_id, created_at DESC);

CREATE TABLE trust_safety.shadow_result (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    action_id UUID NOT NULL,
    bundle_id UUID NOT NULL REFERENCES trust_safety.policy_bundle(id),
    active_decision_id UUID REFERENCES trust_safety.decision_record(id),
    shadow_policy_version_id UUID NOT NULL REFERENCES trust_safety.policy_version(id),
    shadow_decision trust_safety.decision NOT NULL,
    effect_differences JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX shadow_result_bundle_idx ON trust_safety.shadow_result (bundle_id, created_at DESC);

CREATE TABLE trust_safety.review_item (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    queue TEXT NOT NULL,
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    status trust_safety.resource_status NOT NULL DEFAULT 'PENDING',
    reason_codes TEXT[] NOT NULL DEFAULT '{}',
    decision_id UUID REFERENCES trust_safety.decision_record(id),
    assigned_to TEXT,
    resolved_by TEXT,
    resolution TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1
);
ALTER TABLE trust_safety.safety_flag
    ADD CONSTRAINT safety_flag_review_item_fk
    FOREIGN KEY (review_item_id) REFERENCES trust_safety.review_item(id);
CREATE INDEX review_item_queue_idx
    ON trust_safety.review_item (queue, scope_type, scope_id, status, priority, created_at);

CREATE TABLE trust_safety.processed_command (
    command_id UUID PRIMARY KEY,
    decision_id UUID NOT NULL REFERENCES trust_safety.decision_record(id),
    command_type TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'CLAIMED', 'COMPLETED', 'RECOVERY_REQUIRED')),
    retry_safe BOOLEAN NOT NULL,
    claimant_id TEXT,
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    claimed_at TIMESTAMPTZ,
    processed_at TIMESTAMPTZ,
    success BOOLEAN,
    result_code TEXT,
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        (status = 'PENDING' AND claimant_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
        OR (status = 'CLAIMED' AND claimant_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR status IN ('COMPLETED', 'RECOVERY_REQUIRED')
    ),
    CHECK ((status = 'COMPLETED') = (processed_at IS NOT NULL)),
    CHECK ((status = 'COMPLETED') = (success IS NOT NULL)),
    CHECK ((status = 'COMPLETED') = (result_code IS NOT NULL))
);
CREATE INDEX processed_command_lease_idx
    ON trust_safety.processed_command (status, lease_expires_at);

CREATE TABLE trust_safety.mutation_idempotency (
    service_principal TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    operation TEXT NOT NULL,
    resource_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (service_principal, actor_id, idempotency_key)
);

CREATE TABLE trust_safety.outbox (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    aggregate_type TEXT NOT NULL,
    aggregate_id UUID NOT NULL,
    topic TEXT NOT NULL,
    partition_key TEXT NOT NULL,
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload BYTEA NOT NULL,
    status trust_safety.outbox_status NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        (status = 'CLAIMED' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (status <> 'CLAIMED' AND lease_token IS NULL AND lease_expires_at IS NULL)
    )
);
CREATE INDEX outbox_relay_idx
    ON trust_safety.outbox (status, available_at, lease_expires_at, created_at);

CREATE TABLE trust_safety.audit_log (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    request_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    scope_type trust_safety.scope_type,
    scope_id TEXT,
    before_state JSONB,
    after_state JSONB,
    trace_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX audit_log_resource_idx ON trust_safety.audit_log (resource_type, resource_id, created_at DESC);

CREATE FUNCTION trust_safety.reject_immutable_policy_version_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state <> 'DRAFT' THEN
        RAISE EXCEPTION 'published policy versions are immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER policy_version_immutable
BEFORE UPDATE OF language, runtime_version, source, compiled_artifact, source_sha256, artifact_sha256, manifest
ON trust_safety.policy_version
FOR EACH ROW EXECUTE FUNCTION trust_safety.reject_immutable_policy_version_change();

-- Safe bootstrap only: exercise local Hub attachment classification and record
-- shadow comparisons. This policy cannot block, hold, or censor. Threshold-based
-- enforcement must be published separately after the labeled golden-set gate.
INSERT INTO trust_safety.policy_bundle (
    id,
    name,
    description,
    scope_type,
    scope_id,
    product,
    mandatory,
    priority,
    state,
    shadow_version_id,
    created_by
) VALUES (
    '019f61a0-0000-7000-8000-000000000001',
    'bootstrap-hub-nsfw-shadow',
    'Non-enforcing Hub media classifier shadow policy',
    'PRODUCT',
    '',
    'HUB',
    FALSE,
    100,
    'ACTIVE',
    NULL,
    'system:bootstrap'
);

INSERT INTO trust_safety.policy_version (
    id,
    bundle_id,
    version,
    language,
    runtime_version,
    source,
    compiled_artifact,
    source_sha256,
    artifact_sha256,
    manifest,
    state,
    validation_diagnostics,
    created_by,
    validated_at,
    published_at
) VALUES (
    '019f61a0-0000-7000-8000-000000000002',
    '019f61a0-0000-7000-8000-000000000001',
    1,
    'policy-ir-v1',
    'policy-ir-v1.0.0',
    $policy${"rules":[{"id":"shadow-hub-nsfw-review","when":{"operator":"exists","value":{"source":"feature","name":"media.nsfw","path":"0"}},"effects":[{"type":"ROUTE_REVIEW","effect_id":"hub-nsfw-shadow-review","queue":"nsfw-media","priority":50,"reason_codes":["NSFW_MEDIA_SHADOW_MATCH"]}]}]}$policy$,
    convert_to($policy${"rules":[{"id":"shadow-hub-nsfw-review","when":{"operator":"exists","value":{"source":"feature","name":"media.nsfw","path":"0"}},"effects":[{"type":"ROUTE_REVIEW","effect_id":"hub-nsfw-shadow-review","queue":"nsfw-media","priority":50,"reason_codes":["NSFW_MEDIA_SHADOW_MATCH"]}]}]}$policy$, 'UTF8'),
    '050b1402119333a6748a8f00579cd89d20c1105bfd3bf16ed4c9d6de568c0f98',
    '050b1402119333a6748a8f00579cd89d20c1105bfd3bf16ed4c9d6de568c0f98',
    '{"accepted_action_types":["hub.message.created","hub.message.edited"],"accepted_schema_versions":[1],"required_features":[{"name":"media.nsfw","error_behavior":"CONTINUE","deadline_ms":1000,"maximum_data_handling":"SENSITIVE","configuration":{}}],"capabilities":["ROUTE_REVIEW"],"runtime_error_behavior":"CONTINUE"}'::jsonb,
    'SHADOW',
    '[]'::jsonb,
    'system:bootstrap',
    clock_timestamp(),
    clock_timestamp()
);

UPDATE trust_safety.policy_bundle
SET shadow_version_id = '019f61a0-0000-7000-8000-000000000002',
    updated_at = clock_timestamp()
WHERE id = '019f61a0-0000-7000-8000-000000000001';

INSERT INTO trust_safety.policy_activation (
    id,
    bundle_id,
    from_version_id,
    to_version_id,
    activation_type,
    activated_by
) VALUES (
    '019f61a0-0000-7000-8000-000000000003',
    '019f61a0-0000-7000-8000-000000000001',
    NULL,
    '019f61a0-0000-7000-8000-000000000002',
    'SHADOW_START',
    'system:bootstrap'
);

INSERT INTO trust_safety.audit_log (
    request_id,
    actor_id,
    actor_type,
    action,
    resource_type,
    resource_id,
    scope_type,
    scope_id,
    after_state
) VALUES (
    'bootstrap-hub-nsfw-shadow',
    'system:bootstrap',
    'SERVICE',
    'SHADOW_START',
    'POLICY_BUNDLE',
    '019f61a0-0000-7000-8000-000000000001',
    'PRODUCT',
    '',
    '{"mandatory":false,"state":"ACTIVE","mode":"SHADOW","product":"HUB","enforcement":false}'::jsonb
);
