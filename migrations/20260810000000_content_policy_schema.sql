-- Native, relational content policies used by the content_policy model.
-- Rules, patterns, surfaces, and actions are separate rows so a policy can
-- be loaded with joins instead of an opaque policy document or N+1 queries.

CREATE TYPE trust_safety.content_policy_authority AS ENUM (
    'GLOBAL', 'HUB', 'SERVER'
);

CREATE TYPE trust_safety.content_policy_surface AS ENUM (
    'MESSAGE_CONTENT', 'DISPLAY_NAME', 'USERNAME', 'SERVER_NAME', 'HUB_NAME', 'URL_DOMAIN'
);

CREATE TYPE trust_safety.content_policy_pattern_type AS ENUM (
    'EXACT_WORD', 'PREFIX', 'SUFFIX', 'CONTAINS', 'PHRASE'
);

CREATE TYPE trust_safety.content_policy_action_type AS ENUM (
    'ALLOW',
    'BLOCK',
    'CENSOR_MATCH',
    'STRIP_LINK',
    'SUPPRESS_LINKS',
    'REPLACE_NAME',
    'LOG',
    'LOBBY_WARN',
    'LOBBY_BAN',
    'BLACKLIST',
    'HUB_WARN',
    'HUB_MUTE',
    'HUB_BAN'
);

CREATE TABLE trust_safety.content_policy (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    authority trust_safety.content_policy_authority NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by TEXT NOT NULL CHECK (btrim(created_by) <> ''),
    updated_by TEXT NOT NULL CHECK (btrim(updated_by) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (authority, scope_id),
    CHECK (
        (authority = 'GLOBAL' AND scope_id = '')
        OR (authority IN ('HUB', 'SERVER') AND btrim(scope_id) <> '')
    )
);

CREATE TABLE trust_safety.content_policy_rule (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    policy_id UUID NOT NULL REFERENCES trust_safety.content_policy(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    custom_reason TEXT CHECK (custom_reason IS NULL OR length(custom_reason) <= 500),
    created_by TEXT NOT NULL CHECK (btrim(created_by) <> ''),
    updated_by TEXT NOT NULL CHECK (btrim(updated_by) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (policy_id, name)
);

CREATE TABLE trust_safety.content_rule_pattern (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    rule_id UUID NOT NULL REFERENCES trust_safety.content_policy_rule(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL CHECK (length(pattern) BETWEEN 1 AND 100),
    normalized_pattern TEXT NOT NULL CHECK (length(normalized_pattern) BETWEEN 1 AND 100),
    pattern_type trust_safety.content_policy_pattern_type NOT NULL,
    UNIQUE (rule_id, pattern_type, normalized_pattern)
);

CREATE TABLE trust_safety.content_rule_surface (
    rule_id UUID NOT NULL REFERENCES trust_safety.content_policy_rule(id) ON DELETE CASCADE,
    surface trust_safety.content_policy_surface NOT NULL,
    PRIMARY KEY (rule_id, surface)
);

CREATE TABLE trust_safety.content_rule_action (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    rule_id UUID NOT NULL REFERENCES trust_safety.content_policy_rule(id) ON DELETE CASCADE,
    action_type trust_safety.content_policy_action_type NOT NULL,
    duration_seconds BIGINT,
    replacement TEXT,
    CHECK (
        (
            action_type IN ('LOBBY_BAN', 'BLACKLIST', 'HUB_MUTE')
            AND duration_seconds IS NOT NULL
            AND duration_seconds > 0
        )
        OR (
            action_type NOT IN ('LOBBY_BAN', 'BLACKLIST', 'HUB_MUTE')
            AND duration_seconds IS NULL
        )
    ),
    CHECK (
        replacement IS NULL
        OR (
            action_type = 'REPLACE_NAME'
            AND length(replacement) BETWEEN 1 AND 100
        )
    ),
    UNIQUE (rule_id, action_type)
);

-- The application increments policy.version whenever any policy content
-- changes. Reject stale or repeated versions at the database boundary.
CREATE FUNCTION trust_safety.enforce_content_policy_monotonic_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.version <= OLD.version THEN
        RAISE EXCEPTION 'content policy version must increase (old %, new %)', OLD.version, NEW.version;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER policy_version_monotonic
    BEFORE UPDATE OF version ON trust_safety.content_policy
    FOR EACH ROW
    EXECUTE FUNCTION trust_safety.enforce_content_policy_monotonic_version();

CREATE INDEX policy_rule_active_idx
    ON trust_safety.content_policy_rule (policy_id, id)
    WHERE enabled;

CREATE INDEX rule_pattern_rule_idx
    ON trust_safety.content_rule_pattern (rule_id, pattern_type, id);

CREATE INDEX rule_pattern_match_idx
    ON trust_safety.content_rule_pattern (pattern_type, normalized_pattern, rule_id);

CREATE INDEX rule_surface_surface_idx
    ON trust_safety.content_rule_surface (surface, rule_id);

CREATE INDEX rule_action_rule_idx
    ON trust_safety.content_rule_action (rule_id, action_type, id);

CREATE INDEX rule_action_type_idx
    ON trust_safety.content_rule_action (action_type, rule_id);
