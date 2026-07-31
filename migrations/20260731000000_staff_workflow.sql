-- Moderation workflow state only. Staff identity and authorization live in Iris.

CREATE TABLE trust_safety.staff_action_request (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    action_type TEXT NOT NULL CHECK (action_type IN ('LOBBY_BAN', 'GLOBAL_BLACKLIST')),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('USER', 'SERVER')),
    subject_id TEXT NOT NULL CHECK (subject_id <> ''),
    scope_type trust_safety.scope_type NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    report_id UUID REFERENCES trust_safety.report(id) ON DELETE RESTRICT,
    requested_reason TEXT NOT NULL CHECK (length(requested_reason) BETWEEN 1 AND 2000),
    requested_expires_at TIMESTAMPTZ,
    requested_by TEXT NOT NULL CHECK (requested_by <> ''),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'REJECTED', 'EXPIRED', 'EXECUTED', 'CANCELLED')),
    decided_by TEXT,
    decision_reason TEXT,
    decided_at TIMESTAMPTZ,
    executed_infraction_id UUID REFERENCES trust_safety.infraction(id) ON DELETE RESTRICT,
    executed_restriction_id UUID REFERENCES trust_safety.restriction(id) ON DELETE RESTRICT,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + interval '24 hours'),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (expires_at > requested_at),
    CHECK (decided_by IS NULL OR decided_by <> requested_by),
    CHECK (
        (status = 'PENDING' AND decided_by IS NULL AND decision_reason IS NULL AND decided_at IS NULL)
        OR status <> 'PENDING'
    )
);
CREATE UNIQUE INDEX staff_action_request_pending_unique
    ON trust_safety.staff_action_request (action_type, subject_type, subject_id, scope_type, scope_id)
    WHERE status = 'PENDING';
CREATE INDEX staff_action_request_queue_idx
    ON trust_safety.staff_action_request (status, expires_at, requested_at);
CREATE INDEX staff_action_request_report_idx
    ON trust_safety.staff_action_request (report_id, status) WHERE report_id IS NOT NULL;

ALTER TABLE trust_safety.report
    ADD COLUMN claimed_by TEXT,
    ADD COLUMN claimed_at TIMESTAMPTZ,
    ADD COLUMN claim_expires_at TIMESTAMPTZ,
    ADD COLUMN last_claim_change_at TIMESTAMPTZ,
    ADD CONSTRAINT report_claim_consistent CHECK (
        (claimed_by IS NULL AND claimed_at IS NULL AND claim_expires_at IS NULL)
        OR (claimed_by IS NOT NULL AND claimed_at IS NOT NULL AND claim_expires_at IS NOT NULL)
    ),
    ADD CONSTRAINT report_claim_expiry CHECK (
        claim_expires_at IS NULL OR claim_expires_at > claimed_at
    );
CREATE INDEX report_claim_owner_idx
    ON trust_safety.report (claimed_by, claim_expires_at)
    WHERE claimed_by IS NOT NULL;

ALTER TABLE trust_safety.infraction
    ADD COLUMN source_report_id UUID REFERENCES trust_safety.report(id) ON DELETE RESTRICT;
CREATE INDEX infraction_source_report_idx
    ON trust_safety.infraction (source_report_id) WHERE source_report_id IS NOT NULL;

ALTER TABLE trust_safety.restriction
    ADD COLUMN source_report_id UUID REFERENCES trust_safety.report(id) ON DELETE RESTRICT;
CREATE INDEX restriction_source_report_idx
    ON trust_safety.restriction (source_report_id) WHERE source_report_id IS NOT NULL;

ALTER TABLE trust_safety.audit_log
    ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object');

CREATE FUNCTION trust_safety.reject_audit_log_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'trust_safety.audit_log is append-only';
END
$$;

CREATE TRIGGER audit_log_immutable
BEFORE UPDATE OR DELETE ON trust_safety.audit_log
FOR EACH ROW EXECUTE FUNCTION trust_safety.reject_audit_log_change();
