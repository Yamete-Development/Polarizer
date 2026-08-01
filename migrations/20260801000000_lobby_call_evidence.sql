-- Durable, append-only evidence timeline for Lobby calls. The encrypted source
-- payload remains in action_inbox; these rows provide stable ordering and
-- report-scoped retention without duplicating sensitive plaintext.
CREATE TABLE trust_safety.call_evidence_archive (
    lobby_id TEXT PRIMARY KEY,
    last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE trust_safety.call_evidence_event (
    lobby_id TEXT NOT NULL REFERENCES trust_safety.call_evidence_archive(lobby_id) ON DELETE RESTRICT,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    action_id UUID NOT NULL UNIQUE REFERENCES trust_safety.action_inbox(action_id) ON DELETE RESTRICT,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('USER_MESSAGE', 'SYSTEM_EVENT')),
    occurred_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (lobby_id, sequence)
);
CREATE INDEX call_evidence_event_timeline_idx
    ON trust_safety.call_evidence_event (lobby_id, sequence);

CREATE TABLE trust_safety.report_evidence_snapshot (
    report_id UUID PRIMARY KEY REFERENCES trust_safety.report(id) ON DELETE RESTRICT,
    lobby_id TEXT NOT NULL REFERENCES trust_safety.call_evidence_archive(lobby_id) ON DELETE RESTRICT,
    first_sequence BIGINT NOT NULL CHECK (first_sequence > 0),
    last_sequence BIGINT NOT NULL CHECK (last_sequence >= first_sequence),
    entry_count BIGINT NOT NULL CHECK (entry_count > 0),
    terminal_action_id UUID NOT NULL REFERENCES trust_safety.call_evidence_event(action_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX report_evidence_snapshot_archive_idx
    ON trust_safety.report_evidence_snapshot (lobby_id, last_sequence);

COMMENT ON TABLE trust_safety.call_evidence_event IS
    'Append-only Lobby evidence ordering; content is encrypted in action_inbox.';
COMMENT ON TABLE trust_safety.report_evidence_snapshot IS
    'Immutable call evidence prefix pinned to a moderation report.';
