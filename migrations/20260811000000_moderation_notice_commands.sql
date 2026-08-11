-- Moderation notices may originate from a manual infraction/restriction
-- mutation, which has no policy decision record. Keep the relationship when
-- present, but do not invent a synthetic decision just to deliver feedback.
ALTER TABLE trust_safety.processed_command
    ALTER COLUMN decision_id DROP NOT NULL;

COMMENT ON COLUMN trust_safety.processed_command.decision_id IS
    'The originating policy decision, when the command was produced by policy evaluation.';
