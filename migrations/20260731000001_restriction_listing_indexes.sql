-- Staff blacklist records are listed by scope, type, and creation order.
-- The enforcement index starts with subject identity and cannot support this
-- global ledger query efficiently.
CREATE INDEX restriction_blacklist_list_idx
    ON trust_safety.restriction (scope_type, scope_id, created_at DESC, id DESC)
    WHERE restriction_type = 'BLACKLIST';

CREATE INDEX restriction_blacklist_moderator_list_idx
    ON trust_safety.restriction (scope_type, scope_id, created_by, created_at DESC, id DESC)
    WHERE restriction_type = 'BLACKLIST';

CREATE INDEX restriction_blacklist_expiry_list_idx
    ON trust_safety.restriction (
        scope_type,
        scope_id,
        (expires_at IS NULL),
        expires_at ASC,
        id ASC
    )
    WHERE restriction_type = 'BLACKLIST';
