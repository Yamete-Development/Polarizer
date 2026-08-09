-- Interactive staff history covers Hub/Lobby warnings and product-level Lobby
-- bans. Keep the filtered working set small and support its common cursor,
-- target, moderator, and expiry access paths.
CREATE INDEX infraction_staff_records_list_idx
    ON trust_safety.infraction (created_at DESC, id DESC)
    WHERE infraction_type = 'WARNING'
       OR (infraction_type = 'BAN' AND scope_type = 'PRODUCT');

CREATE INDEX infraction_staff_records_subject_idx
    ON trust_safety.infraction (subject_type, subject_id, created_at DESC, id DESC)
    WHERE infraction_type = 'WARNING'
       OR (infraction_type = 'BAN' AND scope_type = 'PRODUCT');

CREATE INDEX infraction_staff_records_moderator_idx
    ON trust_safety.infraction (created_by, created_at DESC, id DESC)
    WHERE infraction_type = 'WARNING'
       OR (infraction_type = 'BAN' AND scope_type = 'PRODUCT');

CREATE INDEX infraction_staff_records_expiry_idx
    ON trust_safety.infraction ((expires_at IS NULL), expires_at ASC, id ASC)
    WHERE infraction_type = 'WARNING'
       OR (infraction_type = 'BAN' AND scope_type = 'PRODUCT');
