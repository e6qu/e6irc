-- Bounded maintenance selects the oldest expired rows before deleting them.
-- These indexes keep each fixed-size batch proportional to the batch rather
-- than to the lifetime size of the table.

CREATE INDEX messages_ts_id_idx
    ON messages (ts, id);

CREATE INDEX audit_log_created_at_id_idx
    ON audit_log (created_at, id);

CREATE INDEX api_tokens_expires_at_idx
    ON api_tokens (expires_at)
    WHERE expires_at IS NOT NULL;
