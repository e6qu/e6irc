-- Support the prune-on-write DELETEs added for device_grants and web_sessions
-- (both delete WHERE expires_at <= now() on each insert) with an index on
-- expires_at, and drop the redundant device_grants(user_code) index — the
-- UNIQUE constraint from migration 0009 already provides one.

CREATE INDEX device_grants_expires_at_idx ON device_grants (expires_at);
CREATE INDEX web_sessions_expires_at_idx ON web_sessions (expires_at);
DROP INDEX device_grants_user_code_idx;
