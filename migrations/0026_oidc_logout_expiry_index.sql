-- `consume_oidc_backchannel_logout` prunes on every write
-- (`DELETE FROM oidc_logout_tokens WHERE expires_at <= now()`), but the table
-- (migration 0020) has only a `(issuer, jti)` primary key, so each prune is a
-- full sequential scan and the table grows with logout volume. Index
-- `expires_at`, exactly as migration 0021 did for the other prune-on-write
-- tables (device_grants, web_sessions), which this one was left out of.

CREATE INDEX oidc_logout_tokens_expires_at_idx ON oidc_logout_tokens (expires_at);
