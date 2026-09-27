-- A device code is a bearer secret: whoever holds it collects the token its
-- grant mints. It was stored and compared in plaintext while every other
-- bearer (browser sessions, personal access tokens, logout tokens) keeps only
-- its SHA-256, so a read of this table handed out every pending approval. It
-- now keeps the same digest, which the server computes the same way
-- (`token_hash`: the raw 32-byte SHA-256 of the code's UTF-8 bytes).
--
-- Existing grants are hashed in place rather than dropped: `sha256()` is built
-- in since PostgreSQL 11, so no pending approval is lost to the upgrade.
ALTER TABLE device_grants ADD COLUMN device_code_hash BYTEA;
UPDATE device_grants SET device_code_hash = sha256(convert_to(device_code, 'UTF8'));
ALTER TABLE device_grants
    ALTER COLUMN device_code_hash SET NOT NULL,
    DROP COLUMN device_code,
    ADD CONSTRAINT device_grants_device_code_hash_key UNIQUE (device_code_hash);

-- RFC 8628 binds a grant to the client that started it (§3.4 `client_id`)
-- and paces each device code's polling (§3.5): a poll sooner than the grant's
-- interval is answered `slow_down` and the interval grows by five seconds.
-- Grants started before this migration name no client; they are the e6irc
-- command-line client's, which starts every grant as `e6irc-cli`.
ALTER TABLE device_grants
    ADD COLUMN client_id TEXT NOT NULL DEFAULT 'e6irc-cli'
        CHECK (octet_length(client_id) BETWEEN 1 AND 64),
    ADD COLUMN poll_interval_seconds INTEGER NOT NULL DEFAULT 5
        CHECK (poll_interval_seconds BETWEEN 1 AND 600),
    ADD COLUMN last_polled_at TIMESTAMPTZ;
ALTER TABLE device_grants ALTER COLUMN client_id DROP DEFAULT;
