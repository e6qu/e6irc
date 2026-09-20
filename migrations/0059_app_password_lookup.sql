-- An app password is 32 random bytes, so a SHA-256 of it identifies its row
-- without weakening it (personal access tokens and browser sessions are looked
-- up the same way). With the lookup, verifying a login computes Argon2 for the
-- one row the presented secret names, instead of for every app password the
-- account holds (up to 32, all under one permit of the process-wide pool).
--
-- Rows minted before this migration have no lookup: their secrets were never
-- stored, so it cannot be computed here. They are still verified, by trying
-- each, and gain their lookup the first time they are used.
ALTER TABLE account_credentials ADD COLUMN secret_lookup BYTEA;

ALTER TABLE account_credentials
    ADD CONSTRAINT account_credentials_lookup_is_for_app_passwords
    CHECK (secret_lookup IS NULL OR kind = 'app_password');

CREATE UNIQUE INDEX account_credentials_secret_lookup_idx
    ON account_credentials (secret_lookup)
    WHERE secret_lookup IS NOT NULL;
