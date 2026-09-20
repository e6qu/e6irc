-- An app password is 32 random bytes, so a SHA-256 of it identifies its row
-- without weakening it (personal access tokens and browser sessions are looked
-- up the same way). With the lookup, verifying a login computes Argon2 for the
-- one row the presented secret names, instead of for every app password the
-- account holds (up to 32, all under one permit of the process-wide pool).
--
-- An app password without a lookup cannot exist: it would have to be tried
-- blind on every attempt, which is the cost this migration removes. The secrets
-- of app passwords minted before it were never stored, so their lookups cannot
-- be computed here; those rows are revoked, each with an audit record naming
-- this migration as the actor, and their owners mint new ones. There are no
-- deployed users holding any.
INSERT INTO audit_log (actor, action, target, detail)
SELECT 'migration:0059', 'ACCOUNT_APP_PASSWORD_REVOKE', a.name,
       'app password revoked: minted before app passwords were found by lookup'
FROM account_credentials c
JOIN accounts a ON a.id = c.account_id
WHERE c.kind = 'app_password';

DELETE FROM account_credentials WHERE kind = 'app_password';

ALTER TABLE account_credentials ADD COLUMN secret_lookup BYTEA;

-- Exactly the app passwords carry one: never a primary password, always an app
-- password.
ALTER TABLE account_credentials
    ADD CONSTRAINT account_credentials_lookup_names_app_passwords
    CHECK ((kind = 'app_password') = (secret_lookup IS NOT NULL));

CREATE UNIQUE INDEX account_credentials_secret_lookup_idx
    ON account_credentials (secret_lookup)
    WHERE secret_lookup IS NOT NULL;
