-- An account has one primary password. App passwords remain independently
-- repeatable, but a second local password would make rotation ambiguous.
CREATE UNIQUE INDEX account_credentials_one_local_password
    ON account_credentials (account_id)
    WHERE kind = 'local_password';
