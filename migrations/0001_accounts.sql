-- Accounts and their credentials (DESIGN §8, §9.1).

CREATE TABLE accounts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Display casing as registered.
    name TEXT NOT NULL,
    -- rfc1459-casefolded, the lookup key.
    name_folded TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE account_credentials (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('local_password', 'app_password')),
    argon2_hash TEXT NOT NULL,
    -- User-facing label for app passwords ("laptop weechat").
    label TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX account_credentials_account_idx
    ON account_credentials (account_id);
