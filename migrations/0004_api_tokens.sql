-- Personal access tokens for the REST API (DESIGN §9.4). Hash-only at
-- rest, like web sessions; scopes arrive with the endpoints that need
-- distinctions.

CREATE TABLE api_tokens (
    token_hash BYTEA PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX api_tokens_account_idx ON api_tokens (account_id);
