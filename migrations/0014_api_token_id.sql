-- Give PATs a stable integer id so the owner can list and revoke them by
-- reference (DESIGN §9.4). The token_hash stays the PK; id is a surrogate.
ALTER TABLE api_tokens
    ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE;
