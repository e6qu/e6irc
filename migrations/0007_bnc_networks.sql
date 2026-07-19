-- Per-account BNC networks (DESIGN §10.3, §15): a user's own always-on
-- upstream connections, managed at runtime rather than in server config.
-- The upstream SASL password is stored sealed (enc:v1:, §15); the server
-- decrypts it with the master key when starting the driver.

CREATE TABLE bnc_networks (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    -- Selector the owner uses as the /network suffix (unique per owner).
    name TEXT NOT NULL,
    addr TEXT NOT NULL,
    tls BOOLEAN NOT NULL DEFAULT false,
    nick TEXT NOT NULL,
    realname TEXT,
    autojoin TEXT[] NOT NULL DEFAULT '{}',
    sasl_account TEXT,
    -- Sealed (enc:v1:) upstream SASL password, or NULL for no upstream auth.
    sasl_password_sealed TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id, name)
);

CREATE INDEX bnc_networks_account_idx ON bnc_networks (account_id);
