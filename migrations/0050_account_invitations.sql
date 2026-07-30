-- Administrator-issued, single-use account invitations. Only a SHA-256
-- digest is stored; the bearer secret is returned once to the administrator.

CREATE TABLE account_invitations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE,
    account_name TEXT NOT NULL,
    name_folded TEXT NOT NULL,
    contact_email TEXT,
    administrator BOOLEAN NOT NULL DEFAULT false,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    accepted_account_id BIGINT REFERENCES accounts (id) ON DELETE SET NULL,
    CONSTRAINT account_invitations_name_shape CHECK (
        octet_length(account_name) BETWEEN 1 AND 64
        AND octet_length(name_folded) BETWEEN 1 AND 64
    ),
    CONSTRAINT account_invitations_contact_email_shape CHECK (
        contact_email IS NULL
        OR (
            octet_length(contact_email) BETWEEN 3 AND 254
            AND contact_email !~ '[[:cntrl:][:space:]]'
        )
    ),
    CONSTRAINT account_invitations_lifetime CHECK (
        expires_at > created_at
        AND expires_at <= created_at + interval '30 days'
    )
);

CREATE UNIQUE INDEX account_invitations_pending_name_idx
    ON account_invitations (name_folded)
    WHERE consumed_at IS NULL;

CREATE INDEX account_invitations_pending_expiry_idx
    ON account_invitations (expires_at, id)
    WHERE consumed_at IS NULL;
