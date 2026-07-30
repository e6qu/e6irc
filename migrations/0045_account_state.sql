-- Durable account lifecycle and administrator authority. A closed bit set
-- prevents unknown persisted states from being silently reinterpreted.

ALTER TABLE accounts
    ADD COLUMN flags BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT accounts_flags_known CHECK (flags BETWEEN 0 AND 3);

CREATE INDEX accounts_admin_idx
    ON accounts (id)
    WHERE (flags & 1) = 1;
