-- Registered channels (DESIGN §8): founder-owned, minimal for now;
-- access flags and mlock arrive with the fuller ChanServ surface.

CREATE TABLE channels (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL,
    name_folded TEXT NOT NULL UNIQUE,
    founder_account_id BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
