-- Persisted BNC detached-buffer lines (DESIGN §10.4): each upstream line
-- a network driver receives is appended here so a client attaching after
-- a server restart still replays recent backlog. Keyed by the owning
-- account (`*` for a shared/server-level network) and the network name.

CREATE TABLE bnc_buffer (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner TEXT NOT NULL,
    network TEXT NOT NULL,
    line TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX bnc_buffer_lookup_idx ON bnc_buffer (owner, network, id);
