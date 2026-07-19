-- Server bans (oper K-lines, DESIGN §7.6/§15): a user@host glob mask is
-- refused at registration and matching sessions are disconnected.
CREATE TABLE server_bans (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mask TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    set_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
