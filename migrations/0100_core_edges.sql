-- The roster of edges (DESIGN §19.3): every edge a serving core has linked,
-- the slot that forms the top bits of every connection identifier the edge
-- allocates (DESIGN §19.2), and the serving-lease epoch it last linked under.
-- A core writes a row when an edge links and when its link ends; nothing is
-- written per session or per event, so the database-outage hold (DESIGN
-- §19.7) never makes a client's line depend on the database.
--
-- The slot is the core's to assign and the edge's to keep: an edge that links
-- again, to this core or the next, is given the slot it had, so the
-- identifiers it allocates never collide with another edge's.
CREATE TABLE core_edges (
    edge TEXT PRIMARY KEY CHECK (edge ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    slot INTEGER NOT NULL UNIQUE CHECK (slot BETWEEN 1 AND 16383),
    last_epoch BIGINT NOT NULL CHECK (last_epoch >= 0),
    linked_at TIMESTAMPTZ NOT NULL,
    unlinked_at TIMESTAMPTZ
);
