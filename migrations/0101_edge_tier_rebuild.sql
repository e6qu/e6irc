-- The graceful rebuild (DESIGN §19.3).
--
-- The roster names the cut each edge holds: a stopping core writes it when
-- it cuts, the next core waits for the edges it names (at most 30 seconds,
-- D12) and clears it once it has rebuilt their sessions. An edge presents
-- the cut it holds in its `Hello`, so the roster only says whom to wait for;
-- it never decides what an edge holds.
ALTER TABLE core_edges ADD COLUMN last_cut BIGINT CHECK (last_cut <> 0);

-- The body format the cores write for their edges to hold (D11): a release
-- reads its own format and the one before, and keeps writing the one before
-- until the operator runs `e6ircd records advance`, so a one-release rollback
-- never meets a body it cannot read. One row, announced when it changes, so
-- a serving core writes the new format from the moment it is advanced.
CREATE TABLE record_format (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    written SMALLINT NOT NULL CHECK (written > 0),
    advanced_at TIMESTAMPTZ
);
INSERT INTO record_format (written) VALUES (1);

CREATE FUNCTION announce_record_format() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('e6irc_record_format', NEW.written::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER record_format_announced
    AFTER UPDATE ON record_format
    FOR EACH ROW EXECUTE FUNCTION announce_record_format();
