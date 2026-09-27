-- A bouncer backlog line is read in the state it was said in: an attaching
-- client is first brought to the session's nick as of the oldest line it is
-- replayed (DESIGN §10.1), so a line said under an old nick reads as its own
-- and the rename as its own rename. The in-memory ring follows that state as it
-- evicts; a backlog restored from this table after a restart had nothing to
-- start from, so its replay began at the current nick.
--
-- `own_nick` is the session's own nick when the line was said (before the line
-- itself, for the rename that a NICK line is), as the persistence task follows
-- it through the driver's events; NULL when the session had no nick yet (the
-- bouncer's own notices before the upstream welcomed it). `own_nick_recorded`
-- tells that NULL apart from a row stored before this column existed, which
-- recorded nothing: every existing row is false, and a restore whose oldest
-- row is one of them starts at the current nick, as before. A writer that does
-- not state it records nothing, and says so.
ALTER TABLE bnc_buffer
    ADD COLUMN own_nick TEXT,
    ADD COLUMN own_nick_recorded BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT bnc_buffer_own_nick_recorded
        CHECK (own_nick IS NULL OR own_nick_recorded),
    -- Written back to a client as a NICK: one line, never an empty name.
    ADD CONSTRAINT bnc_buffer_own_nick_one_line
        CHECK (own_nick IS NULL OR own_nick ~ '^[^\r\n]+$');
