-- CHATHISTORY pages on the attach listener are cut by a SQL `LIMIT`, but a
-- stored `TAGMSG` is dropped afterwards for a client that did not negotiate
-- `message-tags` -- it is nothing but tags, so there is no line left to send.
-- The client asked for 100 and silently got 87, with no way to tell a short
-- page from the end of the buffer. To let the `LIMIT` count only lines the
-- client can receive, the command has to be a column the query can filter on.
--
-- It is GENERATED rather than written by the insert path so it cannot disagree
-- with the line it describes, and so every row already stored gets it too. The
-- expression is the IRC frame: an optional `@tags` word, an optional `:prefix`
-- word, then the command.
ALTER TABLE bnc_buffer
    ADD COLUMN command TEXT
    GENERATED ALWAYS AS (
        upper(substring(line from '^(?:@[^ ]+[ ]+)?(?::[^ ]+[ ]+)?([^ ]+)'))
    ) STORED;
