-- CHATHISTORY replay must reproduce the client-only tags a message was relayed
-- with (`+reply`, `+draft/react`, ...): a threaded reply that loses its parent
-- link, or a reaction that loses what it reacts to, is not the message that
-- was delivered. Store them beside the message, escaped and `;`-joined exactly
-- as they were relayed ('' for none; rows stored before this carried none that
-- were kept). A client's whole tag section is bounded at 4094 bytes on input,
-- so the column is bounded by the same budget.
ALTER TABLE messages ADD COLUMN client_tags TEXT NOT NULL DEFAULT ''
    CHECK (octet_length(client_tags) <= 4096);

-- A TAGMSG is history too: a reaction is part of the conversation. It has no
-- text, and is kept only when it carries a client-only tag worth replaying
-- (a typing indicator is not stored), so its row is exactly that.
ALTER TABLE messages DROP CONSTRAINT messages_kind_check;
ALTER TABLE messages ADD CONSTRAINT messages_kind_check
    CHECK (kind IN ('privmsg', 'notice', 'tagmsg'));
ALTER TABLE messages ADD CONSTRAINT messages_tagmsg_shape
    CHECK (kind <> 'tagmsg' OR (body = '' AND multiline IS NULL AND client_tags <> ''));
