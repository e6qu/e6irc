-- Message history with a BRIN index for time-bounded scans.

CREATE TABLE messages (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- IRCv3 msgid (unique per message, stable across history queries).
    msgid TEXT NOT NULL UNIQUE,
    -- Casefolded target (channel or nick).
    target TEXT NOT NULL,
    sender_prefix TEXT NOT NULL,
    sender_account TEXT,
    -- 'privmsg' | 'notice'
    kind TEXT NOT NULL CHECK (kind IN ('privmsg', 'notice')),
    body TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL
);

CREATE INDEX messages_target_ts_idx ON messages (target, ts);
CREATE INDEX messages_ts_brin ON messages USING brin (ts);
