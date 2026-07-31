-- CHATHISTORY on the BNC attach listener needs per-target queries, not a
-- flat scan of every stored line. `target` is the channel or nick a message
-- was addressed to, extracted from the raw line at persistence time. NULL
-- for non-message lines (JOIN, NICK, server numerics, etc.) so they are
-- excluded from target-filtered history without an extra predicate.
ALTER TABLE bnc_buffer ADD COLUMN target TEXT;
ALTER TABLE bnc_buffer ADD COLUMN msgid TEXT;
-- Effective message timestamp: the IRCv3 `time=` tag when the upstream sent
-- one, else the bouncer's arrival time. CHATHISTORY timestamp selectors and
-- MARKREAD positions both compare on this (ISO-8601 UTC sorts lexically).
ALTER TABLE bnc_buffer ADD COLUMN sent_at TEXT;

CREATE INDEX bnc_buffer_target_idx
    ON bnc_buffer (owner, network, target, id);

CREATE INDEX bnc_buffer_msgid_idx
    ON bnc_buffer (owner, network, msgid)
    WHERE msgid IS NOT NULL;

CREATE INDEX bnc_buffer_sent_at_idx
    ON bnc_buffer (owner, network, target, sent_at);

-- Per-network, per-target read markers for the BNC attach layer (soju-style):
-- an ISO-8601 timestamp recording where the user stopped reading, so a client
-- can resume from there rather than replaying the whole ring.
CREATE TABLE bnc_read_markers (
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    network TEXT NOT NULL,
    target TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    PRIMARY KEY (account_id, network, target)
);
