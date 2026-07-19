-- Per-account channel access flags (ChanServ FLAGS/ACCESS, DESIGN §7.6,
-- §8). `flags` is a set of chars: 'o' auto-op, 'v' auto-voice.
CREATE TABLE channel_access (
    channel_id BIGINT NOT NULL REFERENCES channels (id) ON DELETE CASCADE,
    account_id BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    flags TEXT NOT NULL,
    PRIMARY KEY (channel_id, account_id)
);
