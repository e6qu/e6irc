-- Temporary server bans (Solanum's `KLINE <minutes> <mask>`, DESIGN §7.6):
-- a ban with an expiry stops being enforced when it lapses, on every shard,
-- and storage maintenance deletes its row. NULL is a permanent ban.
ALTER TABLE server_bans ADD COLUMN expires_at TIMESTAMPTZ;

-- Maintenance selects the oldest expired rows in bounded batches.
CREATE INDEX server_bans_expires_at_idx
    ON server_bans (expires_at, id)
    WHERE expires_at IS NOT NULL;
