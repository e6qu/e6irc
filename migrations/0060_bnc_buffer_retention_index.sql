-- Bouncer history (`bnc_buffer`) now expires under `storage.history_retention_days`
-- like `messages`, deleted by storage maintenance in bounded, oldest-first
-- batches. That delete selects by storage age; without this index it would scan
-- the whole table on every tick.
CREATE INDEX bnc_buffer_created_at_idx ON bnc_buffer (created_at, id);
