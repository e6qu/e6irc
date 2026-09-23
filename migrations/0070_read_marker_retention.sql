-- Read markers were the one stored collection with no bound at all: capped at
-- 256 per account, but unbounded in accounts, and absent from the storage
-- maintenance sweep. The table only ever grew -- and every row of it is read
-- at boot and mirrored into each core shard, so its size is also the daemon's
-- start-up cost and resident memory.
--
-- A marker points at a position in history. Once history retention has removed
-- every message that old, the marker names a position nothing can be read
-- from, so the same retention bounds it. Both marker tables are swept: the core
-- one against the message retention, the bouncer's against the same window its
-- backlog is kept for.
--
-- The indexes are what make the sweep's `ORDER BY ... LIMIT` a bounded index
-- scan instead of a sort of the whole table.
CREATE INDEX read_markers_marker_ts_idx ON read_markers (marker_ts);

-- `timestamp` is the ISO-8601 UTC text the attach layer compares on; it sorts
-- lexically, which is what both the CHATHISTORY queries and this sweep rely on.
CREATE INDEX bnc_read_markers_timestamp_idx ON bnc_read_markers (timestamp);
