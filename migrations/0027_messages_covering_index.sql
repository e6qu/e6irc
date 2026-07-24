-- CHATHISTORY orders by `(ts, id)` and the msgid-pivot variants filter on the
-- composite `(ts, id)` position, but migration 0005's index is only
-- `(target, ts)` — so ties on an equal millisecond `ts` need an extra sort/id
-- filter. Replace it with a covering `(target, ts, id)` index so the paged
-- LIMIT queries are pure index scans; `(target, ts)` is a prefix of the new
-- index, so nothing that used the old one regresses.

CREATE INDEX messages_target_ts_id_idx ON messages (target, ts, id);
DROP INDEX messages_target_ts_idx;
