-- Three indexes that no query uses, maintained on the two hottest insert paths
-- (every chat message, every bouncer line):
--
-- * `bnc_buffer_target_idx (owner, network, target, id)` is a strict prefix
--   match of `bnc_buffer_sent_at_idx (owner, network, target, sent_at, id)`,
--   which already serves every per-target read.
-- * `bnc_buffer_msgid_idx (owner, network, msgid)`: a bouncer CHATHISTORY
--   pivot is looked up within one target, so the per-target index above finds
--   it inside that target's bounded, capped slice.
-- * `messages_ts_brin`: maintenance orders by `(ts, id)` and uses
--   `messages_ts_id_idx` from 0046; nothing reads the BRIN.
DROP INDEX bnc_buffer_target_idx;
DROP INDEX bnc_buffer_msgid_idx;
DROP INDEX messages_ts_brin;
