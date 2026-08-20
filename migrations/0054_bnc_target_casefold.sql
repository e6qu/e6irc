-- BNC history keys use RFC1459 case mapping, not PostgreSQL's locale-aware
-- lower(). Normalize rows written by the original CHATHISTORY implementation
-- so channel aliases such as `[room]`/`{room}` and differently-cased direct
-- message peers cannot remain split across buffers after an upgrade.
UPDATE bnc_buffer
SET target = translate(
    target,
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\~',
    'abcdefghijklmnopqrstuvwxyz{}|^'
)
WHERE target IS NOT NULL;

-- Earlier builds trusted an upstream time tag verbatim. Rebase the retained
-- bounded buffer onto its database arrival time once so malformed or
-- non-canonical historical values cannot violate the lexical ordering that
-- the corrected writer now guarantees for every new row.
UPDATE bnc_buffer
SET sent_at = to_char(
    created_at AT TIME ZONE 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
)
WHERE target IS NOT NULL;

DROP INDEX bnc_buffer_target_idx;
DROP INDEX bnc_buffer_sent_at_idx;

CREATE INDEX bnc_buffer_target_idx
    ON bnc_buffer (owner, network, target, id);

CREATE INDEX bnc_buffer_sent_at_idx
    ON bnc_buffer (owner, network, target, sent_at, id);
