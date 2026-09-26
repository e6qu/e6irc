-- A bouncer read marker is keyed by its conversation folded the way the
-- network folds names, like the backlog it marks (0076). When the network
-- changes its CASEMAPPING the backlog is re-keyed from `bnc_buffer.target_display`;
-- a marker kept only its folded key, so it could not be, and on an
-- `ascii`-mapped network a marker on `#a[` was lost (or landed on `#a{`) once
-- the keys were folded the RFC 1459 way.
--
-- `target_display` keeps the conversation's name as the client spelled it in
-- MARKREAD, and `target_casemapping` the mapping `target` was folded under, so
-- the key is re-derived whenever the network's mapping differs.
ALTER TABLE bnc_read_markers
    ADD COLUMN target_display TEXT,
    ADD COLUMN target_casemapping TEXT NOT NULL DEFAULT 'rfc1459'
        CONSTRAINT bnc_read_markers_target_casemapping_known
        CHECK (target_casemapping IN ('rfc1459', 'rfc1459-strict', 'ascii'));

-- What is known about a stored marker is the backlog of its conversation: the
-- newest stored line keyed the same way (on the account's own network, or on
-- a shared one, whose buffer belongs to `*`) spells the name and says which
-- mapping folded it.
UPDATE bnc_read_markers m
SET target_display = known.target_display,
    target_casemapping = known.target_casemapping
FROM (
    SELECT DISTINCT ON (r.account_id, r.network, r.target)
           r.account_id, r.network, r.target, b.target_display, b.target_casemapping
    FROM bnc_read_markers r
    JOIN accounts a ON a.id = r.account_id
    JOIN bnc_buffer b
      ON b.network = r.network
     AND b.owner IN (a.name_folded, '*')
     AND b.target = r.target
     AND b.target_display IS NOT NULL
    ORDER BY r.account_id, r.network, r.target, b.id DESC
) known
WHERE m.account_id = known.account_id
  AND m.network = known.network
  AND m.target = known.target;

-- A marker whose conversation has no stored line left keeps its folded key as
-- its name, under the mapping the network's newest stored conversation was
-- keyed with: the one the network last said, and so the one MARKREAD folded
-- with. With no backlog at all it was RFC 1459, the default before a network
-- says otherwise.
UPDATE bnc_read_markers m
SET target_display = m.target,
    target_casemapping = COALESCE((
        SELECT b.target_casemapping
        FROM bnc_buffer b
        JOIN accounts a ON a.id = m.account_id
        WHERE b.network = m.network
          AND b.owner IN (a.name_folded, '*')
          AND b.target IS NOT NULL
        ORDER BY b.id DESC
        LIMIT 1
    ), 'rfc1459')
WHERE m.target_display IS NULL;

ALTER TABLE bnc_read_markers
    ALTER COLUMN target_display SET NOT NULL,
    ALTER COLUMN target_casemapping DROP DEFAULT;
