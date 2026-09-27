-- 1. A conversation's read marker is kept under the correspondent's *identity*
-- (DESIGN §11.1.1): their account's folded name, or `~` and their folded nick
-- when they have not authenticated. Markers stored before that were kept under
-- the correspondent's folded nick, so one on a grouped nick is not found under
-- the account it now resolves to, and the reader's position starts over at `*`.
--
-- The data model tells every stored target apart:
--   * a channel's folded name starts with `#` — kept;
--   * a `~` target is already an identity (`~` cannot occur in a nick) — kept;
--   * an account's folded name is that account's identity (an account owns the
--     nick spelled like its name) — kept;
--   * a grouped nick (`account_nicks`) is its account's — moved to the
--     account's folded name;
--   * any other nick is registered to no one, so whoever held it had not
--     authenticated — moved to `~nick`.
-- Two markers the move puts on one key (a grouped nick's and its account's, or
-- a nick's and the `~nick` one written since) are one marker at the newer
-- position. Nothing a move writes is itself moved, so running this again
-- changes nothing.
CREATE TEMPORARY TABLE moved_read_markers ON COMMIT DROP AS
SELECT marker.account_id,
       marker.target AS stored_target,
       coalesce(owner.name_folded, '~' || marker.target) AS identity_target,
       marker.marker_ts
FROM read_markers marker
LEFT JOIN account_nicks grouped ON grouped.nick_folded = marker.target
LEFT JOIN accounts owner ON owner.id = grouped.account_id
WHERE marker.target NOT LIKE '#%'
  AND marker.target NOT LIKE '~%'
  AND NOT EXISTS (SELECT 1 FROM accounts named WHERE named.name_folded = marker.target);

DELETE FROM read_markers marker
USING moved_read_markers moved
WHERE marker.account_id = moved.account_id
  AND marker.target = moved.stored_target;

INSERT INTO read_markers (account_id, target, marker_ts)
SELECT account_id, identity_target, max(marker_ts)
FROM moved_read_markers
GROUP BY account_id, identity_target
ON CONFLICT (account_id, target)
DO UPDATE SET marker_ts = greatest(read_markers.marker_ts, EXCLUDED.marker_ts);

-- 2. The MOTD is bounded to 14 lines (`MAX_MOTD_LINES`): a new client is sent
-- all of it at registration, and more need not fit the smallest SendQ beside
-- the rest of that burst. It used to be bounded only per line. A stored MOTD
-- above the bound keeps its first 14 lines rather than being left for the next
-- start to refuse; running this again changes nothing.
UPDATE server_settings
SET settings = jsonb_set(
    settings,
    '{motd}',
    (
        SELECT jsonb_agg(line ORDER BY position)
        FROM jsonb_array_elements(settings -> 'motd') WITH ORDINALITY AS entry(line, position)
        WHERE position <= 14
    )
)
WHERE jsonb_typeof(settings -> 'motd') = 'array'
  AND jsonb_array_length(settings -> 'motd') > 14;

-- 3. CHATHISTORY pages by `(ts, msgid COLLATE "C")` and migration 0093 built
-- the index for it; `(target, ts, id)` served the `(ts, id)` order it
-- replaces, and every other reader of it (a buffer's newest time, the
-- conversation summaries' backward probe) reads the `(target, ts)` prefix the
-- new index shares. Dropped last: it holds the table's lock until commit.
DROP INDEX IF EXISTS messages_target_ts_id_idx;
