-- Direct-message conversation summary, storage constraints the application
-- already relies on, and two pieces of dead schema.

-- 1. `dm_conversations`: one row per (participant, correspondent) of every
-- stored direct-message conversation, holding the conversation's newest
-- message time. CHATHISTORY TARGETS answers "which conversations is this
-- account part of, newest activity in a window" from it with one index range
-- read bounded by the request's limit. It used to aggregate every retained
-- direct message of the requester (a GIN scan of `messages_dm_peers_idx`, a
-- heap fetch per row, then a hash aggregate) on the serial database worker.
--
-- Both columns are RFC 1459-folded identities, as `messages.dm_peers` stores
-- them; a conversation with oneself is the one row (me, me). The summary is a
-- function of `messages` and is kept by triggers on that table, so every
-- writer -- the history flush, retention, account deletion's purge, a
-- hand-run statement -- keeps it exact without having to know it exists.
CREATE TABLE dm_conversations (
    account TEXT NOT NULL,
    peer TEXT NOT NULL,
    latest_ts TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (account, peer)
);

CREATE INDEX dm_conversations_account_latest_idx
    ON dm_conversations (account, latest_ts);

-- The (participant, correspondent) pairs a stored direct message belongs to:
-- (a, b) and (b, a) for a two-party conversation, (a, a) for one with
-- oneself. A conversation with an unauthenticated `~nick` party is never
-- stored (migration 0058); should such a row exist anyway it summarizes to
-- nothing, as CHATHISTORY TARGETS never listed it.
CREATE FUNCTION dm_conversation_pairs(peers TEXT[])
RETURNS TABLE (account TEXT, peer TEXT)
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT DISTINCT participant,
           COALESCE(
               (SELECT other FROM unnest(peers) other WHERE other <> participant LIMIT 1),
               participant)
    FROM unnest(peers) participant
    WHERE NOT EXISTS (SELECT 1 FROM unnest(peers) p WHERE left(p, 1) = '~')
$$;

INSERT INTO dm_conversations (account, peer, latest_ts)
SELECT pair.account, pair.peer, max(m.ts)
FROM messages m
CROSS JOIN LATERAL dm_conversation_pairs(m.dm_peers) pair
WHERE m.dm_peers IS NOT NULL
GROUP BY pair.account, pair.peer;

-- Inserted messages advance their conversations' newest time. Rows the
-- deleted-account guard (0072) or `ON CONFLICT (msgid) DO NOTHING` refused are
-- not in the transition table. Rows are upserted in key order, the order the
-- delete trigger locks them in, so the two cannot deadlock.
CREATE FUNCTION summarize_inserted_direct_messages()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO dm_conversations (account, peer, latest_ts)
    SELECT pair.account, pair.peer, max(inserted.ts)
    FROM inserted
    CROSS JOIN LATERAL dm_conversation_pairs(inserted.dm_peers) pair
    WHERE inserted.dm_peers IS NOT NULL
    GROUP BY pair.account, pair.peer
    ORDER BY pair.account, pair.peer
    ON CONFLICT (account, peer) DO UPDATE
        SET latest_ts = GREATEST(dm_conversations.latest_ts, EXCLUDED.latest_ts);
    RETURN NULL;
END
$$;

CREATE TRIGGER messages_summarize_inserted_direct_messages
AFTER INSERT ON messages
REFERENCING NEW TABLE AS inserted
FOR EACH STATEMENT
EXECUTE FUNCTION summarize_inserted_direct_messages();

-- Deleted messages (retention, account purge) can only lower a conversation's
-- newest time, and only when the newest summarized message was among them:
-- such a conversation is recomputed from what remains (one backward probe of
-- `messages_target_ts_id_idx`) or forgotten when nothing does. The rows are
-- locked, in key order, only while their newest time is still covered by the
-- deletion; a message inserted concurrently moves it past that and the row is
-- left to the insert.
CREATE FUNCTION summarize_deleted_direct_messages()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    WITH gone AS (
        SELECT pair.account, pair.peer, deleted.target, max(deleted.ts) AS gone_ts
        FROM deleted
        CROSS JOIN LATERAL dm_conversation_pairs(deleted.dm_peers) pair
        WHERE deleted.dm_peers IS NOT NULL
        GROUP BY pair.account, pair.peer, deleted.target
    ), affected AS (
        SELECT c.account, c.peer, gone.target
        FROM dm_conversations c
        JOIN gone ON gone.account = c.account AND gone.peer = c.peer
        WHERE c.latest_ts <= gone.gone_ts
        ORDER BY c.account, c.peer
        FOR UPDATE OF c
    ), remaining AS (
        SELECT affected.account, affected.peer,
               (SELECT max(m.ts) FROM messages m WHERE m.target = affected.target) AS latest
        FROM affected
    ), forgotten AS (
        DELETE FROM dm_conversations c
        USING remaining
        WHERE c.account = remaining.account AND c.peer = remaining.peer
          AND remaining.latest IS NULL
    )
    UPDATE dm_conversations c
    SET latest_ts = remaining.latest
    FROM remaining
    WHERE c.account = remaining.account AND c.peer = remaining.peer
      AND remaining.latest IS NOT NULL;
    RETURN NULL;
END
$$;

CREATE TRIGGER messages_summarize_deleted_direct_messages
AFTER DELETE ON messages
REFERENCING OLD TABLE AS deleted
FOR EACH STATEMENT
EXECUTE FUNCTION summarize_deleted_direct_messages();

-- 2. A BNC network name is one bounded, path-safe token
-- (`sanitize::valid_network_name`). On that charset PostgreSQL's `lower()`
-- equals the RFC 1459 fold the registry and backlog keys use, which the
-- case-insensitive name index (0034) and every folded lookup depend on; the
-- rule is now a fact of the schema rather than of each ingress. Every shipped
-- ingress already validated it, so an existing row outside it was written by
-- hand and is named rather than rewritten: renaming could collide with
-- another network's folded name.
DO $$
DECLARE
    offending TEXT;
BEGIN
    SELECT string_agg(format('%s (account %s)', quote_literal(name), account_id), ', ')
    INTO offending
    FROM bnc_networks
    WHERE NOT (name ~ '^[A-Za-z0-9._-]{1,64}$' AND name NOT IN ('.', '..'));
    IF offending IS NOT NULL THEN
        RAISE EXCEPTION 'bnc_networks rows with names outside [A-Za-z0-9._-]{1,64} '
            '(or "."/".."): %; rename or delete them, then restart', offending;
    END IF;
END
$$;

ALTER TABLE bnc_networks
    ADD CONSTRAINT bnc_networks_name_token
    CHECK (name ~ '^[A-Za-z0-9._-]{1,64}$' AND name NOT IN ('.', '..'));

-- 3. Bouncer history positions are text compared lexically: CHATHISTORY
-- selectors, the MARKREAD `GREATEST`, and the retention comparison are only
-- ordered correctly on the one canonical form the writers produce
-- (`e6irc_proto::time::server_time`: `YYYY-MM-DDTHH:MM:SS.mmmZ`). Migration
-- 0054 rebased history onto that form; any line still outside it is rebased
-- the same way (onto its arrival time), and a read marker outside it -- a
-- position that cannot be ordered against any line -- is removed, which reads
-- as "nothing marked read" until the client marks again.
UPDATE bnc_buffer
SET sent_at = to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
WHERE sent_at !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$';

DELETE FROM bnc_read_markers
WHERE timestamp !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$';

ALTER TABLE bnc_buffer
    ADD CONSTRAINT bnc_buffer_sent_at_canonical
    CHECK (sent_at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$');

ALTER TABLE bnc_read_markers
    ADD CONSTRAINT bnc_read_markers_timestamp_canonical
    CHECK (timestamp ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$');

-- 4. `account_invitations.accepted_account_id` was written on acceptance and
-- never read, and storage maintenance deletes a consumed invitation on its
-- next cycle; the audit log's ACCOUNT_INVITATION_ACCEPT event is the durable
-- record of who accepted. Its unindexed foreign key also made every account
-- deletion scan the table.
ALTER TABLE account_invitations DROP COLUMN accepted_account_id;

-- 5. `bnc_networks_account_idx (account_id)` is a prefix of the unique
-- `bnc_networks_account_name_folded_idx (account_id, lower(name))` (0034),
-- which serves every query and the cascade it did; it cost a write per change.
DROP INDEX bnc_networks_account_idx;
