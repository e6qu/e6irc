-- CHATHISTORY TARGETS dates a buffer by its newest entry the requester can be
-- sent. A stored TAGMSG (0081) is nothing but tags, so a client without
-- `message-tags` cannot receive one: for it a conversation is dated by its
-- newest PRIVMSG or NOTICE, and one whose only activity is TAGMSGs is not its
-- buffer. `latest_text_ts` is that time, NULL while the conversation holds no
-- text; `latest_ts` stays the newest entry of any kind. Both are kept by the
-- same triggers, so every writer keeps both exact.
ALTER TABLE dm_conversations ADD COLUMN latest_text_ts TIMESTAMPTZ;

UPDATE dm_conversations c
SET latest_text_ts = newest_text.latest
FROM (
    SELECT pair.account, pair.peer, max(m.ts) AS latest
    FROM messages m
    CROSS JOIN LATERAL dm_conversation_pairs(m.dm_peers) pair
    WHERE m.dm_peers IS NOT NULL AND m.kind <> 'tagmsg'
    GROUP BY pair.account, pair.peer
) newest_text
WHERE c.account = newest_text.account AND c.peer = newest_text.peer;

-- TARGETS in the text scope reads at most its limit of rows here, as the
-- other scope does of `dm_conversations_account_latest_idx`.
CREATE INDEX dm_conversations_account_latest_text_idx
    ON dm_conversations (account, latest_text_ts);

-- An inserted message advances each time it is newer than. `GREATEST` skips
-- NULL, so a batch of only TAGMSGs leaves `latest_text_ts` as it was.
CREATE OR REPLACE FUNCTION summarize_inserted_direct_messages()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO dm_conversations (account, peer, latest_ts, latest_text_ts)
    SELECT pair.account, pair.peer, max(inserted.ts),
           max(inserted.ts) FILTER (WHERE inserted.kind <> 'tagmsg')
    FROM inserted
    CROSS JOIN LATERAL dm_conversation_pairs(inserted.dm_peers) pair
    WHERE inserted.dm_peers IS NOT NULL
    GROUP BY pair.account, pair.peer
    ORDER BY pair.account, pair.peer
    ON CONFLICT (account, peer) DO UPDATE
        SET latest_ts = GREATEST(dm_conversations.latest_ts, EXCLUDED.latest_ts),
            latest_text_ts = GREATEST(dm_conversations.latest_text_ts,
                                      EXCLUDED.latest_text_ts);
    RETURN NULL;
END
$$;

-- Deleted messages can only lower a time, and only when the newest message it
-- summarized was among them: such a conversation has both times recomputed
-- from what remains (a backward probe of `messages_target_ts_id_idx` each) or
-- is forgotten when nothing does. Locking is as before (0080): in key order,
-- only while a time is still covered by the deletion.
CREATE OR REPLACE FUNCTION summarize_deleted_direct_messages()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    WITH gone AS (
        SELECT pair.account, pair.peer, deleted.target, max(deleted.ts) AS gone_ts,
               max(deleted.ts) FILTER (WHERE deleted.kind <> 'tagmsg') AS gone_text_ts
        FROM deleted
        CROSS JOIN LATERAL dm_conversation_pairs(deleted.dm_peers) pair
        WHERE deleted.dm_peers IS NOT NULL
        GROUP BY pair.account, pair.peer, deleted.target
    ), affected AS (
        SELECT c.account, c.peer, gone.target
        FROM dm_conversations c
        JOIN gone ON gone.account = c.account AND gone.peer = c.peer
        WHERE c.latest_ts <= gone.gone_ts OR c.latest_text_ts <= gone.gone_text_ts
        ORDER BY c.account, c.peer
        FOR UPDATE OF c
    ), remaining AS (
        SELECT affected.account, affected.peer,
               (SELECT max(m.ts) FROM messages m WHERE m.target = affected.target) AS latest,
               (SELECT max(m.ts) FROM messages m
                WHERE m.target = affected.target AND m.kind <> 'tagmsg') AS latest_text
        FROM affected
    ), forgotten AS (
        DELETE FROM dm_conversations c
        USING remaining
        WHERE c.account = remaining.account AND c.peer = remaining.peer
          AND remaining.latest IS NULL
    )
    UPDATE dm_conversations c
    SET latest_ts = remaining.latest, latest_text_ts = remaining.latest_text
    FROM remaining
    WHERE c.account = remaining.account AND c.peer = remaining.peer
      AND remaining.latest IS NOT NULL;
    RETURN NULL;
END
$$;
