-- A direct-message conversation with an unauthenticated party was stored under
-- that party's `~nick` identity. `~nick` is not a person: it is whoever holds
-- the nick right now, so the next stranger to take the nick could read the
-- previous occupant's conversations and the list of who they talked to.
-- The server no longer stores such conversations (they live only in memory,
-- for the session); this removes the ones already stored. Conversations
-- between two accounts, and all channel history, are untouched.
DELETE FROM messages
WHERE dm_peers IS NOT NULL
  AND EXISTS (SELECT 1 FROM UNNEST(dm_peers) AS peer WHERE left(peer, 1) = '~');
