-- Direct-message history (DESIGN §11.1). A conversation is stored once, under
-- a `target` key built from both participants' casefolded nicks sorted and
-- joined by `!` — invalid in a nick, and channels start with `#`, so the three
-- namespaces cannot collide. Sorting makes the key symmetric, so both sides
-- read the same thread from the single stored copy.
--
-- `dm_peers` carries those participants as an array (NULL for a channel
-- message). CHATHISTORY TARGETS has to answer "which conversations is this
-- user part of", which the composite key cannot be searched for; the GIN index
-- makes that containment test indexable.
ALTER TABLE messages ADD COLUMN dm_peers TEXT[];

CREATE INDEX messages_dm_peers_idx ON messages USING gin (dm_peers);
