-- An explicit IRC user name (ident) for every IRC network.
--
-- The `USER` name used to be derived from the nickname: its first ten bytes.
-- A nickname may begin with `_`, `[` or `|`; a user name may not, so Solanum
-- and its relatives closed the link on perfectly legal nicknames
-- ("Invalid username [~_bot]"), the network retried, parked, and its owner had
-- no field to correct. The user name is now stated, and new configuration never
-- receives an implicit default for it.
--
-- Existing configuration is a different question, and not a guess: what each
-- network *has been sending* is known exactly. It is written in so that every
-- network that worked keeps its identity byte for byte, and only a derived
-- value the grammar no longer admits is repaired — dropping the characters no
-- server accepts in a user name, then any leading character that is not a
-- letter or digit. A nickname with nothing usable left (`___`, or all
-- non-ASCII) becomes the literal `e6irc`.
--
-- The alphabets are spelled out because a bracket *range* such as `A-Z` is
-- collation-dependent in a regular expression.

CREATE OR REPLACE FUNCTION pg_temp.e6irc_backfilled_username(nick TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE AS $$
    SELECT COALESCE(
        NULLIF(
            left(
                regexp_replace(
                    regexp_replace(
                        -- The old derivation: the longest prefix of the
                        -- nickname, in whole characters, within ten bytes.
                        (SELECT left(nick, n)
                         FROM generate_series(0, 10) AS n
                         WHERE octet_length(left(nick, n)) <= 10
                         ORDER BY n DESC
                         LIMIT 1),
                        '[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-]',
                        '',
                        'g'),
                    '^[_-]+',
                    ''),
                10),
            ''),
        'e6irc')
$$;

ALTER TABLE bnc_networks ADD COLUMN IF NOT EXISTS username TEXT;

UPDATE bnc_networks
SET username = pg_temp.e6irc_backfilled_username(nick)
WHERE kind = 'irc' AND username IS NULL;

-- Present exactly for the kind that has one. A bridge has no IRC registration,
-- and an IRC network without a user name cannot be started.
ALTER TABLE bnc_networks DROP CONSTRAINT IF EXISTS bnc_networks_username_for_irc;
ALTER TABLE bnc_networks
    ADD CONSTRAINT bnc_networks_username_for_irc
    CHECK ((kind = 'irc') = (username IS NOT NULL));

-- Server-level networks live in the managed settings document. Both kinds that
-- register over IRC (`irc`, and `local`, the in-process network) had the same
-- derivation and get the same backfill; an entry that already states a user
-- name is left alone.
UPDATE server_settings
SET settings = jsonb_set(
        settings,
        '{networks}',
        (
            SELECT jsonb_agg(
                CASE
                    WHEN network ->> 'kind' IN ('irc', 'local')
                         AND network ->> 'username' IS NULL
                    THEN network || jsonb_build_object(
                        'username',
                        pg_temp.e6irc_backfilled_username(network ->> 'nick'))
                    ELSE network
                END
                ORDER BY ordinality
            )
            FROM jsonb_array_elements(settings -> 'networks')
                 WITH ORDINALITY AS elements(network, ordinality)
        )
    )
WHERE jsonb_typeof(settings -> 'networks') = 'array'
  AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements(settings -> 'networks') AS network
      WHERE network ->> 'kind' IN ('irc', 'local')
        AND network ->> 'username' IS NULL
  );
