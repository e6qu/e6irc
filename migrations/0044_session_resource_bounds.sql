-- Keep durable browser-login storage and owner inventory bounded. Existing
-- deployments may predate the issuance cap, so retain only each account's
-- newest 32 active sessions and remove expired rows before the new invariant
-- takes effect. The composite owner/id index subsumes the original owner-only
-- index and supports newest-first retained-set maintenance.

DELETE FROM web_sessions WHERE expires_at <= now();

WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY account_id
               ORDER BY created_at DESC, id DESC
           ) AS position
    FROM web_sessions
)
DELETE FROM web_sessions
USING ranked
WHERE web_sessions.id = ranked.id
  AND ranked.position > 32;

DROP INDEX web_sessions_account_idx;

CREATE INDEX web_sessions_account_id_desc_idx
    ON web_sessions (account_id, id DESC);
