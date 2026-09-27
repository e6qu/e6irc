-- A server network's `buffer_cap` (the lines it keeps for replay) is bounded
-- by what its stored backlog keeps, 5,000 lines, so a start restores the whole
-- buffer the setting promises. It used to accept up to 100,000 while storage
-- kept 5,000 and a start restored 1,000: anything above that was honoured only
-- until the next restart. A stored network above the new bound is brought to
-- it -- the most that ever survived a restart -- rather than left for the next
-- start to refuse, and not in silence: the change is a revision of its own
-- with a `CONFIG` audit entry, as a console save is, whose detail carries each
-- changed network's previous `buffer_cap`, so nothing is lost.
WITH over AS (
    SELECT (
               SELECT jsonb_agg(
                          CASE
                              WHEN (network ->> 'buffer_cap')::bigint > 5000
                              THEN jsonb_set(network, '{buffer_cap}', '5000'::jsonb)
                              ELSE network
                          END
                          ORDER BY position
                      )
               FROM jsonb_array_elements(settings -> 'networks')
                    WITH ORDINALITY AS entry(network, position)
           ) AS networks,
           (
               SELECT jsonb_object_agg(network ->> 'name', network -> 'buffer_cap')
               FROM jsonb_array_elements(settings -> 'networks') AS entry(network)
               WHERE (network ->> 'buffer_cap')::bigint > 5000
           ) AS previous
    FROM server_settings
    WHERE jsonb_typeof(settings -> 'networks') = 'array'
      AND EXISTS (
          SELECT 1
          FROM jsonb_array_elements(settings -> 'networks') AS entry(network)
          WHERE (network ->> 'buffer_cap')::bigint > 5000
      )
),
changed AS (
    UPDATE server_settings
    SET settings = jsonb_set(settings, '{networks}', (SELECT networks FROM over)),
        revision = revision + 1,
        updated_by = 'migration:0091',
        updated_at = now()
    WHERE EXISTS (SELECT 1 FROM over)
    RETURNING revision
)
INSERT INTO audit_log (actor, actor_kind, action, target, target_kind, detail)
SELECT 'migration:0091', 'host', 'CONFIG', 'server', 'server',
       format(
           'revision %s; networks buffer_cap brought to 5000 (what storage keeps) by '
           'migration 0091; previous buffer_cap by network: %s',
           changed.revision,
           over.previous::text)
FROM changed, over;
