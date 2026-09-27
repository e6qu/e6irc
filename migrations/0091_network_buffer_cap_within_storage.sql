-- A server network's `buffer_cap` (the lines it keeps for replay) is bounded
-- by what its stored backlog keeps, 5,000 lines, so a start restores the whole
-- buffer the setting promises. It used to accept up to 100,000 while storage
-- kept 5,000 and a start restored 1,000: anything above that was honoured only
-- until the next restart. A stored network above the new bound is brought to
-- it -- the most that ever survived a restart -- rather than left for the next
-- start to refuse.
UPDATE server_settings
SET settings = jsonb_set(
    settings,
    '{networks}',
    (
        SELECT jsonb_agg(
            CASE
                WHEN (network ->> 'buffer_cap')::bigint > 5000
                THEN jsonb_set(network, '{buffer_cap}', '5000'::jsonb)
                ELSE network
            END
            ORDER BY position
        )
        FROM jsonb_array_elements(settings -> 'networks') WITH ORDINALITY AS entry(network, position)
    )
)
WHERE jsonb_typeof(settings -> 'networks') = 'array'
  AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements(settings -> 'networks') AS entry(network)
      WHERE (network ->> 'buffer_cap')::bigint > 5000
  );
