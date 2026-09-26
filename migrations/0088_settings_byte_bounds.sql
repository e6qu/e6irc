-- The per-connection send queue is bounded in bytes, not lines (Solanum's
-- class `sendq`): the console-owned `sendq`, a count of lines, is replaced by
-- `sendq_bytes`. A stored count becomes that many full 512-byte lines, which
-- lets ordinary traffic queue what it did, clamped to the range the setting
-- now takes (two of the longest lines the server sends, up to 32 MiB). The
-- rename is deliberate: a configuration file still stating `sendq` is refused
-- by name rather than read as a byte count a thousandth of what it meant.
UPDATE server_settings
SET settings = (settings - 'sendq')
    || jsonb_build_object(
        'sendq_bytes',
        least(greatest((settings ->> 'sendq')::bigint * 512, 17406), 33554432)
    )
WHERE settings ? 'sendq';

-- `limits.auth_rate_burst` is on by default now, and off is the explicit
-- string "off". A stored `null` was the old default — unset, which then meant
-- off, and was the only way to leave the throttle alone — and the new type
-- refuses it; removing the key gives the setting its new default, as 0067 and
-- 0068 did for the fields they made required.
UPDATE server_settings
SET settings = settings #- '{limits,auth_rate_burst}'
WHERE jsonb_typeof(settings #> '{limits,auth_rate_burst}') = 'null';
