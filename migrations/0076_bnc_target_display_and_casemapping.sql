-- A stored bouncer conversation is keyed by its name folded the way the
-- *network* folds names, not always by RFC 1459. On a `CASEMAPPING=ascii`
-- network `#a[` and `#a{` are two channels and `dev[m]` and `dev{m}` two
-- people; folded by RFC 1459 they shared one history, and CHATHISTORY TARGETS
-- answered with a folded key (`alice{m}`) that names someone else there.
--
-- `target_display` keeps the conversation's name as the network spelled it,
-- which TARGETS returns and from which the key is re-derived whenever the
-- network's mapping differs from `target_casemapping`, the mapping `target`
-- was folded under. Every row stored so far was folded under RFC 1459.
ALTER TABLE bnc_buffer
    ADD COLUMN target_display TEXT,
    ADD COLUMN target_casemapping TEXT NOT NULL DEFAULT 'rfc1459'
        CONSTRAINT bnc_buffer_target_casemapping_known
        CHECK (target_casemapping IN ('rfc1459', 'rfc1459-strict', 'ascii'));

-- The name as spelled is still in each stored line: the conversation is
-- either the message's (STATUSMSG-less) addressee or its sender, whichever
-- one folds to the stored key. A row where neither does (none is expected)
-- keeps its folded key as its name.
WITH parts AS (
    SELECT id,
           target,
           regexp_replace(
               substring(line FROM '^(?:@[^ ]+[ ]+)?(?::[^ ]+[ ]+)?[^ ]+[ ]+([^ ]+)'),
               '^[@+]([#&])', '\1') AS addressed,
           substring(line FROM '^(?:@[^ ]+[ ]+)?:([^ !@]+)') AS sender
    FROM bnc_buffer
    WHERE target IS NOT NULL
)
UPDATE bnc_buffer
SET target_display = CASE
        WHEN translate(parts.addressed,
                       'ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\~',
                       'abcdefghijklmnopqrstuvwxyz{}|^') = parts.target
            THEN parts.addressed
        WHEN translate(parts.sender,
                       'ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\~',
                       'abcdefghijklmnopqrstuvwxyz{}|^') = parts.target
            THEN parts.sender
        ELSE parts.target
    END
FROM parts
WHERE bnc_buffer.id = parts.id;
