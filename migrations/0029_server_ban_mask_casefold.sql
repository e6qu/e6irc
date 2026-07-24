-- Server-ban enforcement folds both mask and subject under the server
-- casemapping (mask::matches), but the add-dedup and UN*LINE removal used to
-- compare masks case-sensitively — so `KLINE Baddie@Host` then `UNKLINE
-- baddie@host` failed to remove (while the ban kept enforcing), and two
-- case-variants double-stored. The handler now folds the mask at storage; fold
-- existing rows to the same rfc1459-lowercased form so the table agrees with the
-- hot list (which loads folded) and with matching. Mirrors 0025's owner fold.
--
-- Drop any row that already has a folded twin of the same kind first, so the
-- fold below cannot collide on the UNIQUE (mask, kind) constraint. Keep the
-- lowest id (the earliest-set ban).
DELETE FROM server_bans a
 USING server_bans b
 WHERE a.kind = b.kind
   AND a.id > b.id
   AND translate(lower(a.mask), '[]\~', '{}|^') = translate(lower(b.mask), '[]\~', '{}|^');

UPDATE server_bans
   SET mask = translate(lower(mask), '[]\~', '{}|^')
 WHERE mask <> translate(lower(mask), '[]\~', '{}|^');
