-- ChanServ SET KEEPTOPIC (DESIGN §7.6, §8): whether a registered channel
-- retains its topic across empty→recreate cycles. Default on, matching the
-- prior always-retain behavior. Only the OFF exceptions are boot-loaded.
ALTER TABLE channels ADD COLUMN keeptopic BOOLEAN NOT NULL DEFAULT true;
