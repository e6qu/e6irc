-- ChanServ SET MLOCK (DESIGN §7.6, §8): a registered channel's locked
-- boolean modes, e.g. '+nt-i' — n and t forced on, i forced off. NULL when
-- no lock is set. Only channels with a lock are boot-loaded.
ALTER TABLE channels ADD COLUMN mlock TEXT;
