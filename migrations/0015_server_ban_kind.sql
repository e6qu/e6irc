-- Server bans gain a kind (DESIGN §7.6/§15). One table, one matcher; the
-- kind selects which part of a connecting session the mask is tested
-- against: kline = user@host, dline = host/IP, xline = realname (gecos).
-- Existing rows are K-lines. Uniqueness becomes per (mask, kind) so a
-- textually identical mask can exist as different ban kinds.
ALTER TABLE server_bans ADD COLUMN kind TEXT NOT NULL DEFAULT 'kline';
ALTER TABLE server_bans DROP CONSTRAINT server_bans_mask_key;
ALTER TABLE server_bans ADD CONSTRAINT server_bans_mask_kind_key UNIQUE (mask, kind);
