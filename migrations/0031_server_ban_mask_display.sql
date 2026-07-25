-- Server bans stored only the casefolded mask, so STATS and the confirmation
-- echoed the folded form — an operator who set `KLINE Baddie@Host` saw it as
-- `baddie@host`, unlike a channel `+b` which preserves the setter's casing.
-- Record the display casing alongside the folded key. The folded `mask` stays
-- the storage/uniqueness key (matching and UN*LINE both fold), so this column
-- is purely for display. Nullable: a row that predates it reads its folded
-- `mask` via `COALESCE(mask_display, mask)`, which is the honest value (its
-- original casing was never captured).
ALTER TABLE server_bans ADD COLUMN mask_display TEXT;
