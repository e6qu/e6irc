-- Support newest-first administrator policy pages without scanning and
-- sorting every row owned by a matching founder or server-ban kind. The
-- composite channel index subsumes the founder-only index added in 0042.

DROP INDEX channels_founder_account_idx;

CREATE INDEX channels_founder_account_id_desc_idx
    ON channels (founder_account_id, id DESC);

CREATE INDEX server_bans_kind_id_desc_idx
    ON server_bans (kind, id DESC);
