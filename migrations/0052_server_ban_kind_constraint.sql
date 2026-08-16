ALTER TABLE server_bans
    ADD CONSTRAINT server_bans_kind_valid
    CHECK (kind IN ('kline', 'dline', 'xline'));
