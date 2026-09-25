-- `channel_access`'s primary key leads with `channel_id`, so nothing indexed
-- `account_id`: account deletion's cascade into this table, and every lookup
-- of one account's access entries, scanned the whole table.
CREATE INDEX channel_access_account_id_idx ON channel_access (account_id);
