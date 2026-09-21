-- Account deletion and account export select an account's messages by
-- `sender_account IN (display name, folded name) OR dm_peers @> ARRAY[folded]`.
-- The `dm_peers` half has had a GIN index since 0022; the `sender_account`
-- half had none, so the whole predicate was a sequential scan of `messages`
-- — under the account-authority lock, for deletion. With this index the
-- predicate is a BitmapOr of two index scans.
CREATE INDEX messages_sender_account_idx
    ON messages (sender_account)
    WHERE sender_account IS NOT NULL;
