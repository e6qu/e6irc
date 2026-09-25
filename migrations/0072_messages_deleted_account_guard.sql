-- Account deletion purges every message naming the account (as sender or
-- direct-message peer) in the transaction that retires its name. Messages are
-- written asynchronously -- batched by the database worker, from core shards
-- that learn of the account's suspension at their own pace -- so a row naming
-- the account could commit after the purge and outlive the deletion that was
-- meant to remove it.
--
-- This trigger makes that impossible in storage, whatever the writer's timing.
-- For every account a new row names, it takes FOR KEY SHARE on the account row
-- without waiting (SKIP LOCKED). Only account deletion locks that row FOR
-- UPDATE, the one mode KEY SHARE conflicts with, so:
--
-- * Locked: deletion now waits for this insert to commit, and its purge then
--   sees and removes the row.
-- * Present but not lockable: the account is being deleted (it was suspended
--   first); the row is not stored.
-- * Absent: if the name is retired the account is gone and the row is not
--   stored. Deletion holds the account row until it commits the retirement,
--   so no writer can see neither.
--
-- A name with no account and no retirement (a service, a bridged sender) is
-- not an account's data; the row is stored.
--
-- The fold is RFC 1459 as elsewhere (0025, 0054, 0065): account names are
-- ASCII. `sender_account` holds the display name, `dm_peers` folded names.
CREATE FUNCTION refuse_messages_of_deleted_accounts()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    named TEXT;
BEGIN
    FOREACH named IN ARRAY array_remove(
        array_append(
            COALESCE(NEW.dm_peers, ARRAY[]::TEXT[]),
            translate(lower(NEW.sender_account), '[]\~', '{}|^')),
        NULL)
    LOOP
        PERFORM 1 FROM accounts WHERE name_folded = named FOR KEY SHARE SKIP LOCKED;
        IF NOT FOUND AND (
            EXISTS (SELECT 1 FROM accounts WHERE name_folded = named)
            OR EXISTS (SELECT 1 FROM retired_account_names WHERE name_folded = named)
        ) THEN
            RETURN NULL;
        END IF;
    END LOOP;
    RETURN NEW;
END
$$;

CREATE TRIGGER messages_refuse_deleted_accounts
BEFORE INSERT ON messages
FOR EACH ROW
EXECUTE FUNCTION refuse_messages_of_deleted_accounts();
