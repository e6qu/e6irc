-- An approved device grant named its account by display-name text, with no
-- foreign key: deleting or renaming nothing could reach it, revocation matched
-- it by a spelling, and a grant approved for an account deleted before the
-- device polled pointed at a name that might one day be someone else's. It now
-- holds the account's id and dies with the account.

ALTER TABLE device_grants
    ADD COLUMN account_id BIGINT REFERENCES accounts (id) ON DELETE CASCADE;

-- RFC1459 fold, as 0025 and 0054 spell it: account names are ASCII.
UPDATE device_grants g
   SET account_id = a.id
  FROM accounts a
 WHERE g.account IS NOT NULL
   AND a.name_folded = translate(lower(g.account), '[]\~', '{}|^');

-- An approval whose account no longer exists can mint nothing; it would only
-- ever be denied.
DELETE FROM device_grants WHERE account IS NOT NULL AND account_id IS NULL;

ALTER TABLE device_grants DROP COLUMN account;

-- Account deletion and suspension revoke by this column, and the cascade
-- deletes by it.
CREATE INDEX device_grants_account_id_idx
    ON device_grants (account_id)
    WHERE account_id IS NOT NULL;
