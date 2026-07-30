-- Deleted account names remain reserved. Re-registering one would let a new
-- person inherit nick/account-keyed relationships and would race a late
-- credential verdict already in flight during deletion.

CREATE TABLE retired_account_names (
    name_folded TEXT PRIMARY KEY,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Make the retirement boundary a storage invariant. Every account INSERT,
-- including a future call path that forgets the application helper, takes the
-- same per-name transaction lock used by deletion and refuses a retired name.
CREATE FUNCTION enforce_account_name_retirement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.name_folded, 7293132586581229569));
    IF EXISTS (
        SELECT 1 FROM retired_account_names
        WHERE name_folded = NEW.name_folded
    ) THEN
        RAISE EXCEPTION 'account name is retired'
            USING ERRCODE = '23505', CONSTRAINT = 'accounts_name_not_retired';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER accounts_name_retirement
BEFORE INSERT ON accounts
FOR EACH ROW
EXECUTE FUNCTION enforce_account_name_retirement();
