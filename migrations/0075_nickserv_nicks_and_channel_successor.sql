-- NickServ nick grouping and protection, and the ChanServ channel successor
-- (DESIGN §7.6, Atheme semantics).
--
-- An account owns the nick spelled like its name. GROUP adds further nicks
-- to it; each grouped nick is one row here, owned by exactly one account and
-- gone with it. A nick is therefore registered to at most one account: it is
-- either some account's name or some account's grouped nick, never both. The
-- two triggers below make that a storage invariant under the same per-name
-- transaction lock account creation and deletion take, so no writer — however
-- it reaches the table — can register one nick to two accounts.
CREATE TABLE account_nicks (
    nick_folded TEXT PRIMARY KEY,
    -- Display spelling as grouped.
    nick TEXT NOT NULL,
    account_id BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX account_nicks_account_idx ON account_nicks (account_id);

-- NickServ SET ENFORCE: a user holding one of the account's nicks without
-- identifying to it is renamed to a Guest nick after the enforcement delay.
ALTER TABLE accounts ADD COLUMN nick_enforce BOOLEAN NOT NULL DEFAULT false;

CREATE FUNCTION enforce_grouped_nick_is_free()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.nick_folded, 7293132586581229569));
    IF EXISTS (SELECT 1 FROM accounts WHERE name_folded = NEW.nick_folded)
        OR EXISTS (SELECT 1 FROM retired_account_names WHERE name_folded = NEW.nick_folded)
    THEN
        RAISE EXCEPTION 'nick is an account name'
            USING ERRCODE = '23505', CONSTRAINT = 'account_nicks_not_an_account_name';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER account_nicks_not_an_account_name
BEFORE INSERT OR UPDATE OF nick_folded ON account_nicks
FOR EACH ROW
EXECUTE FUNCTION enforce_grouped_nick_is_free();

CREATE FUNCTION enforce_account_name_not_grouped()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.name_folded, 7293132586581229569));
    IF EXISTS (SELECT 1 FROM account_nicks WHERE nick_folded = NEW.name_folded) THEN
        RAISE EXCEPTION 'account name is a grouped nick'
            USING ERRCODE = '23505', CONSTRAINT = 'accounts_name_not_grouped';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER accounts_name_not_grouped
BEFORE INSERT ON accounts
FOR EACH ROW
EXECUTE FUNCTION enforce_account_name_not_grouped();

-- ChanServ SET SUCCESSOR: the account a registered channel passes to when its
-- founder's account is deleted. Clearing it when that account is deleted is
-- data about the successor, not the channel, so the reference sets NULL; the
-- founder is never also the successor.
ALTER TABLE channels
    ADD COLUMN successor_account_id BIGINT REFERENCES accounts (id) ON DELETE SET NULL,
    ADD CONSTRAINT channels_successor_is_not_founder
        CHECK (successor_account_id <> founder_account_id);

CREATE INDEX channels_successor_account_idx
    ON channels (successor_account_id)
    WHERE successor_account_id IS NOT NULL;

-- A founder change that promotes the successor (a transfer to it, or the
-- succession an account deletion performs) leaves the channel without one,
-- whichever writer made the change: the check above would otherwise refuse
-- every such transfer.
CREATE FUNCTION clear_successor_promoted_to_founder()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.successor_account_id = NEW.founder_account_id THEN
        NEW.successor_account_id := NULL;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER channels_successor_promoted
BEFORE UPDATE OF founder_account_id ON channels
FOR EACH ROW
EXECUTE FUNCTION clear_successor_promoted_to_founder();
