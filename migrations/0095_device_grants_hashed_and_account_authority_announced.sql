-- A device code is a bearer secret: whoever holds it collects the token its
-- grant mints. It was stored and compared in plaintext while every other
-- bearer (browser sessions, personal access tokens, logout tokens) keeps only
-- its SHA-256, so a read of this table handed out every pending approval. It
-- now keeps the same digest, which the server computes the same way
-- (`token_hash`: the raw 32-byte SHA-256 of the code's UTF-8 bytes).
--
-- Existing grants are hashed in place rather than dropped: `sha256()` is built
-- in since PostgreSQL 11, so no pending approval is lost to the upgrade.
ALTER TABLE device_grants ADD COLUMN device_code_hash BYTEA;
UPDATE device_grants SET device_code_hash = sha256(convert_to(device_code, 'UTF8'));
ALTER TABLE device_grants
    ALTER COLUMN device_code_hash SET NOT NULL,
    DROP COLUMN device_code,
    ADD CONSTRAINT device_grants_device_code_hash_key UNIQUE (device_code_hash);

-- RFC 8628 binds a grant to the client that started it (§3.4 `client_id`)
-- and paces each device code's polling (§3.5): a poll sooner than the grant's
-- interval is answered `slow_down` and the interval grows by five seconds.
-- Grants started before this migration name no client; they are the e6irc
-- command-line client's, which starts every grant as `e6irc-cli`.
ALTER TABLE device_grants
    ADD COLUMN client_id TEXT NOT NULL DEFAULT 'e6irc-cli'
        CHECK (octet_length(client_id) BETWEEN 1 AND 64),
    ADD COLUMN poll_interval_seconds INTEGER NOT NULL DEFAULT 5
        CHECK (poll_interval_seconds BETWEEN 1 AND 600),
    ADD COLUMN last_polled_at TIMESTAMPTZ;
ALTER TABLE device_grants ALTER COLUMN client_id DROP DEFAULT;

-- An account's authority is announced from the table, as a credential's is
-- (0077): several servers may serve one database, and a suspension, a
-- deletion or a primary password change committed by any of them must end the
-- account's IRC sessions and bouncer attachments on every one. The accounts
-- row counts each change of its authority -- its suspended flag (bit 2)
-- flipping, its primary password added, replaced or removed, by whichever
-- path -- and every created row, counted change and deleted row notifies the
-- credential channel with the account's id and folded name. A listener
-- re-reads the row and acts once per counted change it has not already
-- applied itself; a rolled-back change announces nothing.
ALTER TABLE accounts ADD COLUMN authority_generation BIGINT NOT NULL DEFAULT 0;

CREATE FUNCTION count_account_suspension_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.flags & 2) <> (NEW.flags & 2) THEN
        NEW.authority_generation := OLD.authority_generation + 1;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER accounts_suspension_counted
BEFORE UPDATE OF flags ON accounts
FOR EACH ROW EXECUTE FUNCTION count_account_suspension_change();

CREATE FUNCTION count_primary_password_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE accounts SET authority_generation = authority_generation + 1
    WHERE id = CASE TG_OP WHEN 'DELETE' THEN OLD.account_id ELSE NEW.account_id END;
    RETURN NULL;
END;
$$;

CREATE TRIGGER primary_password_added
AFTER INSERT ON account_credentials
FOR EACH ROW WHEN (NEW.kind = 'local_password')
EXECUTE FUNCTION count_primary_password_change();

CREATE TRIGGER primary_password_replaced
AFTER UPDATE OF argon2_hash ON account_credentials
FOR EACH ROW WHEN (NEW.kind = 'local_password' AND OLD.argon2_hash IS DISTINCT FROM NEW.argon2_hash)
EXECUTE FUNCTION count_primary_password_change();

CREATE TRIGGER primary_password_removed
AFTER DELETE ON account_credentials
FOR EACH ROW WHEN (OLD.kind = 'local_password')
EXECUTE FUNCTION count_primary_password_change();

CREATE FUNCTION notify_account_authority_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    announced accounts;
BEGIN
    IF TG_OP = 'DELETE' THEN
        announced := OLD;
    ELSE
        announced := NEW;
    END IF;
    PERFORM pg_notify(
        'e6irc_credential_changed',
        'account:' || announced.id || ':' || announced.name_folded
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER accounts_created
AFTER INSERT ON accounts
FOR EACH ROW EXECUTE FUNCTION notify_account_authority_changed();

CREATE TRIGGER accounts_authority_changed
AFTER UPDATE ON accounts
FOR EACH ROW WHEN (OLD.authority_generation IS DISTINCT FROM NEW.authority_generation)
EXECUTE FUNCTION notify_account_authority_changed();

CREATE TRIGGER accounts_deleted
AFTER DELETE ON accounts
FOR EACH ROW EXECUTE FUNCTION notify_account_authority_changed();
