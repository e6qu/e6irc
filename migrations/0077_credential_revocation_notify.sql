-- A long-lived authenticated socket (the web chat's /ws/ui) is opened by one
-- browser session or personal access token and must end when that credential
-- does. Credentials are revoked by many paths -- logout, single and bulk
-- session revocation, a password change, identity unlink, provider logout,
-- the per-account session cap, token revocation, suspension, recovery,
-- account deletion (by cascade), maintenance pruning -- and by processes other
-- than the one holding the socket (the recovery command, another replica).
-- Announcing the change from the table itself means no revocation path, now
-- or later, can forget to: every committed DELETE of a row, and every UPDATE
-- that changes what the row authorizes, notifies the channel with the kind and
-- the row's token digest. A listener then re-reads the credential and closes
-- the sockets it no longer authorizes. Notifications are delivered only on
-- commit, so a rolled-back revocation closes nothing.
CREATE FUNCTION notify_credential_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify(
        'e6irc_credential_changed',
        TG_ARGV[0] || ':' || encode(OLD.token_hash, 'hex')
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER web_sessions_changed
AFTER DELETE OR UPDATE ON web_sessions
FOR EACH ROW EXECUTE FUNCTION notify_credential_changed('session');

CREATE TRIGGER api_tokens_changed
AFTER DELETE OR UPDATE ON api_tokens
FOR EACH ROW EXECUTE FUNCTION notify_credential_changed('token');
