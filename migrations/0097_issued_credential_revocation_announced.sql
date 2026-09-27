-- An IRC session and a bouncer attachment remember the credential that
-- opened them, and revoking an app password or a personal access token ends
-- exactly what that credential opened, whichever process deletes it. The
-- browser-credential announcement (0077) names a token by its digest, which
-- a server holding only the row id cannot match, and app passwords announced
-- nothing. Each committed deletion of an app password or
-- a personal access token -- by its revocation endpoint, account recovery,
-- maintenance pruning, or the account's deletion by cascade -- now notifies
-- the credential channel with the credential's kind and row id. The
-- deletion is the revocation, so a listener need not read the row again; a
-- rolled-back deletion announces nothing.
CREATE FUNCTION notify_issued_credential_revoked() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify(
        'e6irc_credential_changed',
        TG_ARGV[0] || ':' || OLD.id
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER app_password_revoked
AFTER DELETE ON account_credentials
FOR EACH ROW WHEN (OLD.kind = 'app_password')
EXECUTE FUNCTION notify_issued_credential_revoked('app_password');

CREATE TRIGGER api_token_revoked
AFTER DELETE ON api_tokens
FOR EACH ROW EXECUTE FUNCTION notify_issued_credential_revoked('api_token');
