-- Migration 0059 recorded each app password it revoked with `target` set to
-- the account's display name. Every other audit row names an account by its
-- RFC1459-folded name, and the account's own security-activity view matches on
-- exactly that — so for any account whose name has an upper-case letter (or
-- one of []\~) those revocations were invisible to the person they were about.
-- Fold them the way 0054 folds bouncer targets. 0059 itself is not edited: it
-- has been applied.
UPDATE audit_log
   SET target = translate(lower(target), '[]\~', '{}|^')
 WHERE actor = 'migration:0059'
   AND action = 'ACCOUNT_APP_PASSWORD_REVOKE'
   AND target <> translate(lower(target), '[]\~', '{}|^');
