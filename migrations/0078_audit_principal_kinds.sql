-- An audit row's actor and target were bare names from several namespaces:
-- account names, configured operator names, nicknames, channels, masks. The
-- same spelling can live in more than one -- an operator block `root` beside
-- an account `root`, a nick `eve` beside the account `eve` -- so an account's
-- own security activity and export, which selected every row whose actor or
-- target equalled its name, also served operator actions and other people's
-- KILL/SETHOST/K-line rows to whoever registered the colliding account name.
--
-- Every row now records which namespace each name belongs to, and account
-- views select only rows that name the account *as an account*.
ALTER TABLE audit_log
    ADD COLUMN actor_kind TEXT,
    ADD COLUMN target_kind TEXT;

-- Existing rows are classified only where the writing code proves the kind.
-- `legacy` marks a name whose namespace cannot be proven from the row: an
-- IRC-issued K/D/X-line recorded the operator's nick while an HTTP one
-- recorded the administrator's account, and an IRC KILL recorded the operator
-- name while an HTTP disconnect recorded the account, under the same action.
-- A `legacy` name is shown to administrators as it always was and is never
-- shown to an account as its own activity.
UPDATE audit_log SET
    actor_kind = CASE
        -- An account name never holds ':'. `oidc:<issuer>` provisioned an
        -- account; `host:recover-administrator` and `migration:0059` are
        -- commands run on the host.
        WHEN actor LIKE 'oidc:%' THEN 'provider'
        WHEN position(':' IN actor) > 0 THEN 'host'
        WHEN action = 'SECRET_ROTATE' THEN 'host'
        -- The start-up credential import wrote `bootstrap`, which an account
        -- may also be named.
        WHEN action = 'CONFIG' AND actor = 'bootstrap' THEN 'legacy'
        WHEN action IN ('OPER', 'SETHOST') THEN 'operator'
        WHEN action IN ('KILL', 'KLINE', 'DLINE', 'XLINE', 'UNKLINE', 'UNDLINE', 'UNXLINE')
            THEN 'legacy'
        WHEN action = 'CONFIG'
            OR action LIKE 'ACCOUNT\_%'
            OR action LIKE 'CHANNEL\_%'
            OR action LIKE 'NICK\_%'
            OR action LIKE 'NETWORK\_%'
            THEN 'account'
        ELSE 'legacy'
    END,
    target_kind = CASE
        WHEN action IN ('ACCOUNT_INVITATION_CREATE', 'ACCOUNT_INVITATION_REVOKE') THEN 'invitation'
        WHEN action = 'ADMINISTRATOR_RECOVERY'
            OR action LIKE 'ACCOUNT\_%'
            OR action LIKE 'NICK\_%'
            THEN 'account'
        WHEN action LIKE 'CHANNEL\_%' THEN 'channel'
        WHEN action LIKE 'NETWORK\_%' THEN 'network'
        WHEN action IN ('CONFIG', 'SECRET_ROTATE') THEN 'server'
        WHEN action = 'OPER' THEN 'operator'
        WHEN action IN ('KILL', 'SETHOST') THEN 'nick'
        WHEN action IN ('KLINE', 'DLINE', 'XLINE', 'UNKLINE', 'UNDLINE', 'UNXLINE') THEN 'mask'
        ELSE 'legacy'
    END;

ALTER TABLE audit_log
    ALTER COLUMN actor_kind SET NOT NULL,
    ALTER COLUMN target_kind SET NOT NULL,
    ADD CONSTRAINT audit_log_actor_kind_known CHECK (actor_kind IN (
        'account', 'operator', 'nick', 'channel', 'network', 'mask', 'server',
        'provider', 'host', 'invitation', 'legacy')),
    ADD CONSTRAINT audit_log_target_kind_known CHECK (target_kind IN (
        'account', 'operator', 'nick', 'channel', 'network', 'mask', 'server',
        'provider', 'host', 'invitation', 'legacy'));
