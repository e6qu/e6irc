-- Support the administrator account directory and the existing owner-scoped
-- identity/channel reads without scanning the child tables for every account.

CREATE INDEX oidc_identities_account_idx
    ON oidc_identities (account_id);

CREATE INDEX channels_founder_account_idx
    ON channels (founder_account_id);
