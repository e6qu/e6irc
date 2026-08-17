-- Backfill account_claim into persisted OIDC providers.
--
-- #295 ("Reject implicit identity and history fallbacks") added
-- OidcProviderConfig::account_claim without a serde default, deliberately: the
-- claim that maps an identity to a local account must be stated, not guessed.
-- No migration accompanied it, so any deployment whose server_settings row was
-- written before that change cannot deserialize its own settings and refuses to
-- start:
--
--   e6ircd: failed to start: invalid persisted server settings:
--           missing field `account_claim`
--
-- This is not the same question as the config file's. For a row written before
-- the field existed, the value is not a guess: the code at the time called
-- claims.preferred_username() unconditionally, so preferred_username is what
-- those providers already did. Writing it in preserves each existing account
-- mapping exactly rather than choosing a new one, and leaves #295's requirement
-- intact for every provider configured from here on.
UPDATE server_settings
SET settings = jsonb_set(
        settings,
        '{oidc_providers}',
        (
            SELECT jsonb_agg(
                CASE
                    WHEN provider ? 'account_claim' THEN provider
                    ELSE provider || '{"account_claim": "preferred_username"}'::jsonb
                END
                ORDER BY ordinality
            )
            FROM jsonb_array_elements(settings -> 'oidc_providers')
                 WITH ORDINALITY AS elements(provider, ordinality)
        )
    )
WHERE jsonb_typeof(settings -> 'oidc_providers') = 'array'
  AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements(settings -> 'oidc_providers') AS provider
      WHERE NOT (provider ? 'account_claim')
  );
