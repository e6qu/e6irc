-- RP-initiated (front-channel) logout needs the OIDC id token as the
-- `id_token_hint`, and the provider it came from to find that provider's
-- end-session endpoint. Both are null for password/PAT sessions, which have
-- no upstream SSO session to end.
ALTER TABLE web_sessions ADD COLUMN id_token      TEXT;
ALTER TABLE web_sessions ADD COLUMN oidc_provider TEXT;
