-- Preserve the verified Shauth identity shown by the application and its
-- deployment-neutral post-deployment validation endpoint.
ALTER TABLE web_sessions ADD COLUMN oidc_email TEXT;
ALTER TABLE web_sessions ADD COLUMN oidc_role TEXT
    CHECK (oidc_role IS NULL OR oidc_role IN ('developer', 'admin'));
