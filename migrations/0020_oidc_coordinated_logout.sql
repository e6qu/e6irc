ALTER TABLE web_sessions ADD COLUMN oidc_issuer  TEXT;
ALTER TABLE web_sessions ADD COLUMN oidc_subject TEXT;
ALTER TABLE web_sessions ADD COLUMN oidc_sid     TEXT;

CREATE INDEX web_sessions_oidc_sid
    ON web_sessions (oidc_issuer, oidc_sid)
    WHERE oidc_issuer IS NOT NULL AND oidc_sid IS NOT NULL;
CREATE INDEX web_sessions_oidc_subject
    ON web_sessions (oidc_issuer, oidc_subject)
    WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL;

CREATE TABLE oidc_logout_tokens (
    issuer     TEXT        NOT NULL,
    jti        TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (issuer, jti)
);
