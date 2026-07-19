-- OAuth 2.0 Device Authorization Grant (RFC 8628), brokered by e6ircd
-- itself: a headless client starts a grant, the user approves it in the
-- browser (by the short user_code), and the client polls for a token.

CREATE TABLE device_grants (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Secret the client polls with.
    device_code TEXT NOT NULL UNIQUE,
    -- Short human-entered code, shown to the user.
    user_code TEXT NOT NULL UNIQUE,
    -- Set when the user approves; NULL while pending.
    account TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX device_grants_user_code_idx ON device_grants (user_code);
