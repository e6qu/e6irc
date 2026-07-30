-- Personal access tokens are explicit, bounded grants. Existing unscoped
-- tokens retain their old authority for a bounded 90-day transition instead
-- of becoming immortal compatibility bearers.

ALTER TABLE api_tokens
    ADD COLUMN scopes TEXT[] NOT NULL
        DEFAULT ARRAY['read', 'write', 'administrator', 'irc']::TEXT[];

UPDATE api_tokens
SET expires_at = GREATEST(now(), created_at) + interval '90 days'
WHERE expires_at IS NULL OR expires_at <= created_at;

ALTER TABLE api_tokens
    ALTER COLUMN expires_at SET NOT NULL,
    ADD CONSTRAINT api_tokens_scopes_closed
        CHECK (
            cardinality(scopes) BETWEEN 1 AND 4
            AND scopes <@ ARRAY['read', 'write', 'administrator', 'irc']::TEXT[]
            AND cardinality(scopes) =
                ('read' = ANY(scopes))::INTEGER
                + ('write' = ANY(scopes))::INTEGER
                + ('administrator' = ANY(scopes))::INTEGER
                + ('irc' = ANY(scopes))::INTEGER
        ),
    ADD CONSTRAINT api_tokens_expiry_after_creation
        CHECK (expires_at > created_at);
