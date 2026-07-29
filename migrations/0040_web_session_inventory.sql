-- Stable owner-scoped identifiers and bounded client provenance make durable
-- browser sessions manageable without exposing their token hashes.
ALTER TABLE web_sessions
    ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY,
    ADD COLUMN user_agent VARCHAR(512);

ALTER TABLE web_sessions
    ADD CONSTRAINT web_sessions_id_unique UNIQUE (id),
    ADD CONSTRAINT web_sessions_user_agent_nonempty
        CHECK (user_agent IS NULL OR char_length(user_agent) > 0);
