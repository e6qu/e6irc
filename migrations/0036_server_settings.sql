-- The web console's typed, revisioned source of operational configuration.
-- Bootstrap-only values (database URL, secrets key source, HTTP bind) stay in
-- the deployment file because they are prerequisites for reaching this table.
CREATE TABLE server_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    revision BIGINT NOT NULL CHECK (revision > 0),
    settings JSONB NOT NULL CHECK (jsonb_typeof(settings) = 'object'),
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
