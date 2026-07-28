-- Bounded operational history. The payload uses the same closed, typed schema
-- served by the live API; retention is enforced by every sampler write.
CREATE TABLE observability_samples (
    sampled_at_ms BIGINT PRIMARY KEY CHECK (sampled_at_ms > 0),
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot) = 'object')
);
