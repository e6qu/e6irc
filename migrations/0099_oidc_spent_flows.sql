-- An OpenID Connect sign-in in progress is carried by the browser, sealed
-- into its state cookie under keys derived from the master key, so any
-- process of the deployment -- a restarted one, or a standby that took
-- over -- can finish it. Each flow is answered once: the callback's code
-- exchange first inserts the flow's OAuth `state` here (as its SHA-256), and
-- a flow already present is refused, so a kept copy of the cookie never makes
-- any process present the client secret to the token endpoint again. A row
-- lives as long as its flow could; storage maintenance deletes it after.
CREATE TABLE oidc_spent_flows (
    state_digest BYTEA PRIMARY KEY CHECK (octet_length(state_digest) = 32),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX oidc_spent_flows_expires_at_idx ON oidc_spent_flows (expires_at);
