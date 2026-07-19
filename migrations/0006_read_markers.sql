-- Per-account read markers (IRCv3 draft/read-marker, DESIGN §11). One
-- marker per (account, casefolded target); the newest timestamp wins.

CREATE TABLE read_markers (
    account_id BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    marker_ts TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (account_id, target)
);
