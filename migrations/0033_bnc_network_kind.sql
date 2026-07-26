-- Runtime-managed bridges: a BNC network's driver kind. Existing rows are
-- IRC upstreams, so the column defaults to 'irc'; matrix/discord/slack rows
-- are created (and started as the matching bridge driver) by the console /
-- REST API when the binary was built with that feature.
ALTER TABLE bnc_networks ADD COLUMN kind TEXT NOT NULL DEFAULT 'irc';
