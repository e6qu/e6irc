-- A BNC network's stored driver kind is a closed set. Treating an unknown
-- value as `irc` can reinterpret bridge configuration and credentials as a
-- plain IRC upstream, so invalid values must make migration/startup fail
-- instead of acquiring fallback semantics at read time.
ALTER TABLE bnc_networks
    ADD CONSTRAINT bnc_networks_kind_valid
    CHECK (kind IN ('irc', 'matrix', 'discord', 'slack'));
