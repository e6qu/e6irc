-- Two things a stored IRC network keeps across a process restart and an edit
-- (DESIGN §10.3).
--
-- 1. The channels its session was in. A channel is remembered once the
--    upstream's JOIN echo for our own nick confirms it, and forgotten on a
--    PART, a KICK of us, a rejoin the upstream refuses, or the owner removing
--    it; the driver that starts next rejoins them with the configured autojoin.
--    A key the channel is joined with is a secret of its members, so it is
--    stored sealed like a configured autojoin key (0087), and only when the
--    server has a master key to seal it with.
--
--    The rows die with their network. The registry rewrites a network's
--    whole set after each change, so the set is never longer than the 512
--    channels a session tracks; the bound here is that limit, enforced where
--    the rows are written.
CREATE TABLE bnc_remembered_channels (
    network_id BIGINT NOT NULL REFERENCES bnc_networks (id) ON DELETE CASCADE,
    -- One JOIN parameter: RFC 1459's 200 bytes at most, no separators.
    channel TEXT NOT NULL CHECK (
        octet_length(channel) BETWEEN 2 AND 200
        AND channel !~ '[[:space:],[:cntrl:]]'
    ),
    key_sealed TEXT,
    PRIMARY KEY (network_id, channel)
);

-- 2. A TLS client certificate, presented to the upstream: SASL EXTERNAL where
--    the network offers it, and otherwise recognised by its fingerprint
--    (NickServ CertFP, which is how OFTC authenticates). The certificate is
--    public; its private key is sealed with the master key like every other
--    upstream secret, and never readable back through the API. Only an IRC
--    network over TLS can present one.
ALTER TABLE bnc_networks
    ADD COLUMN client_certificate TEXT,
    ADD COLUMN client_key_sealed TEXT,
    ADD CONSTRAINT bnc_networks_client_certificate_paired
        CHECK ((client_certificate IS NULL) = (client_key_sealed IS NULL)),
    ADD CONSTRAINT bnc_networks_client_certificate_irc_tls
        CHECK (client_certificate IS NULL OR (kind = 'irc' AND tls));
