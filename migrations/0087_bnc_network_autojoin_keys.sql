-- An IRC network's autojoin channel may be keyed (`+k`). The key is a secret
-- of the channel's members, so it is stored sealed like the network's other
-- upstream secrets (SASL and server passwords, 0007 and 0061), and never in
-- `autojoin`, which the API returns.
--
-- `autojoin_keys_sealed[i]` is the sealed key of `autojoin[i]`, or NULL for a
-- channel joined without one: two parallel arrays, held to one length. Only
-- an IRC channel has a key; a bridge's rooms and channel ids never do.
ALTER TABLE bnc_networks
    ADD COLUMN autojoin_keys_sealed TEXT[];

UPDATE bnc_networks
SET autojoin_keys_sealed = array_fill(NULL::TEXT, ARRAY[cardinality(autojoin)]);

ALTER TABLE bnc_networks
    ALTER COLUMN autojoin_keys_sealed SET NOT NULL,
    ALTER COLUMN autojoin_keys_sealed SET DEFAULT '{}',
    ADD CONSTRAINT bnc_networks_autojoin_keys_paired
        CHECK (cardinality(autojoin_keys_sealed) = cardinality(autojoin)),
    ADD CONSTRAINT bnc_networks_autojoin_keys_irc_only
        CHECK (kind = 'irc' OR cardinality(array_remove(autojoin_keys_sealed, NULL)) = 0);
