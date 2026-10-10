-- Durable ring positions (DESIGN §10, §19.3): a client's `ReplayCursor` names
-- a network ring's epoch and a position in it, and stays valid across a
-- restart that stored every line the ring took.
--
-- Each stored backlog line keeps the ring position it took. Each backlog
-- (configured or stored network alike, keyed as `bnc_buffer` is) has one ring
-- epoch; a stop that stored every line records the last position it handed
-- out (`clean_through`), and the next start continues that epoch after it. A
-- start clears it at once, so a process that then ends without storing
-- everything — a crash, a storage failure — leaves no claim behind, and the
-- start after it begins a new epoch: every cursor of the old one is refused
-- and its client replays the whole ring, as before.
ALTER TABLE bnc_buffer ADD COLUMN seq BIGINT CHECK (seq > 0);

CREATE TABLE bnc_ring_positions (
    owner TEXT NOT NULL,
    network TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    clean_through BIGINT CHECK (clean_through > 0),
    PRIMARY KEY (owner, network)
);
