-- An IRC network's server password: the argument of the `PASS` line a private
-- server requires before `CAP LS`, `NICK` and `USER`, answering `464` when it
-- is wrong or missing.
--
-- It is a secret like the SASL password, and stored the same way: sealed with
-- the server master key, never readable back through the API. Nullable,
-- because nearly every network has none, and there is no value to backfill: a
-- network that worked without one keeps working without one.

ALTER TABLE bnc_networks ADD COLUMN IF NOT EXISTS server_password_sealed TEXT;

-- Only a network that registers over IRC sends `PASS`; a bridge has no such
-- line to carry one.
ALTER TABLE bnc_networks DROP CONSTRAINT IF EXISTS bnc_networks_server_password_for_irc;
ALTER TABLE bnc_networks
    ADD CONSTRAINT bnc_networks_server_password_for_irc
    CHECK (server_password_sealed IS NULL OR kind = 'irc');
