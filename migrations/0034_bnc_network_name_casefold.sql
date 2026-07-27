-- Network-name selection is now case-insensitive end-to-end, matching every
-- other IRC identifier (nicks, channels, account names) and the RFC1459 fold
-- already applied to the owner in the in-memory registry key. Without this a
-- user who owns network `foo` and types `/network Foo` would miss their own
-- network (a case-sensitive `n.name = $2` lookup) and, if an operator-defined
-- shared network `Foo` existed, silently attach to *that* instead of their own
-- (DESIGN §2: no silent fallbacks / cross-owner substitution).
--
-- Network names are restricted to [A-Za-z0-9._-] at creation (`network_name_ok`),
-- which excludes RFC1459's []\^ <-> {}|~ specials, so `lower(name)` is exactly
-- the RFC1459 fold the registry key uses — the two lookups agree by construction.
--
-- Replace the case-sensitive uniqueness with a case-insensitive one so `foo` and
-- `Foo` can no longer coexist as two networks under the same owner (which would
-- make `/network foo` ambiguous and could fold-collide in the registry on load).
ALTER TABLE bnc_networks DROP CONSTRAINT bnc_networks_account_id_name_key;
CREATE UNIQUE INDEX bnc_networks_account_name_folded_idx
    ON bnc_networks (account_id, lower(name));

-- `bnc_buffer.network` is keyed by the same selector the registry uses, which is
-- now casefolded (like `owner` in 0025). Fold existing rows so a network's
-- backlog is not orphaned under a spelling nothing looks up any more. `lower` is
-- the exact fold here for the same reason as above (names are ASCII, []\^-free).
UPDATE bnc_buffer
   SET network = lower(network)
 WHERE network <> lower(network);
