-- A stored backlog line of a database-defined network now names that
-- network's row, and dies with it.
--
-- `bnc_buffer` was keyed only by the text pair (owner, network). A network
-- could therefore be deleted while its driver's persistence task still had a
-- line in flight: the late INSERT landed after the delete, the row outlived its
-- network, and a network re-created under the same name replayed its previous
-- life's backlog. Handlers now stop the driver before deleting, and this makes
-- the class impossible rather than merely avoided: the persistence task writes
-- the id it resolved when it started, so a line for a network that no longer
-- exists fails its foreign key loudly instead of inserting, and deleting a
-- network (or its account) cascades to its backlog.
--
-- A network defined in configuration has no `bnc_networks` row and carries no
-- id: a server-level one (owner `*`) never does, and neither does one the
-- configuration assigns to an account. Rows of the latter cannot be told apart
-- from pre-existing orphans here, so nothing is deleted by this migration.

ALTER TABLE bnc_buffer
    ADD COLUMN network_id BIGINT REFERENCES bnc_networks (id) ON DELETE CASCADE;

UPDATE bnc_buffer b
   SET network_id = n.id
  FROM bnc_networks n
  JOIN accounts a ON a.id = n.account_id
 WHERE b.owner <> '*'
   AND b.owner = a.name_folded
   AND b.network = lower(n.name);

ALTER TABLE bnc_buffer
    ADD CONSTRAINT bnc_buffer_server_networks_have_no_row
    CHECK (owner <> '*' OR network_id IS NULL);

-- The cascade from `bnc_networks` deletes by this column.
CREATE INDEX bnc_buffer_network_id_idx
    ON bnc_buffer (network_id)
    WHERE network_id IS NOT NULL;
