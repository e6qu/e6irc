-- Account identities are BIGINT throughout the durable schema. The initial
-- BNC read-marker migration accidentally narrowed this foreign key to INTEGER,
-- preventing markers for valid accounts above the 32-bit range and making the
-- Rust query boundary disagree with accounts.id.
ALTER TABLE bnc_read_markers
    ALTER COLUMN account_id TYPE BIGINT;
