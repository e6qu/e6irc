-- A BNC network can be paused without deletion (DESIGN §12). A disabled
-- network keeps its config and buffers but runs no always-on driver: it is
-- skipped at boot and its driver is stopped when disabled at runtime.
ALTER TABLE bnc_networks ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT true;
