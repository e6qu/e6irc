-- A BNC read marker is account-owned data: it has no meaning once its account
-- is gone. The original foreign key carried no deletion rule, so PostgreSQL
-- refused to delete any account that had ever sent one MARKREAD through the
-- bouncer, and permanent account deletion failed for that account forever.
-- Every other account-owned table cascades; this one now does too.
ALTER TABLE bnc_read_markers
    DROP CONSTRAINT bnc_read_markers_account_id_fkey,
    ADD CONSTRAINT bnc_read_markers_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;
