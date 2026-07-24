-- audit_log_created_idx (0013) indexes (created_at DESC), but the only reader —
-- list_audit_log — orders by `id DESC`, and nothing filters or orders on
-- created_at. The index served no query; it was pure write-time overhead on
-- every audited oper action. Drop it. (id order ≡ insertion order, so the
-- primary-key index already gives the intended most-recent-first listing.)
DROP INDEX IF EXISTS audit_log_created_idx;
