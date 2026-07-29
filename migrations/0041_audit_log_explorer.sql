-- Exact actor/action/target filters page newest-first by the stable audit id.
-- Matching compound indexes keep those administrator queries bounded by the
-- requested page rather than the age of the audit trail.
CREATE INDEX audit_log_actor_id_idx ON audit_log (actor, id DESC);
CREATE INDEX audit_log_action_id_idx ON audit_log (action, id DESC);
CREATE INDEX audit_log_target_id_idx ON audit_log (target, id DESC);
