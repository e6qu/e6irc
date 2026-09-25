-- Per-account password-attempt throttle. Per-address limits alone do not bound
-- guessing against one account: an attacker with many source addresses (a
-- botnet, or simply several IPv6 prefixes) gets a fresh budget from each. Every
-- password check -- web login, app-password exchange, the current password of
-- a password change, SASL PLAIN and NickServ IDENTIFY in the core, and the
-- bouncer's attach authentication -- reserves one attempt here first, keyed by
-- the folded name whether or not an account holds it (so a refusal says
-- nothing about which names exist). A verified password clears the row; a row
-- whose window has passed is deleted on the next reservation.
CREATE TABLE login_attempts (
    name_folded TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL CHECK (attempts > 0),
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX login_attempts_window_started_at_idx ON login_attempts (window_started_at);
