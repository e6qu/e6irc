-- One process serves a database; any other is a standby (DESIGN §18). The
-- serving process holds this one row's lease and renews it every few seconds;
-- a standby takes the lease once it is released (a graceful stop) or once its
-- last renewal is older than `ttl_ms` (a crash). Every comparison is against
-- PostgreSQL's own clock, so the hosts' clocks never have to agree.
--
-- `holder` identifies the process for its lifetime (a random identifier it
-- draws at start), `holder_label` names it for an operator (the address it
-- connects from, its process id and its release), and `epoch` counts
-- acquisitions: a renewal names the epoch it holds, so a process whose lease
-- was taken and given back can never renew the later one.
CREATE TABLE serving_lease (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    holder UUID,
    holder_label TEXT,
    epoch BIGINT NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    acquired_at TIMESTAMPTZ,
    renewed_at TIMESTAMPTZ,
    ttl_ms INTEGER NOT NULL CHECK (ttl_ms > 0),
    CONSTRAINT serving_lease_held_whole CHECK (
        (holder IS NULL) = (holder_label IS NULL)
        AND (holder IS NULL OR (acquired_at IS NOT NULL AND renewed_at IS NOT NULL))
    )
);

INSERT INTO serving_lease (id, ttl_ms) VALUES (1, 15000);

-- The connections the holder has opened, recorded as each one is made, so the
-- next holder can end every one of them (`pg_terminate_backend`) and nothing
-- the previous holder had in flight can commit after the takeover. A backend
-- is named by its process id and its start time together: a process id alone
-- is reused by the next connection PostgreSQL starts, which may be anyone's.
-- `application_name` is not used to find them because an operator may state
-- it in the database URL.
CREATE TABLE serving_lease_backends (
    holder UUID NOT NULL,
    pid INTEGER NOT NULL,
    backend_start TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (holder, pid, backend_start)
);

-- The fence every connection of the serving process passes before it is used
-- (the pool's after-connect hook): it refuses unless `me` holds the lease, and
-- records the connection as the holder's. The lease row is read `FOR SHARE`,
-- so a connection made while another process is taking the lease waits for
-- that takeover to commit and is then refused, instead of slipping in behind
-- it. Connections of `me` that have since closed are forgotten here, so the
-- table holds only live ones.
CREATE FUNCTION serving_lease_register_backend(me UUID) RETURNS VOID
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM serving_lease WHERE id = 1 AND holder = me FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'this process does not hold the serving lease; another process serves this database'
            USING ERRCODE = 'E6L01';
    END IF;
    DELETE FROM serving_lease_backends b
    WHERE b.holder = me
      AND NOT EXISTS (
          SELECT 1 FROM pg_stat_activity a
          WHERE a.pid = b.pid AND a.backend_start = b.backend_start
      );
    INSERT INTO serving_lease_backends (holder, pid, backend_start)
    SELECT me, a.pid, a.backend_start
    FROM pg_stat_activity a
    WHERE a.pid = pg_backend_pid();
END;
$$;

-- A standby waits on this channel: every change of holder, a release
-- included, is announced, so a graceful handoff is taken at once rather than
-- at the standby's next poll. Notifications are delivered only on commit.
CREATE FUNCTION notify_serving_lease_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.holder IS DISTINCT FROM OLD.holder OR NEW.epoch <> OLD.epoch THEN
        PERFORM pg_notify('e6irc_serving_lease', NEW.epoch::text);
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER serving_lease_changed
AFTER UPDATE ON serving_lease
FOR EACH ROW EXECUTE FUNCTION notify_serving_lease_changed();
