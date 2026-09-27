-- Several processes write the managed settings: every replica's console (more
-- than one replica may serve one database) and `e6ircd rotate-secrets`, which
-- re-seals the stored credentials and bumps the revision. Each running server
-- keeps the stored revision in memory -- the console answers from it and
-- compares every save against it, and storage maintenance, the observability
-- sampler and the BNC attach listener follow it -- so a revision another
-- process committed must reach it, or its console refuses every later save as
-- stale until it restarts. As with 0077's credential announcements, the table
-- announces every committed write itself, so no writer, now or later, can
-- forget to. Notifications are delivered only on commit.
CREATE FUNCTION notify_server_settings_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('e6irc_server_settings_changed', NEW.revision::text);
    RETURN NULL;
END;
$$;

CREATE TRIGGER server_settings_changed
AFTER INSERT OR UPDATE ON server_settings
FOR EACH ROW EXECUTE FUNCTION notify_server_settings_changed();
