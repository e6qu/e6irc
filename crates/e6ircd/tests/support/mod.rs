//! Shared setup for the PostgreSQL-backed integration tests.
//!
//! Every one of these tests used to run against the one database in
//! `E6IRC_TEST_DATABASE_URL` and start by truncating it. That makes any two of
//! them mutually destructive: run in parallel — which is what `cargo test` does
//! within a test binary — one test's `TRUNCATE` deletes the rows another just
//! wrote. It showed up as three bouncer tests failing together and passing
//! under `--test-threads=1`.
//!
//! A per-test database removes the sharing rather than scheduling around it.
//! `E6IRC_TEST_DATABASE_URL` becomes the *administrative* connection used to
//! create them, and each test gets one named after itself.

use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;

/// The administrative URL, used only to create per-test databases.
fn admin_url() -> String {
    std::env::var("E6IRC_TEST_DATABASE_URL")
        .expect("E6IRC_TEST_DATABASE_URL must be set for --ignored database tests")
}

/// Databases this process has already created, so a test that asks twice keeps
/// the rows it wrote the first time.
/// Which thread first asked for each database. libtest runs each test on its
/// own thread, so a second thread asking for the same name means two tests are
/// sharing a database — the exact thing this module exists to prevent, and the
/// easy mistake to make by naming the database after a shared helper instead of
/// the test that called it. It is caught here rather than surfacing later as
/// one test mysteriously failing when another runs.
fn prepared() -> &'static Mutex<std::collections::HashMap<String, ThreadId>> {
    static PREPARED: OnceLock<Mutex<std::collections::HashMap<String, ThreadId>>> = OnceLock::new();
    PREPARED.get_or_init(Default::default)
}

/// A URL for `test`'s own database, dropping and recreating it the first time
/// the test asks. `test` must be unique within the run — the test function's
/// own name is what every caller passes.
///
/// Callers still run their schema migrations through `db::connect_and_migrate`;
/// this only hands out an empty database to run them against.
pub async fn test_db(test: &str) -> String {
    let admin = admin_url();
    let name = database_name(test);
    let me = std::thread::current().id();
    let first_claim = {
        let mut registry = prepared().lock().expect("test database registry");
        match registry.get(&name) {
            // Same test asking again — it keeps the rows it already wrote.
            Some(&owner) if owner == me => false,
            Some(_) => panic!(
                "two tests both asked for the database {name:?}: pass each test's own \
                 name to test_db, not a shared helper's"
            ),
            None => {
                registry.insert(name.clone(), me);
                true
            }
        }
    };
    if first_claim {
        create(&admin, &name).await;
    }
    with_database(&admin, &name)
}

/// `test` as a PostgreSQL identifier: lowercase, `[a-z0-9_]` only, and short
/// enough to survive the 63-byte identifier limit with the prefix.
fn database_name(test: &str) -> String {
    let mut out = String::from("e6irc_t_");
    for c in test.chars().take(50) {
        out.push(match c.to_ascii_lowercase() {
            c @ ('a'..='z' | '0'..='9' | '_') => c,
            _ => '_',
        });
    }
    out
}

async fn create(admin: &str, name: &str) {
    let pool = sqlx::PgPool::connect(admin)
        .await
        .expect("connect to the administrative database");
    // Dropped first so a run starts from an empty database even if a previous
    // run died before it could clean up. `WITH (FORCE)` closes connections a
    // killed test left behind, which would otherwise make the DROP hang.
    let drop_it = format!(r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#);
    let create_it = format!(r#"CREATE DATABASE "{name}""#);
    // `raw_sql`, not `query`: PostgreSQL refuses CREATE/DROP DATABASE in the
    // extended (prepared) protocol that `query` uses, and a database name is an
    // identifier, which no protocol lets you bind as a parameter. `AssertSqlSafe`
    // is answerable here because `database_name` above builds the only
    // interpolated value out of `[a-z0-9_]` — nothing a caller passes survives
    // into the statement.
    sqlx::raw_sql(sqlx::AssertSqlSafe(drop_it))
        .execute(&pool)
        .await
        .expect("drop the previous test database");
    sqlx::raw_sql(sqlx::AssertSqlSafe(create_it))
        .execute(&pool)
        .await
        .expect("create the test database");
    pool.close().await;
}

/// `admin` with its database path replaced by `name`, query string preserved.
fn with_database(admin: &str, name: &str) -> String {
    let (base, query) = admin
        .split_once('?')
        .map_or((admin, None), |(b, q)| (b, Some(q)));
    // Everything up to the last `/` is scheme + credentials + authority; what
    // follows is the database name this replaces.
    let authority = base.rsplit_once('/').expect("a database URL has a path").0;
    match query {
        Some(q) => format!("{authority}/{name}?{q}"),
        None => format!("{authority}/{name}"),
    }
}
