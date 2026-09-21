//! `sqlx::migrate!` embeds `migrations/` at compile time, but a proc macro on
//! stable Rust cannot tell Cargo which files it read. Without this, adding a
//! migration left every crate that was not otherwise edited running the old
//! embedded set — a binary that silently lacks a schema change.
fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
