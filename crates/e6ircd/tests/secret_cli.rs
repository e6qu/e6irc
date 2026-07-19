//! End-to-end operator workflow for sealed secrets: `e6ircd genkey`
//! mints a key, `e6ircd seal` encrypts an upstream password against it,
//! and the server loads a config carrying that sealed value — decrypting
//! it back to the original plaintext.

use std::io::Write;
use std::process::{Command, Stdio};

use e6ircd::config::Config;

fn unique_path(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("e6irc-{tag}-{}-{n}", std::process::id()))
}

fn genkey() -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_e6ircd"))
        .arg("genkey")
        .output()
        .expect("run genkey");
    assert!(out.status.success(), "genkey failed");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn seal(key_file: &std::path::Path, plaintext: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_e6ircd"))
        .args(["seal", "--key-file"])
        .arg(key_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn seal");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(plaintext.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("seal output");
    assert!(out.status.success(), "seal failed");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn genkey_seal_and_load_round_trip() {
    let key_file = unique_path("key");
    std::fs::write(&key_file, genkey()).unwrap();

    let sealed = seal(&key_file, "upstreampass");
    assert!(sealed.starts_with("enc:v1:"), "sealed: {sealed}");

    let config_toml = format!(
        r#"
        server_name = "irc.x.example"
        network_name = "XNet"
        [[listeners]]
        addr = "127.0.0.1:0"
        [secrets]
        key_file = {key_file:?}
        [[network]]
        name = "up"
        addr = "irc.example:6697"
        tls = true
        nick = "e6bnc"
        sasl_account = "e6bnc"
        sasl_password = "{sealed}"
        "#,
    );
    let config_path = unique_path("cfg.toml");
    std::fs::write(&config_path, config_toml).unwrap();

    let loaded = Config::load(&config_path).expect("load config");
    std::fs::remove_file(&key_file).ok();
    std::fs::remove_file(&config_path).ok();

    assert_eq!(
        loaded.networks[0].sasl_password.as_deref(),
        Some("upstreampass"),
        "sealed password must decrypt at load"
    );
}

#[test]
fn seal_without_key_source_fails() {
    // No --key-file and (assuming a clean env) no E6IRC_SECRET_KEY.
    if std::env::var_os("E6IRC_SECRET_KEY").is_some() {
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_e6ircd"))
        .arg("seal")
        .stdin(Stdio::null())
        .output()
        .expect("run seal");
    assert!(!out.status.success(), "seal must fail with no key source");
}
