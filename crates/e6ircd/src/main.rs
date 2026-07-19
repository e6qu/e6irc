use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use e6ircd::config::Config;
use e6ircd::net;
use e6ircd::secret::SecretKey;

const USAGE: &str = "usage:\n  \
    e6ircd [--config <path>]        run the server\n  \
    e6ircd genkey                   print a new base64 master key\n  \
    e6ircd seal [--key-file <path>] seal stdin into an enc:v1: blob";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("genkey") => genkey(),
        Some("seal") => seal(&args[1..]),
        _ => run(&args),
    }
}

/// Print a fresh base64 master key. The operator writes it to a file
/// (0600) referenced by `[secrets].key_file`, or exports it as
/// `E6IRC_SECRET_KEY`.
fn genkey() -> ExitCode {
    println!("{}", SecretKey::generate().to_base64());
    ExitCode::SUCCESS
}

/// Read plaintext from stdin and print its sealed `enc:v1:` form, using
/// the key from `--key-file` or the `E6IRC_SECRET_KEY` env var.
fn seal(args: &[String]) -> ExitCode {
    let key = match load_seal_key(args) {
        Ok(k) => k,
        Err(msg) => {
            eprintln!("e6ircd seal: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let mut plaintext = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut plaintext) {
        eprintln!("e6ircd seal: cannot read stdin: {e}");
        return ExitCode::FAILURE;
    }
    // A trailing newline from a pipe or interactive entry is not part of
    // the secret.
    let plaintext = plaintext.strip_suffix('\n').unwrap_or(&plaintext);
    println!("{}", key.seal(plaintext));
    ExitCode::SUCCESS
}

fn load_seal_key(args: &[String]) -> Result<SecretKey, String> {
    match args {
        [] => {
            let v = std::env::var("E6IRC_SECRET_KEY")
                .map_err(|_| "no --key-file and E6IRC_SECRET_KEY is unset".to_string())?;
            SecretKey::from_base64(&v).map_err(|e| format!("E6IRC_SECRET_KEY: {e}"))
        }
        [flag, path] if flag == "--key-file" => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read key_file {path}: {e}"))?;
            SecretKey::from_base64(&raw).map_err(|e| format!("key_file: {e}"))
        }
        _ => Err(format!("bad arguments\n{USAGE}")),
    }
}

fn run(args: &[String]) -> ExitCode {
    let config_path = match args {
        [] => PathBuf::from("e6irc.toml"),
        [flag, path] if flag == "--config" => PathBuf::from(path),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("e6ircd: {} ({})", e, config_path.display());
            return ExitCode::FAILURE;
        }
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        match net::start(config).await {
            Ok(running) => {
                for addr in &running.addrs {
                    println!("listening on {addr}");
                }
                // Run until killed; graceful shutdown arrives with the
                // signal-handling work.
                std::future::pending::<()>().await;
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("e6ircd: failed to start: {e}");
                ExitCode::FAILURE
            }
        }
    })
}
