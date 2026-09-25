//! TLS server certificates that follow their files.
//!
//! A certificate is renewed on disk (by an ACME client, by hand) long before
//! the process that serves it restarts. Every TLS listener — the IRC listeners
//! and the bouncer attach listener — serves its certificate through a
//! [`ReloadingCertificate`], which reads the files again when the process gets
//! `SIGHUP` and when a periodic check sees the files change. A reload that
//! fails (a half-written file, a key that does not match its certificate)
//! keeps the certificate being served and says so loudly, so a renewal
//! mistake degrades to "still the old certificate", never to a listener that
//! can no longer complete a handshake; the failing read is retried at every
//! check until it succeeds.

use std::io;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::SystemTime;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

/// How often the certificate files' identities are compared with the ones the
/// served certificate was read at, and a failing read is retried.
const CERTIFICATE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// What tells one version of a file from another. Metadata alone does not:
/// a rewrite within the file system's timestamp granularity, or a tool that
/// preserves times (`cp -p`, `rsync -t`, an unpacked archive), keeps the
/// modification time, and not every platform has an inode or a status-change
/// time to fall back on. A digest of the contents decides on every platform;
/// a certificate or key file is a few kilobytes, read once a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    modified: SystemTime,
    digest: [u8; 32],
}

impl FileIdentity {
    fn of(path: &std::path::Path) -> io::Result<Self> {
        let located =
            |error: io::Error| io::Error::new(error.kind(), format!("{}: {error}", path.display()));
        let modified = std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .map_err(located)?;
        let contents = std::fs::read(path).map_err(located)?;
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &contents);
        let digest = digest
            .as_ref()
            .try_into()
            .expect("a SHA-256 digest is 32 bytes");
        Ok(Self { modified, digest })
    }
}

/// The identities of a certificate's two files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    certificate: FileIdentity,
    key: FileIdentity,
}

impl FileStamp {
    fn of(files: &TlsConfig) -> io::Result<Self> {
        Ok(Self {
            certificate: FileIdentity::of(&files.cert_path)?,
            key: FileIdentity::of(&files.key_path)?,
        })
    }
}

/// What the periodic check found.
#[derive(Debug)]
enum Check {
    /// The files are the ones the served certificate was read from.
    Unchanged,
    /// The files were read and are now served.
    Reloaded,
    /// The files could not be read; the certificate read before is still
    /// served. `repeated` when this same failure was the last one recorded.
    Failed { error: io::Error, repeated: bool },
}

/// A failed read: the files' identities before it, when they could be taken,
/// and what went wrong. Equal failures are one failure, reported once.
type Failure = (Option<FileStamp>, String);

/// The files the served certificate came from, and how reading them is
/// failing, if it is.
#[derive(Debug)]
struct ReadState {
    served: FileStamp,
    /// While set, every check reads again: a failure is never taken as the
    /// files' settled state, because a fix need not change anything a stamp
    /// can see.
    failing: Option<Failure>,
}

/// A server certificate read from `cert_path`/`key_path`, replaced in place
/// when the files are read again successfully.
#[derive(Debug)]
pub(crate) struct ReloadingCertificate {
    files: TlsConfig,
    current: RwLock<Arc<CertifiedKey>>,
    state: Mutex<ReadState>,
}

impl ReloadingCertificate {
    /// Read the certificate the listener starts with. A failure here is a
    /// startup error: there is no earlier certificate to keep serving.
    pub(crate) fn load(files: &TlsConfig) -> io::Result<Self> {
        let stamp = FileStamp::of(files)?;
        let certified = read(files)?;
        Ok(Self {
            files: files.clone(),
            current: RwLock::new(Arc::new(certified)),
            state: Mutex::new(ReadState {
                served: stamp,
                failing: None,
            }),
        })
    }

    /// Read the files again and serve what they now hold. On failure the
    /// certificate being served is kept and the error returned.
    pub(crate) fn reload(&self) -> io::Result<()> {
        self.read_now().map_err(|(error, _repeated)| error)
    }

    /// Read the files when they are not the ones the served certificate came
    /// from, or when the last read failed.
    fn check(&self) -> Check {
        let unchanged = {
            let state = self.state.lock().expect("certificate state lock");
            state.failing.is_none()
                && FileStamp::of(&self.files).is_ok_and(|stamp| stamp == state.served)
        };
        if unchanged {
            return Check::Unchanged;
        }
        match self.read_now() {
            Ok(()) => Check::Reloaded,
            Err((error, repeated)) => Check::Failed { error, repeated },
        }
    }

    /// Read the files and serve them. A failure is recorded, and returned with
    /// whether it is the one recorded last.
    fn read_now(&self) -> Result<(), (io::Error, bool)> {
        // Taken before the read: a file replaced in between reads as changed
        // at the next check, and is read again then.
        let stamp = FileStamp::of(&self.files);
        let identities = stamp.as_ref().ok().copied();
        let read = stamp.and_then(|stamp| read(&self.files).map(|certified| (stamp, certified)));
        let mut state = self.state.lock().expect("certificate state lock");
        match read {
            Ok((stamp, certified)) => {
                *self.current.write().expect("certificate lock") = Arc::new(certified);
                state.served = stamp;
                state.failing = None;
                Ok(())
            }
            Err(error) => {
                let failure = (identities, error.to_string());
                let repeated = state.failing.as_ref() == Some(&failure);
                state.failing = Some(failure);
                Err((error, repeated))
            }
        }
    }

    fn describe(&self) -> String {
        format!(
            "{} (key {})",
            self.files.cert_path.display(),
            self.files.key_path.display()
        )
    }
}

impl ResolvesServerCert for ReloadingCertificate {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().expect("certificate lock").clone())
    }
}

/// Parse the certificate chain and its private key, and check that the key is
/// the certificate's.
fn read(files: &TlsConfig) -> io::Result<CertifiedKey> {
    use rustls_pki_types::pem::PemObject;
    let pem = |path: &std::path::Path, error: rustls_pki_types::pem::Error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TLS PEM {}: {error}", path.display()),
        )
    };
    let chain: Vec<_> = rustls_pki_types::CertificateDer::pem_file_iter(&files.cert_path)
        .map_err(|error| pem(&files.cert_path, error))?
        .collect::<Result<_, _>>()
        .map_err(|error| pem(&files.cert_path, error))?;
    if chain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} holds no certificate", files.cert_path.display()),
        ));
    }
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(&files.key_path)
        .map_err(|error| pem(&files.key_path, error))?;
    CertifiedKey::from_der(chain, key, &rustls::crypto::aws_lc_rs::default_provider()).map_err(
        |error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} with key {}: {error}",
                    files.cert_path.display(),
                    files.key_path.display()
                ),
            )
        },
    )
}

/// The process's `SIGHUP`s, taken over from the default action (terminate)
/// the moment this exists. It is installed first thing at startup, before
/// the database wait: a `SIGHUP` sent to reload certificates while the
/// process was still waiting for PostgreSQL used to kill it — and a service
/// manager does not restart a unit that died of `SIGHUP`.
pub(crate) struct Hangups {
    #[cfg(unix)]
    signal: tokio::signal::unix::Signal,
}

impl Hangups {
    /// Take over `SIGHUP`. Needs the Tokio runtime.
    pub(crate) fn install() -> io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                signal: signal(SignalKind::hangup())?,
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    /// The next `SIGHUP`; `false` once none can arrive (the runtime is
    /// shutting down). Without Unix signals it never resolves.
    async fn next(&mut self) -> bool {
        #[cfg(unix)]
        {
            self.signal.recv().await.is_some()
        }
        #[cfg(not(unix))]
        std::future::pending().await
    }
}

/// Every certificate the process serves, so one `SIGHUP` or one periodic
/// check reaches all of them. A listener that is replaced (the bouncer attach
/// listener, from the console) drops its certificate; the registry holds only
/// weak references, so a dropped one simply stops being reloaded.
#[derive(Clone, Default)]
pub(crate) struct CertificateReloads {
    certificates: Arc<Mutex<Vec<Weak<ReloadingCertificate>>>>,
}

impl CertificateReloads {
    /// A TLS acceptor serving the certificate `files` names, reloaded with
    /// every other one this registry holds.
    pub(crate) fn acceptor(&self, files: &TlsConfig) -> io::Result<TlsAcceptor> {
        let certificate = Arc::new(ReloadingCertificate::load(files)?);
        {
            let mut certificates = self.certificates.lock().expect("certificate registry lock");
            certificates.retain(|certificate| certificate.strong_count() > 0);
            certificates.push(Arc::downgrade(&certificate));
        }
        Ok(TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(certificate),
        )))
    }

    fn live(&self) -> Vec<Arc<ReloadingCertificate>> {
        let mut certificates = self.certificates.lock().expect("certificate registry lock");
        certificates.retain(|certificate| certificate.strong_count() > 0);
        certificates.iter().filter_map(Weak::upgrade).collect()
    }

    /// Reload every certificate now (`SIGHUP`), reporting each outcome: the
    /// operator asked, so every failure is answered, repeated or not.
    fn reload_all(&self) {
        for certificate in self.live() {
            match certificate.reload() {
                Ok(()) => eprintln!(
                    "e6ircd: reloaded TLS certificate {}",
                    certificate.describe()
                ),
                Err(error) => report_failure(&certificate, &error),
            }
        }
    }

    /// Reload each certificate whose files changed since it was read, or whose
    /// last read failed. A failure that persists is reported once.
    fn reload_changed(&self) {
        for certificate in self.live() {
            match certificate.check() {
                Check::Unchanged | Check::Failed { repeated: true, .. } => {}
                Check::Reloaded => eprintln!(
                    "e6ircd: TLS certificate files read; now serving {}",
                    certificate.describe()
                ),
                Check::Failed {
                    error,
                    repeated: false,
                } => report_failure(&certificate, &error),
            }
        }
    }

    /// Reload on each of `hangups` and whenever the files change, until the
    /// process ends. Supervised: its exit is a critical failure.
    pub(crate) async fn run(self, mut hangups: Hangups) {
        let mut check = tokio::time::interval(CERTIFICATE_CHECK_INTERVAL);
        check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        check.tick().await;
        loop {
            tokio::select! {
                received = hangups.next() => {
                    if !received {
                        eprintln!("e6ircd: the SIGHUP stream ended; certificate reloads stop");
                        return;
                    }
                    self.reload_all();
                }
                _ = check.tick() => self.reload_changed(),
            }
        }
    }
}

fn report_failure(certificate: &ReloadingCertificate, error: &io::Error) {
    eprintln!(
        "e6ircd: ERROR: TLS certificate {} could not be reloaded: {error}; still serving the \
         certificate read before. The files are read again every {}s until they load (send \
         SIGHUP to retry at once); this failure is not reported again unless it changes",
        certificate.describe(),
        CERTIFICATE_CHECK_INTERVAL.as_secs()
    );
}

/// A fresh self-signed certificate for `localhost` and its key, written to
/// `files`; returns the certificate's DER form for a client to trust.
#[cfg(test)]
pub(crate) fn write_self_signed(files: &TlsConfig) -> rustls_pki_types::CertificateDer<'static> {
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("certificate");
    std::fs::write(&files.cert_path, generated.cert.pem()).expect("write certificate");
    std::fs::write(&files.key_path, generated.signing_key.serialize_pem()).expect("write key");
    generated.cert.der().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> (std::path::PathBuf, TlsConfig) {
        let dir = std::env::temp_dir().join(format!("e6irc-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let files = TlsConfig {
            cert_path: dir.join("cert.pem"),
            key_path: dir.join("key.pem"),
        };
        (dir, files)
    }

    fn set_modified(path: &std::path::Path, time: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .and_then(|file| file.set_modified(time))
            .expect("set the modification time");
    }

    /// A file rewritten with its modification time kept (a copy that preserves
    /// times, a rewrite within the timestamp granularity) is still a changed
    /// file.
    #[test]
    fn a_rewrite_that_keeps_the_modification_time_is_still_a_change() {
        let (dir, files) = scratch("certificate-stamp");
        write_self_signed(&files);
        let before = FileStamp::of(&files).expect("stamp");
        std::fs::write(&files.cert_path, "a different length of content").expect("rewrite");
        set_modified(&files.cert_path, before.certificate.modified);
        let after = FileStamp::of(&files).expect("stamp");
        assert_eq!(after.certificate.modified, before.certificate.modified);
        assert_ne!(after, before);
        std::fs::remove_dir_all(dir).expect("remove the scratch directory");
    }

    /// A failed read is retried at every check, and reported once. A fix whose
    /// files look exactly like the broken ones' (same length, same time — here
    /// forced) used to be skipped forever; it is served at the next check.
    #[test]
    fn a_failed_read_is_retried_at_every_check_and_reported_once() {
        let (dir, files) = scratch("certificate-retry");
        write_self_signed(&files);
        let certificate = ReloadingCertificate::load(&files).expect("load");
        assert!(matches!(certificate.check(), Check::Unchanged));

        let good = std::fs::read(&files.cert_path).expect("read the certificate");
        let broken = vec![b'x'; good.len()];
        std::fs::write(&files.cert_path, &broken).expect("break the certificate");
        let broken_at = FileStamp::of(&files).expect("stamp").certificate.modified;
        assert!(matches!(
            certificate.check(),
            Check::Failed {
                repeated: false,
                ..
            }
        ));
        assert!(
            matches!(certificate.check(), Check::Failed { repeated: true, .. }),
            "an unchanged failure is read again but not reported again"
        );

        std::fs::write(&files.cert_path, &good).expect("repair the certificate");
        set_modified(&files.cert_path, broken_at);
        assert!(matches!(certificate.check(), Check::Reloaded));
        assert!(matches!(certificate.check(), Check::Unchanged));
        std::fs::remove_dir_all(dir).expect("remove the scratch directory");
    }
}
