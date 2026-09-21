//! TLS server certificates that follow their files.
//!
//! A certificate is renewed on disk (by an ACME client, by hand) long before
//! the process that serves it restarts. Every TLS listener — the IRC listeners
//! and the bouncer attach listener — serves its certificate through a
//! [`ReloadingCertificate`], which reads the files again when the process gets
//! `SIGHUP` and when a periodic check sees their modification times change.
//! A reload that fails (a half-written file, a key that does not match its
//! certificate) keeps the certificate being served and says so loudly, so a
//! renewal mistake degrades to "still the old certificate", never to a
//! listener that can no longer complete a handshake.

use std::io;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::SystemTime;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

/// How often the certificate files' modification times are compared with the
/// ones the served certificate was read at.
const CERTIFICATE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The modification times of a certificate's two files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    certificate: SystemTime,
    key: SystemTime,
}

impl FileStamp {
    fn of(files: &TlsConfig) -> io::Result<Self> {
        let modified = |path: &std::path::Path| {
            std::fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .map_err(|error| {
                    io::Error::new(error.kind(), format!("{}: {error}", path.display()))
                })
        };
        Ok(Self {
            certificate: modified(&files.cert_path)?,
            key: modified(&files.key_path)?,
        })
    }
}

/// A server certificate read from `cert_path`/`key_path`, replaced in place
/// when the files are read again successfully.
#[derive(Debug)]
pub(crate) struct ReloadingCertificate {
    files: TlsConfig,
    current: RwLock<Arc<CertifiedKey>>,
    /// The files' times when `current` was read, and the times of the last
    /// read that failed — so a broken file is reported once, not every check.
    stamps: Mutex<(FileStamp, Option<FileStamp>)>,
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
            stamps: Mutex::new((stamp, None)),
        })
    }

    /// Read the files again and serve what they now hold. On failure the
    /// certificate being served is kept and the error returned.
    pub(crate) fn reload(&self) -> io::Result<()> {
        let stamp = FileStamp::of(&self.files);
        let read = stamp
            .as_ref()
            .map_err(clone_error)
            .and_then(|_| read(&self.files));
        let mut stamps = self.stamps.lock().expect("certificate stamps lock");
        match read {
            Ok(certified) => {
                *self.current.write().expect("certificate lock") = Arc::new(certified);
                if let Ok(stamp) = stamp {
                    *stamps = (stamp, None);
                }
                Ok(())
            }
            Err(error) => {
                stamps.1 = stamp.ok();
                Err(error)
            }
        }
    }

    /// Reload when either file's modification time differs from the one the
    /// served certificate (or the last failed read) was taken at. `Ok(false)`
    /// when nothing changed.
    fn reload_if_changed(&self) -> io::Result<bool> {
        let stamp = FileStamp::of(&self.files)?;
        {
            let stamps = self.stamps.lock().expect("certificate stamps lock");
            if stamps.0 == stamp || stamps.1 == Some(stamp) {
                return Ok(false);
            }
        }
        self.reload().map(|()| true)
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

fn clone_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
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

    /// Reload every certificate now (`SIGHUP`), reporting each outcome.
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

    /// Reload each certificate whose files changed since it was read.
    fn reload_changed(&self) {
        for certificate in self.live() {
            match certificate.reload_if_changed() {
                Ok(false) => {}
                Ok(true) => eprintln!(
                    "e6ircd: TLS certificate files changed; now serving {}",
                    certificate.describe()
                ),
                Err(error) => report_failure(&certificate, &error),
            }
        }
    }

    /// Reload on `SIGHUP` and whenever the files change, until the process
    /// ends. Supervised: its exit is a critical failure.
    pub(crate) async fn run(self) {
        let mut check = tokio::time::interval(CERTIFICATE_CHECK_INTERVAL);
        check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        check.tick().await;
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut hangup = signal(SignalKind::hangup())
                .expect("install the SIGHUP handler that reloads TLS certificates");
            loop {
                tokio::select! {
                    _ = hangup.recv() => self.reload_all(),
                    _ = check.tick() => self.reload_changed(),
                }
            }
        }
        #[cfg(not(unix))]
        loop {
            check.tick().await;
            self.reload_changed();
        }
    }
}

fn report_failure(certificate: &ReloadingCertificate, error: &io::Error) {
    eprintln!(
        "e6ircd: ERROR: TLS certificate {} could not be reloaded: {error}; still serving the \
         certificate read before — fix the files, then send SIGHUP or wait for the next check",
        certificate.describe()
    );
}
