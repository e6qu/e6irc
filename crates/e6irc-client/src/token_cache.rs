//! Cross-platform bearer-token cache shared by the native clients.
//!
//! The cache has one explicit format and one path policy. Unix creates the
//! directory as `0700`, the file as `0600`, and refuses to read a file exposed
//! to group/other users. Windows stores beneath the current user's local
//! application-data directory and atomically replaces through `MoveFileExW`.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const MAX_TOKEN_FILE_BYTES: u64 = 64 * 1024;

/// A device-issued bearer token and the API origin that issued it.
///
/// Keeping the origin beside the secret prevents a cached token from being
/// silently sent to a different server selected later on the command line.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedToken {
    base_url: String,
    access_token: String,
}

impl CachedToken {
    pub fn new(base_url: String, access_token: String) -> io::Result<Self> {
        if base_url.trim().is_empty() || access_token.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "token cache requires a non-empty base URL and access token",
            ));
        }
        Ok(Self {
            base_url,
            access_token,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }
}

/// Resolve the native clients' default token file.
pub fn default_token_path() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("E6IRC_TOKEN_FILE") {
        return nonempty_path(path, "E6IRC_TOKEN_FILE");
    }

    #[cfg(target_os = "windows")]
    {
        let root = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "LOCALAPPDATA or APPDATA is required for the default token cache",
                )
            })?;
        return Ok(PathBuf::from(root).join("e6irc").join("token.json"));
    }

    #[cfg(target_os = "macos")]
    {
        let home = required_home()?;
        return Ok(home
            .join("Library")
            .join("Application Support")
            .join("e6irc")
            .join("token.json"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(root) = std::env::var_os("XDG_CONFIG_HOME") {
            let root = nonempty_path(root, "XDG_CONFIG_HOME")?;
            if !root.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "XDG_CONFIG_HOME must be an absolute path",
                ));
            }
            return Ok(root.join("e6irc").join("token.json"));
        }
        return Ok(required_home()?
            .join(".config")
            .join("e6irc")
            .join("token.json"));
    }

    #[allow(unreachable_code)]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this platform has no token-cache path policy",
    ))
}

fn nonempty_path(value: OsString, variable: &str) -> io::Result<PathBuf> {
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{variable} cannot be empty"),
        ));
    }
    Ok(PathBuf::from(value))
}

#[cfg(unix)]
fn required_home() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "HOME is required for the default token cache",
            )
        })
}

/// Load a cached token. A missing file is `Ok(None)`; malformed, oversized, or
/// insecure storage is an error rather than an unauthenticated fallback.
pub fn load_token(path: &Path) -> io::Result<Option<CachedToken>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if metadata.len() > MAX_TOKEN_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "token cache exceeds the {MAX_TOKEN_FILE_BYTES}-byte limit: {}",
                path.display()
            ),
        ));
    }
    check_private_permissions(&metadata, path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_TOKEN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TOKEN_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token cache grew while it was being read",
        ));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(unix)]
fn check_private_permissions(metadata: &fs::Metadata, path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "token cache is accessible by group or other users; chmod 600 {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(_metadata: &fs::Metadata, _path: &Path) -> io::Result<()> {
    Ok(())
}

/// Atomically store a token, creating a private parent directory and file.
pub fn store_token(path: &Path, token: &CachedToken) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let Some(parent) = parent else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "token cache path must have a parent directory",
        ));
    };
    create_private_directory(parent)?;

    let bytes = serde_json::to_vec(token)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "token cache path must end in a file name",
        )
    })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| io::Error::other(format!("system clock precedes Unix epoch: {error}")))?
        .as_nanos();
    let temporary = parent.join(format!(
        ".{}.{}.{nonce}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
    ));

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        make_file_private(&mut options);
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temporary, path)
    })();
    if let Err(operation_error) = result {
        match fs::remove_file(&temporary) {
            Ok(()) => Err(operation_error),
            Err(cleanup_error) if cleanup_error.kind() == io::ErrorKind::NotFound => {
                Err(operation_error)
            }
            Err(cleanup_error) => Err(io::Error::other(format!(
                "token-cache write failed: {operation_error}; temporary-file cleanup also failed: {cleanup_error}"
            ))),
        }
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(unix)]
fn make_file_private(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn make_file_private(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn atomic_replace(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(windows)]
fn atomic_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both buffers are NUL-terminated and remain live for the call.
    let moved = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(not(unix), not(windows)))]
fn atomic_replace(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this platform has no atomic token-cache replacement",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMPORARY_PATH: AtomicU64 = AtomicU64::new(0);

    fn temporary_path(name: &str) -> PathBuf {
        let sequence = NEXT_TEMPORARY_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "e6irc-token-cache-{}-{sequence}-{name}",
            std::process::id(),
        ))
    }

    #[test]
    fn round_trip_and_replace_are_exact() {
        let directory = temporary_path("round-trip");
        let path = directory.join("token.json");
        let first = CachedToken::new("https://one.example".into(), "first".into()).unwrap();
        store_token(&path, &first).unwrap();
        let loaded = load_token(&path).unwrap().unwrap();
        assert_eq!(loaded.base_url(), "https://one.example");
        assert_eq!(loaded.access_token(), "first");

        let second = CachedToken::new("https://two.example".into(), "second".into()).unwrap();
        store_token(&path, &second).unwrap();
        let loaded = load_token(&path).unwrap().unwrap();
        assert_eq!(loaded.base_url(), "https://two.example");
        assert_eq!(loaded.access_token(), "second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_parent_permissions_are_not_changed() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temporary_path("existing-parent");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        let path = directory.join("token.json");
        let token = CachedToken::new("https://one.example".into(), "secret".into()).unwrap();
        store_token(&path, &token).unwrap();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o755
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn exposed_token_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temporary_path("permissions");
        let path = directory.join("token.json");
        let token = CachedToken::new("https://one.example".into(), "secret".into()).unwrap();
        store_token(&path, &token).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = load_token(&path).err().expect("must refuse broad mode");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn malformed_and_oversized_files_fail_loudly() {
        let directory = temporary_path("invalid");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("token.json");
        fs::write(&path, b"not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            load_token(&path).err().expect("invalid").kind(),
            io::ErrorKind::InvalidData
        );
        fs::write(&path, vec![b'x'; MAX_TOKEN_FILE_BYTES as usize + 1]).unwrap();
        assert_eq!(
            load_token(&path).err().expect("oversized").kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
