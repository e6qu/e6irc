//! Bounded HTTPS API and RFC 8628 device-login client.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use e6irc_client::token_cache::{CachedToken, default_token_path, load_token, store_token};
use e6irc_client::{CleartextCredentials, TerminalSafe};
use reqwest::{Client, Method, Response, StatusCode};
use serde::{Deserialize, Serialize};

const MAX_API_RESPONSE: usize = 16 * 1024 * 1024;
const MAX_DEVICE_RESPONSE: usize = 1024 * 1024;
const MAX_DEVICE_INTERVAL_SECONDS: u64 = 300;
const MAX_DEVICE_EXPIRY_SECONDS: u64 = 3600;

#[derive(Deserialize)]
struct DeviceStart {
    device_code: String,
    user_code: String,
    verification_uri: String,
    interval: u64,
    expires_in: u64,
}

#[derive(Deserialize)]
struct DeviceToken {
    access_token: String,
    token_type: String,
}

#[derive(Deserialize)]
struct DeviceError {
    error: String,
}

#[derive(Serialize)]
struct DeviceTokenRequest<'a> {
    device_code: &'a str,
}

fn verification_uri(value: &str) -> io::Result<&str> {
    let parsed = reqwest::Url::parse(value).map_err(invalid_input)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.fragment().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "device authorization response has an invalid verification URI",
        ));
    }
    Ok(value)
}

fn normalized_base(base: &str) -> io::Result<String> {
    let base = base.trim_end_matches('/');
    let parsed = reqwest::Url::parse(base).map_err(invalid_input)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "API base must be an http(s) origin without a path, query, or fragment",
        ));
    }
    Ok(base.to_owned())
}

fn api_base(requested: Option<&str>, cached: Option<&CachedToken>) -> io::Result<String> {
    match (requested, cached) {
        (Some(base), _) => normalized_base(base),
        (None, Some(token)) => normalized_base(token.base_url()),
        (None, None) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--base is required when no cached login supplies an API origin",
        )),
    }
}

fn endpoint(base: &str, path: &str) -> io::Result<String> {
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "API path must start with one slash",
        ));
    }
    Ok(format!("{}{path}", normalized_base(base)?))
}

fn invalid_input(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

fn transport_error(error: reqwest::Error) -> io::Error {
    if error.is_timeout() {
        io::Error::new(io::ErrorKind::TimedOut, error)
    } else {
        io::Error::other(error)
    }
}

async fn bounded_body(mut response: Response, limit: usize) -> io::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(io::Error::other(format!(
            "HTTP response exceeds {limit} bytes"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
        if body.len() + chunk.len() > limit {
            return Err(io::Error::other(format!(
                "HTTP response exceeds {limit} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn client() -> io::Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(transport_error)
}

pub async fn login(
    base: &str,
    cache_path: &Path,
    cleartext: CleartextCredentials,
) -> io::Result<()> {
    let base = normalized_base(base)?;
    // The whole exchange exists to obtain a token, so it is decided up front.
    token_may_cross(&base, true, cleartext)?;
    let client = client()?;
    let start_response = client
        .post(endpoint(&base, "/api/v1/auth/device/start")?)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(transport_error)?;
    let start_status = start_response.status();
    let start_body = bounded_body(start_response, MAX_DEVICE_RESPONSE).await?;
    if !start_status.is_success() {
        return Err(http_failure(
            "device authorization start",
            start_status,
            &start_body,
        ));
    }
    let start: DeviceStart = serde_json::from_slice(&start_body)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if start.device_code.is_empty()
        || start.user_code.is_empty()
        || !(1..=MAX_DEVICE_INTERVAL_SECONDS).contains(&start.interval)
        || !(1..=MAX_DEVICE_EXPIRY_SECONDS).contains(&start.expires_in)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "device authorization response contains invalid bounds or empty fields",
        ));
    }
    let verification_uri = verification_uri(&start.verification_uri)?;

    eprintln!(
        "Open {} and enter {}",
        TerminalSafe::from_untrusted(verification_uri),
        TerminalSafe::from_untrusted(&start.user_code)
    );
    eprintln!("Waiting for authorization…");
    let deadline = Instant::now() + Duration::from_secs(start.expires_in);
    let mut interval = Duration::from_secs(start.interval);
    loop {
        if Instant::now() + interval > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "device authorization expired before approval",
            ));
        }
        tokio::time::sleep(interval).await;
        let response = client
            .post(endpoint(&base, "/api/v1/auth/device/token")?)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&DeviceTokenRequest {
                    device_code: &start.device_code,
                })
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            )
            .send()
            .await
            .map_err(transport_error)?;
        let status = response.status();
        let body = bounded_body(response, MAX_DEVICE_RESPONSE).await?;
        if status.is_success() {
            let token: DeviceToken = serde_json::from_slice(&body)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if !token.token_type.eq_ignore_ascii_case("bearer") || token.access_token.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "device token response is not a non-empty bearer token",
                ));
            }
            let cached = CachedToken::new(base, token.access_token)?;
            store_token(cache_path, &cached)?;
            eprintln!(
                "Authorized; token stored in {}",
                TerminalSafe::from_untrusted(&cache_path.display().to_string())
            );
            return Ok(());
        }

        let error: DeviceError = serde_json::from_slice(&body)
            .map_err(|parse| io::Error::new(io::ErrorKind::InvalidData, parse))?;
        match error.error.as_str() {
            "authorization_pending" => {}
            "slow_down" => {
                interval = (interval + Duration::from_secs(5))
                    .min(Duration::from_secs(MAX_DEVICE_INTERVAL_SECONDS));
            }
            "access_denied" => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "device authorization was denied",
                ));
            }
            "expired_token" => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "device authorization expired",
                ));
            }
            code => {
                return Err(io::Error::other(format!(
                    "device authorization failed: {code}"
                )));
            }
        }
    }
}

fn http_failure(operation: &str, status: StatusCode, body: &[u8]) -> io::Error {
    let detail = String::from_utf8_lossy(body);
    let detail = detail.trim();
    if detail.is_empty() {
        io::Error::other(format!("{operation} failed: HTTP {}", status.as_u16()))
    } else {
        io::Error::other(format!(
            "{operation} failed: HTTP {}: {detail}",
            status.as_u16()
        ))
    }
}

pub async fn api(
    method: &str,
    path: &str,
    requested_base: Option<&str>,
    explicit_token: Option<String>,
    body: Option<String>,
    cache_path: Option<&Path>,
    cleartext: CleartextCredentials,
) -> io::Result<()> {
    let cached = if explicit_token.is_none() {
        let resolved_cache;
        let cache_path = match cache_path {
            Some(path) => path,
            None => {
                resolved_cache = default_token_path()?;
                &resolved_cache
            }
        };
        load_token(cache_path)?
    } else {
        None
    };
    let base = api_base(requested_base, cached.as_ref())?;
    let token = match (explicit_token, cached) {
        (Some(token), _) => Some(token),
        (None, Some(cached)) => {
            if normalized_base(cached.base_url())? != base {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "cached token belongs to {}; use that base or provide --token",
                        cached.base_url()
                    ),
                ));
            }
            Some(cached.access_token().to_owned())
        }
        (None, None) => None,
    };
    token_may_cross(&base, token.is_some(), cleartext)?;
    let method = Method::from_bytes(method.as_bytes()).map_err(invalid_input)?;
    let mut request = client()?.request(method, endpoint(&base, path)?);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
    }
    let response = request.send().await.map_err(transport_error)?;
    let status = response.status();
    let response_body = bounded_body(response, MAX_API_RESPONSE).await?;
    use std::io::{IsTerminal as _, Write as _};
    let mut stdout = io::stdout().lock();
    let shown = body_for_stdout(&response_body, stdout.is_terminal());
    stdout.write_all(&shown)?;
    if !shown.ends_with(b"\n") {
        stdout.write_all(b"\n")?;
    }
    if status.is_success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "API request failed: HTTP {}",
            status.as_u16()
        )))
    }
}

/// A response body as stdout should receive it. The body is whatever the
/// server sent, so on a terminal its control characters are neutralized line by
/// line (the line breaks of a formatted body are kept). Anywhere else the
/// reader is a program — `e6irc api … | jq`, a file — and gets the exact bytes:
/// a replacement character there would silently change the data.
/// Whether a request to `base` may carry (or, for `login`, obtain) a bearer
/// token. A token is a password with an expiry: over `http://` to another
/// machine it is readable by everything on the path. The rule, the override
/// and the meaning of "this machine" are the IRC commands' own
/// ([`CleartextCredentials`], `e6irc_client::is_loopback_host`), so one flag
/// means one thing across the tool.
fn token_may_cross(
    base: &str,
    sends_token: bool,
    cleartext: CleartextCredentials,
) -> io::Result<()> {
    let url = reqwest::Url::parse(base).map_err(invalid_input)?;
    let exposed = sends_token
        && url.scheme() == "http"
        && cleartext == CleartextCredentials::Refuse
        && !url.host_str().is_some_and(e6irc_client::is_loopback_host);
    if exposed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to send a bearer token in cleartext to {base}; use an https:// base, \
                 or pass --allow-cleartext-credentials to send it unprotected"
            ),
        ));
    }
    Ok(())
}

/// Environment variable consulted for the `api` bearer token, resolved by the
/// same rules as the IRC secrets (flag, else file, else this).
pub(crate) const API_TOKEN_ENVIRONMENT: &str = "E6IRC_API_TOKEN";

pub(crate) fn body_for_stdout(body: &[u8], stdout_is_terminal: bool) -> std::borrow::Cow<'_, [u8]> {
    if !stdout_is_terminal {
        return std::borrow::Cow::Borrowed(body);
    }
    let text = String::from_utf8_lossy(body);
    let safe: Vec<String> = text
        .split('\n')
        .map(|line| TerminalSafe::from_untrusted(line).to_string())
        .collect();
    std::borrow::Cow::Owned(safe.join("\n").into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bearer token is a password with an expiry. Over `http://` it — and, for
    /// `login`, the device code that becomes one — is readable by everything on
    /// the path. Refused before a single request is made, the same way the IRC
    /// commands refuse SASL without TLS.
    #[tokio::test]
    async fn a_bearer_token_never_crosses_plaintext_http_to_another_machine() {
        async fn refused(call: impl Future<Output = io::Result<()>>) -> io::Error {
            // TEST-NET-1 is never dialed when the refusal comes first.
            tokio::time::timeout(Duration::from_secs(3), call)
                .await
                .expect("a request was attempted before the refusal")
                .expect_err("plaintext to another machine")
        }
        let cache = std::env::temp_dir().join("e6irc-cli-never-written-token.json");
        let remote = "http://192.0.2.1";
        for error in [
            refused(login(remote, &cache, CleartextCredentials::Refuse)).await,
            refused(api(
                "GET",
                "/api/v1/me",
                Some(remote),
                Some("secret-token".into()),
                None,
                None,
                CleartextCredentials::Refuse,
            ))
            .await,
        ] {
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
            assert!(error.to_string().contains("cleartext"), "{error}");
            assert!(
                error.to_string().contains("--allow-cleartext-credentials"),
                "{error}"
            );
        }
        assert!(!cache.exists());

        // What is, and is not, a credential crossing the network in the clear.
        use CleartextCredentials::{Allow, Refuse};
        for (base, sends_token, cleartext, allowed) in [
            ("https://irc.example", true, Refuse, true),
            ("http://127.0.0.1:8080", true, Refuse, true),
            ("http://localhost:8080", true, Refuse, true),
            ("http://[::1]:8080", true, Refuse, true),
            ("http://irc.example", false, Refuse, true),
            ("http://irc.example", true, Allow, true),
            ("http://irc.example", true, Refuse, false),
            ("http://192.0.2.1", true, Refuse, false),
        ] {
            assert_eq!(
                token_may_cross(base, sends_token, cleartext).is_ok(),
                allowed,
                "{base} sends_token={sends_token} {cleartext:?}"
            );
        }
    }

    #[test]
    fn an_api_body_is_neutralized_for_a_terminal_and_exact_for_a_program() {
        let body = "{\n  \"name\": \"x\u{1b}[2J\u{9b}y\u{7f}\"\r\n}\n".as_bytes();
        assert_eq!(&*body_for_stdout(body, false), body);
        let shown = String::from_utf8(body_for_stdout(body, true).into_owned()).unwrap();
        assert!(
            !shown.chars().any(|c| c.is_control() && c != '\n'),
            "{shown:?}"
        );
        assert_eq!(shown.matches('\n').count(), 3, "line structure is kept");
    }

    #[test]
    fn origins_and_paths_are_not_ambiguous() {
        assert_eq!(
            normalized_base("https://irc.example/").unwrap(),
            "https://irc.example"
        );
        for invalid in [
            "irc.example",
            "ftp://irc.example",
            "https://irc.example/path",
            "https://irc.example/?query",
        ] {
            assert!(normalized_base(invalid).is_err(), "{invalid}");
        }
        assert!(endpoint("https://irc.example", "/api/v1/me").is_ok());
        assert!(endpoint("https://irc.example", "//attacker.example").is_err());
        assert!(endpoint("https://irc.example", "api/v1/me").is_err());
        assert_eq!(
            verification_uri("https://verify.example/device").unwrap(),
            "https://verify.example/device"
        );
        for invalid in [
            "/device",
            "device",
            "ftp://verify.example/device",
            "https://verify.example/device#fragment",
        ] {
            assert!(verification_uri(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn api_base_requires_provenance() {
        let cached = CachedToken::new("https://irc.example".into(), "token".into()).unwrap();
        assert_eq!(
            api_base(None, Some(&cached)).unwrap(),
            "https://irc.example"
        );
        assert_eq!(
            api_base(Some("https://other.example"), None).unwrap(),
            "https://other.example"
        );
        assert!(api_base(None, None).is_err());
    }

    #[tokio::test]
    async fn device_login_polls_and_persists_the_issued_token() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for response in [
                r#"{"device_code":"device","user_code":"ABCD-EFGH","verification_uri":"https://verify.example/device","interval":1,"expires_in":10}"#,
                r#"{"error":"authorization_pending"}"#,
                r#"{"access_token":"issued-secret","token_type":"bearer"}"#,
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 8192];
                let read = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                assert!(
                    request.starts_with("POST /api/v1/auth/device/"),
                    "{request}"
                );
                let status = if response.contains("\"error\"") {
                    "400 Bad Request"
                } else {
                    "200 OK"
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                );
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
        });

        let directory =
            std::env::temp_dir().join(format!("e6irc-device-login-test-{}", std::process::id()));
        let path = directory.join("token.json");
        login(
            &format!("http://{address}"),
            &path,
            CleartextCredentials::Refuse,
        )
        .await
        .expect("plaintext to this machine is never refused");
        server.await.unwrap();
        let cached = load_token(&path).unwrap().unwrap();
        assert_eq!(cached.base_url(), format!("http://{address}"));
        assert_eq!(cached.access_token(), "issued-secret");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn device_token_request_uses_the_closed_wire_shape() {
        let request = serde_json::to_string(&DeviceTokenRequest {
            device_code: "device",
        })
        .unwrap();
        assert_eq!(request, r#"{"device_code":"device"}"#);
    }
}
