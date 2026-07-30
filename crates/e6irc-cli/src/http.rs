//! Bounded HTTPS API and RFC 8628 device-login client.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use e6irc_client::TerminalSafe;
use e6irc_client::token_cache::{CachedToken, default_token_path, load_token, store_token};
use reqwest::{Client, Method, Response, StatusCode};
use serde::Deserialize;

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

pub async fn login(base: &str, cache_path: &Path) -> io::Result<()> {
    let base = normalized_base(base)?;
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
        || start.verification_uri.is_empty()
        || !(1..=MAX_DEVICE_INTERVAL_SECONDS).contains(&start.interval)
        || !(1..=MAX_DEVICE_EXPIRY_SECONDS).contains(&start.expires_in)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "device authorization response contains invalid bounds or empty fields",
        ));
    }

    eprintln!(
        "Open {} and enter {}",
        TerminalSafe::from_untrusted(&start.verification_uri),
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
            .body(serde_json::json!({ "device_code": start.device_code }).to_string())
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
) -> io::Result<()> {
    let explicit_token = explicit_token.or_else(|| {
        std::env::var("E6IRC_API_TOKEN")
            .ok()
            .filter(|value| !value.is_empty())
    });
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
    let base = match requested_base {
        Some(base) => normalized_base(base)?,
        None => cached
            .as_ref()
            .map(|token| token.base_url().to_owned())
            .unwrap_or_else(|| "http://127.0.0.1:8080".to_owned()),
    };
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
    use std::io::Write as _;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&response_body)?;
    if !response_body.ends_with(b"\n") {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        login(&format!("http://{address}"), &path).await.unwrap();
        server.await.unwrap();
        let cached = load_token(&path).unwrap().unwrap();
        assert_eq!(cached.base_url(), format!("http://{address}"));
        assert_eq!(cached.access_token(), "issued-secret");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
