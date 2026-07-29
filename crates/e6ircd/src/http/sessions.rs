use super::*;

/// List the caller's unexpired browser sessions. Stable resource identifiers
/// permit revocation; token hashes never leave PostgreSQL.
pub(super) async fn list_browser_sessions(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Authenticated(account): Authenticated,
) -> Response {
    let current = session_token(&headers, state.secure_cookies);
    match crate::db::list_web_sessions(pool_of(&state), &account, current.as_deref()).await {
        Ok(rows) => {
            let sessions = rows
                .into_iter()
                .map(|row| {
                    serde_json::json!({
                        "id": row.id,
                        "created_at": row.created_at,
                        "expires_at": row.expires_at,
                        "method": if row.provider.is_some() { "oidc" } else { "local" },
                        "provider": row.provider,
                        "user_agent": row.user_agent,
                        "current": row.current,
                    })
                })
                .collect::<Vec<_>>();
            let mut response =
                axum::Json(serde_json::json!({ "sessions": sessions })).into_response();
            no_store(response.headers_mut());
            response
        }
        Err(error) => {
            eprintln!("http: browser session list failed: {error}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

/// Revoke one browser session owned by the caller. Revoking the request's
/// current cookie also clears that cookie, so the browser cannot retain a
/// visibly logged-in but invalid credential.
pub(super) async fn revoke_browser_session(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Authenticated(account): Authenticated,
    Path(id): Path<i64>,
) -> Response {
    let current = session_token(&headers, state.secure_cookies);
    match crate::db::delete_web_session_by_id(pool_of(&state), &account, id, current.as_deref())
        .await
    {
        Ok(Some(was_current)) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            if was_current {
                response.headers_mut().insert(
                    header::SET_COOKIE,
                    clear_session_cookie(state.secure_cookies)
                        .parse()
                        .expect("session clear cookie is valid"),
                );
            }
            no_store(response.headers_mut());
            response
        }
        Ok(None) => problem(StatusCode::NOT_FOUND, "No such browser session", None),
        Err(error) => {
            eprintln!("http: browser session revoke failed: {error}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}
