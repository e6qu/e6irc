#!/bin/sh
# Render e6ircd's TOML config from environment (the deployment injects
# plaintext config as env vars and secrets — DATABASE_URL, the Shauth OIDC
# client secret — from AWS Secrets Manager), then exec the server. e6ircd
# itself only reads a config file, so this is the bridge.
#
# Required:  E6IRC_SERVER_NAME  E6IRC_PUBLIC_URL  E6IRC_DATABASE_URL
# Optional:  E6IRC_NETWORK_NAME (default e6qu)
#            E6IRC_HTTP_ADDR    (default 0.0.0.0:8080)
#            E6IRC_IRC_ADDR     (default 127.0.0.1:6667 — internal only)
#            E6IRC_SECURE_COOKIES (default true)
#            E6IRC_ADMIN_ACCOUNTS (comma-separated)
#            E6IRC_BOOTSTRAP_TOKEN (32+ byte one-time first-admin secret)
#            E6IRC_SECRET_KEY (base64 32-byte key required to store BNC and
#              managed-configuration credentials; read directly by e6ircd)
#            E6IRC_PREVIOUS_SECRET_KEYS (comma-separated old keys during a
#              credential-key rotation; read directly by e6ircd)
#            Shauth OIDC (all required together to enable SSO):
#              E6IRC_OIDC_ISSUER  E6IRC_OIDC_CLIENT_ID  E6IRC_OIDC_CLIENT_SECRET
#              E6IRC_OIDC_END_SESSION
#              E6IRC_OIDC_NAME (default shauth)
#              E6IRC_OIDC_TOKEN_AUTH (default client_secret_post, which is how
#                Shauth registers managed applications; the method belongs to
#                the client registration, so discovery cannot report it)
set -eu
umask 077

# Fail loudly on missing required config rather than starting half-configured.
: "${E6IRC_SERVER_NAME:?E6IRC_SERVER_NAME is required}"
: "${E6IRC_PUBLIC_URL:?E6IRC_PUBLIC_URL is required}"
: "${E6IRC_DATABASE_URL:?E6IRC_DATABASE_URL is required}"
: "${APPLICATION_RELEASE_REVISION:?APPLICATION_RELEASE_REVISION is required}"

# Escape a value for a TOML basic (double-quoted) string.
toml() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

if [ -n "${E6IRC_CONFIG_PATH:-}" ]; then
  CONFIG="$E6IRC_CONFIG_PATH"
  : > "$CONFIG"
  chmod 0600 "$CONFIG"
else
  CONFIG="$(mktemp "${TMPDIR:-/tmp}/e6irc.XXXXXX")"
fi
{
  printf 'server_name = "%s"\n' "$(toml "$E6IRC_SERVER_NAME")"
  printf 'network_name = "%s"\n\n' "$(toml "${E6IRC_NETWORK_NAME:-e6qu}")"
  printf 'application_release_revision = "%s"\n\n' "$(toml "$APPLICATION_RELEASE_REVISION")"

  # A listener is required. IRC is reached over WebSocket (/ws) publicly; the
  # raw IRC port is bound to loopback only and is not exposed.
  printf '[[listeners]]\naddr = "%s"\n\n' "$(toml "${E6IRC_IRC_ADDR:-127.0.0.1:6667}")"

  printf '[http]\n'
  printf 'addr = "%s"\n' "$(toml "${E6IRC_HTTP_ADDR:-0.0.0.0:8080}")"
  printf 'public_url = "%s"\n' "$(toml "$E6IRC_PUBLIC_URL")"
  printf 'secure_cookies = %s\n' "${E6IRC_SECURE_COOKIES:-true}"
  if [ -n "${E6IRC_ADMIN_ACCOUNTS:-}" ]; then
    printf 'admin_accounts = ['
    # Trailing newline so the last comma-separated account is not lost by
    # `read` when the final field has no newline of its own.
    printf '%s\n' "$E6IRC_ADMIN_ACCOUNTS" | tr ',' '\n' | while IFS= read -r a; do
      [ -n "$a" ] && printf '"%s", ' "$(toml "$a")"
    done
    printf ']\n'
  fi
  printf '\n[database]\nurl = "%s"\n' "$(toml "$E6IRC_DATABASE_URL")"

  if [ -n "${E6IRC_BOOTSTRAP_TOKEN:-}" ]; then
    printf '\n[bootstrap]\ntoken = "%s"\n' "$(toml "$E6IRC_BOOTSTRAP_TOKEN")"
  fi

  if [ -n "${E6IRC_OIDC_ISSUER:-}" ]; then
    : "${E6IRC_OIDC_CLIENT_ID:?E6IRC_OIDC_CLIENT_ID is required when E6IRC_OIDC_ISSUER is set}"
    : "${E6IRC_OIDC_CLIENT_SECRET:?E6IRC_OIDC_CLIENT_SECRET is required when E6IRC_OIDC_ISSUER is set}"
    : "${E6IRC_OIDC_END_SESSION:?E6IRC_OIDC_END_SESSION is required when E6IRC_OIDC_ISSUER is set}"
    printf '\n[[oidc]]\n'
    printf 'name = "%s"\n' "$(toml "${E6IRC_OIDC_NAME:-shauth}")"
    printf 'issuer_url = "%s"\n' "$(toml "$E6IRC_OIDC_ISSUER")"
    printf 'client_id = "%s"\n' "$(toml "$E6IRC_OIDC_CLIENT_ID")"
    printf 'client_secret = "%s"\n' "$(toml "$E6IRC_OIDC_CLIENT_SECRET")"
    # OidcProviderConfig::account_claim carries no serde default, so omitting it
    # is not "take the usual one" -- it fails the whole config parse and e6ircd
    # exits before it listens. Defaulting to preferred_username matches what
    # tools/test-shauth-sso.sh configures against Shauth.
    printf 'account_claim = "%s"\n' \
      "$(toml "${E6IRC_OIDC_ACCOUNT_CLAIM:-preferred_username}")"
    printf 'token_endpoint_auth_method = "%s"\n' \
      "$(toml "${E6IRC_OIDC_TOKEN_AUTH:-client_secret_post}")"
    printf 'end_session_endpoint = "%s"\n' "$(toml "$E6IRC_OIDC_END_SESSION")"
  fi
} > "$CONFIG"

chmod 0600 "$CONFIG"

binary="${E6IRC_BINARY:-/usr/local/bin/e6ircd}"
"$binary" check-config --config "$CONFIG"
exec "$binary" --config "$CONFIG"
