#!/bin/sh
# Render e6ircd's TOML config from environment (the deployment injects
# plaintext config as env vars and secrets — DATABASE_URL, the Shauth OIDC
# client secret — from AWS Secrets Manager), then exec the server. e6ircd
# itself only reads a config file, so this is the bridge.
#
# Required:  E6IRC_SERVER_NAME  E6IRC_PUBLIC_URL  E6IRC_DATABASE_URL
#            APPLICATION_RELEASE_REVISION (the deployed revision; Shauth sign-in
#              requires 12–64 lowercase hex digits or a sha256: digest)
# Optional:  E6IRC_NETWORK_NAME (default e6qu)
#            E6IRC_HTTP_ADDR    (default 0.0.0.0:8080)
#            E6IRC_IRC_ADDR     (default 127.0.0.1:6667 — internal only)
#            E6IRC_SECURE_COOKIES (true or false; default true)
#            E6IRC_ADMIN_ACCOUNTS (comma-separated)
#            E6IRC_BOOTSTRAP_TOKEN (32–512 byte one-time first-admin secret)
#            E6IRC_CONFIG_PATH (where to write the rendered config; default a
#              fresh unpredictable file under TMPDIR)
#            E6IRC_BINARY (default /usr/local/bin/e6ircd)
#            E6IRC_SECRET_KEY (base64 32-byte key required to store BNC and
#              managed-configuration credentials; read directly by e6ircd)
#            E6IRC_PREVIOUS_SECRET_KEYS (comma-separated old keys during a
#              credential-key rotation; read directly by e6ircd)
#            Shauth OIDC (all required together to enable SSO):
#              E6IRC_OIDC_ISSUER  E6IRC_OIDC_CLIENT_ID  E6IRC_OIDC_CLIENT_SECRET
#              E6IRC_OIDC_END_SESSION
#              E6IRC_OIDC_NAME (default shauth)
#              E6IRC_OIDC_ACCOUNT_CLAIM (default preferred_username)
#              E6IRC_OIDC_TOKEN_AUTH (default client_secret_post, which is how
#                Shauth registers managed applications; the method belongs to
#                the client registration, so discovery cannot report it)
set -eu
umask 077

fail() {
  printf 'docker-entrypoint: %s\n' "$1" >&2
  exit 1
}

# Fail loudly on missing required config rather than starting half-configured.
: "${E6IRC_SERVER_NAME:?E6IRC_SERVER_NAME is required}"
: "${E6IRC_PUBLIC_URL:?E6IRC_PUBLIC_URL is required}"
: "${E6IRC_DATABASE_URL:?E6IRC_DATABASE_URL is required}"
: "${APPLICATION_RELEASE_REVISION:?APPLICATION_RELEASE_REVISION is required}"
# The one value rendered bare: anything else would be TOML of the operator's
# choosing rather than a boolean.
case "${E6IRC_SECURE_COOKIES:-true}" in
  true | false) ;;
  *) fail 'E6IRC_SECURE_COOKIES must be exactly true or false' ;;
esac

# Set $quoted to VALUE as a TOML basic string. A control character cannot be
# written inside one, and none belongs in any of these values; it arrives as
# the carriage return or newline of a line pasted into a secret store. Left
# in, it becomes a parse error on the very line that holds the database URL or
# a client secret, so the refusal names the variable and never the value.
# Called as a command, not inside $(...), where its exit would be lost.
quote() { # VARIABLE VALUE
  case "$2" in
    *[[:cntrl:]]*)
      fail "$1 contains a control character (a carriage return or newline pasted with the value?)"
      ;;
  esac
  quoted=$(printf '%s' "$2" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
  quoted="\"$quoted\""
}

# Write `KEY = "VALUE"`.
string() { # KEY VARIABLE VALUE
  quote "$2" "$3"
  printf '%s = %s\n' "$1" "$quoted"
}

if [ -n "${E6IRC_CONFIG_PATH:-}" ]; then
  CONFIG="$E6IRC_CONFIG_PATH"
  : > "$CONFIG"
  chmod 0600 "$CONFIG"
else
  CONFIG="$(mktemp "${TMPDIR:-/tmp}/e6irc.XXXXXX")"
fi
{
  string server_name E6IRC_SERVER_NAME "$E6IRC_SERVER_NAME"
  string network_name E6IRC_NETWORK_NAME "${E6IRC_NETWORK_NAME:-e6qu}"
  string application_release_revision APPLICATION_RELEASE_REVISION "$APPLICATION_RELEASE_REVISION"

  # A listener is required. IRC is reached over WebSocket (/ws/irc) publicly;
  # the raw IRC port is bound to loopback only and is not exposed.
  printf '\n[[listeners]]\n'
  string addr E6IRC_IRC_ADDR "${E6IRC_IRC_ADDR:-127.0.0.1:6667}"

  printf '\n[http]\n'
  string addr E6IRC_HTTP_ADDR "${E6IRC_HTTP_ADDR:-0.0.0.0:8080}"
  string public_url E6IRC_PUBLIC_URL "$E6IRC_PUBLIC_URL"
  printf 'secure_cookies = %s\n' "${E6IRC_SECURE_COOKIES:-true}"
  if [ -n "${E6IRC_ADMIN_ACCOUNTS:-}" ]; then
    printf 'admin_accounts = ['
    # Split on commas in this shell, with globbing off: a loop fed by a
    # pipeline would run in a subshell, where a refusal could not stop the
    # render. Empty fields (a trailing or doubled comma) name no account.
    set -f
    unsplit=$IFS
    IFS=,
    for account in $E6IRC_ADMIN_ACCOUNTS; do
      if [ -n "$account" ]; then
        quote E6IRC_ADMIN_ACCOUNTS "$account"
        printf '%s, ' "$quoted"
      fi
    done
    IFS=$unsplit
    set +f
    printf ']\n'
  fi

  printf '\n[database]\n'
  string url E6IRC_DATABASE_URL "$E6IRC_DATABASE_URL"

  if [ -n "${E6IRC_BOOTSTRAP_TOKEN:-}" ]; then
    printf '\n[bootstrap]\n'
    string token E6IRC_BOOTSTRAP_TOKEN "$E6IRC_BOOTSTRAP_TOKEN"
  fi

  if [ -n "${E6IRC_OIDC_ISSUER:-}" ]; then
    : "${E6IRC_OIDC_CLIENT_ID:?E6IRC_OIDC_CLIENT_ID is required when E6IRC_OIDC_ISSUER is set}"
    : "${E6IRC_OIDC_CLIENT_SECRET:?E6IRC_OIDC_CLIENT_SECRET is required when E6IRC_OIDC_ISSUER is set}"
    : "${E6IRC_OIDC_END_SESSION:?E6IRC_OIDC_END_SESSION is required when E6IRC_OIDC_ISSUER is set}"
    printf '\n[[oidc]]\n'
    string name E6IRC_OIDC_NAME "${E6IRC_OIDC_NAME:-shauth}"
    string issuer_url E6IRC_OIDC_ISSUER "$E6IRC_OIDC_ISSUER"
    string client_id E6IRC_OIDC_CLIENT_ID "$E6IRC_OIDC_CLIENT_ID"
    string client_secret E6IRC_OIDC_CLIENT_SECRET "$E6IRC_OIDC_CLIENT_SECRET"
    # OidcProviderConfig::account_claim carries no serde default, so omitting it
    # is not "take the usual one" -- it fails the whole config parse and e6ircd
    # exits before it listens. Defaulting to preferred_username matches what
    # tools/test-shauth-sso.sh configures against Shauth.
    string account_claim E6IRC_OIDC_ACCOUNT_CLAIM \
      "${E6IRC_OIDC_ACCOUNT_CLAIM:-preferred_username}"
    string token_endpoint_auth_method E6IRC_OIDC_TOKEN_AUTH \
      "${E6IRC_OIDC_TOKEN_AUTH:-client_secret_post}"
    string end_session_endpoint E6IRC_OIDC_END_SESSION "$E6IRC_OIDC_END_SESSION"
  fi
} > "$CONFIG"

chmod 0600 "$CONFIG"

binary="${E6IRC_BINARY:-/usr/local/bin/e6ircd}"
"$binary" check-config --config "$CONFIG"
exec "$binary" --config "$CONFIG"
