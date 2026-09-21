#!/usr/bin/env python3
"""Run a PostgreSQL client with E6IRC_DATABASE_URL as libpq environment.

usage: E6IRC_DATABASE_URL=... postgres-url-environment.py COMMAND [ARGUMENT...]

libpq expands a connection URL only when it arrives as an explicit database
name argument, which would put the password in the process list. Placed in
PGDATABASE a URL is not expanded at all: it is taken as the literal database
name, and the server's refusal then prints it, password included. So the URL
is split here, once, into the per-field variables libpq does read, and the
client is executed with them. The password reaches it only through its
environment.

The URL is the one e6ircd itself connects with, so its query parameters are
read the way the daemon reads them (hyphenated spellings included). Every
parameter is either forwarded, or named below as meaningless to a client, or
refused: dropping one silently could dial a different server, or the right one
without the TLS verification the operator asked for.

No message names any part of the URL's content; a malformed URL can put a
fragment of the password anywhere a parser looks.
"""

from __future__ import annotations

import os
import sys
import urllib.parse

URL_VARIABLE = "E6IRC_DATABASE_URL"

QUERY_PARAMETERS = {
    "host": "PGHOST",
    "hostaddr": "PGHOSTADDR",
    "port": "PGPORT",
    "dbname": "PGDATABASE",
    "user": "PGUSER",
    "password": "PGPASSWORD",
    "sslmode": "PGSSLMODE",
    "ssl-mode": "PGSSLMODE",
    "sslrootcert": "PGSSLROOTCERT",
    "ssl-root-cert": "PGSSLROOTCERT",
    "ssl-ca": "PGSSLROOTCERT",
    "sslcert": "PGSSLCERT",
    "ssl-cert": "PGSSLCERT",
    "sslkey": "PGSSLKEY",
    "ssl-key": "PGSSLKEY",
    "application_name": "PGAPPNAME",
    "options": "PGOPTIONS",
    "connect_timeout": "PGCONNECT_TIMEOUT",
}

# Sizes the daemon's prepared-statement cache; it selects nothing about the
# connection, so a client loses nothing by not hearing it.
DAEMON_ONLY_PARAMETERS = {"statement-cache-capacity"}


class UnusableUrl(Exception):
    """The reason, already free of anything the URL contained."""


def decoded(component: str, encoded: str) -> str:
    try:
        value = urllib.parse.unquote(encoded, errors="strict")
    except UnicodeDecodeError:
        raise UnusableUrl(f"its {component} is not percent-encoded UTF-8") from None
    if "\0" in value:
        raise UnusableUrl(f"its {component} contains a NUL byte")
    return value


def host_and_port(authority: str) -> tuple[str, str]:
    if "," in authority:
        raise UnusableUrl("it lists several hosts; e6ircd connects to exactly one")
    if authority.startswith("["):
        host, bracket, rest = authority[1:].partition("]")
        if not bracket or (rest and not rest.startswith(":")):
            raise UnusableUrl("its bracketed host address is malformed")
        return host, rest[1:]
    host, _, port = authority.partition(":")
    return host, port


def libpq_environment(url: str) -> dict[str, str]:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        raise UnusableUrl("it is not a URL") from None
    if parts.scheme not in ("postgres", "postgresql"):
        raise UnusableUrl("its scheme is neither postgres:// nor postgresql://")
    if parts.fragment or url.endswith("#"):
        raise UnusableUrl("it contains a bare '#'; write one inside a value as %23")

    environment: dict[str, str] = {}
    credentials, _, authority = parts.netloc.rpartition("@")
    user, has_password, password = credentials.partition(":")
    if user:
        environment["PGUSER"] = decoded("user name", user)
    if has_password:
        environment["PGPASSWORD"] = decoded("password", password)
    host, port = host_and_port(authority)
    if host:
        environment["PGHOST"] = decoded("host", host)
    if port:
        environment["PGPORT"] = port
    if parts.path.strip("/"):
        environment["PGDATABASE"] = decoded("database name", parts.path[1:])

    for pair in filter(None, parts.query.split("&")):
        key, _, value = pair.partition("=")
        key = decoded("query string", key)
        if key in DAEMON_ONLY_PARAMETERS:
            continue
        variable = QUERY_PARAMETERS.get(key)
        if variable is None:
            supported = ", ".join(sorted({*QUERY_PARAMETERS, *DAEMON_ONLY_PARAMETERS}))
            raise UnusableUrl(
                f"it has a query parameter other than the supported {supported}"
            )
        if "+" in value:
            raise UnusableUrl(
                f"its query parameter {key!r} has a bare '+', which e6ircd reads "
                "as a space and libpq as a plus sign; write %20 or %2B"
            )
        environment[variable] = decoded(f"query parameter {key!r}", value)

    port = environment.get("PGPORT")
    if port is not None and not (port.isascii() and port.isdigit() and 0 < int(port) < 65536):
        raise UnusableUrl("its port is not a number from 1 to 65535")
    return environment


def main() -> int:
    command = sys.argv[1:]
    if not command:
        print(f"usage: {URL_VARIABLE}=... {sys.argv[0]} COMMAND [ARGUMENT...]", file=sys.stderr)
        return 2
    environment = dict(os.environ)
    url = environment.pop(URL_VARIABLE, "")
    if not url:
        print(f"{URL_VARIABLE} is required", file=sys.stderr)
        return 2
    try:
        environment.update(libpq_environment(url))
    except UnusableUrl as reason:
        print(f"{URL_VARIABLE} cannot be used: {reason}", file=sys.stderr)
        return 2
    try:
        os.execvpe(command[0], command, environment)
    except OSError as error:
        print(f"cannot run {command[0]}: {error.strerror}", file=sys.stderr)
        return 127


if __name__ == "__main__":
    sys.exit(main())
