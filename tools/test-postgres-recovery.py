#!/usr/bin/env python3
"""Exercise first boot and a PostgreSQL stop/start against the real daemon."""

from __future__ import annotations

import json
import os
import pathlib
import signal
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = pathlib.Path(
    os.environ.get("E6IRC_TEST_SERVER_BINARY", ROOT / "target/debug/e6ircd")
).resolve()
POSTGRES_IMAGE = os.environ.get("E6IRC_TEST_POSTGRES_IMAGE", "postgres:18-alpine")
# Every reserved URL delimiter appears in the password, so a consumer that
# forgets to percent-decode it (or that splits the URL on the wrong `@`, `:` or
# `/`) cannot authenticate.
POSTGRES_PASSWORD = "recovery test:p@ss/word#1"
POSTGRES_PASSWORD_IN_URL = urllib.parse.quote(POSTGRES_PASSWORD, safe="")
POSTGRES_DATABASE = "e6irc_recovery"
# PostgreSQL listens off its default port inside the container, so a client
# there reaches it only by honoring the port in the database URL.
POSTGRES_CONTAINER_PORT = 5544
TIMEOUT = 30.0

# Stands in for `pg_dump`, `psql` and `pg_restore` on PATH: the real client of
# the server's own version runs inside the PostgreSQL container, receiving the
# connection exactly as the script under test exported it. Files cross the
# container boundary on standard input and output.
CONTAINER_CLIENT = """#!/usr/bin/env python3
import os
import subprocess
import sys

tool = os.path.basename(sys.argv[0])
arguments = sys.argv[1:]
with open(os.environ["E6IRC_TEST_CLIENT_LOG"], "a", encoding="utf-8") as log:
    log.write(" ".join([tool, *arguments]) + "\\n")
forwarded = []
for name in sorted(os.environ):
    if name.startswith("PG"):
        forwarded += ["--env", name]
command = [
    "docker", "exec", "--interactive", *forwarded,
    os.environ["E6IRC_TEST_POSTGRES_CONTAINER"], tool,
]
standard_input = subprocess.DEVNULL
standard_output = None
if tool == "pg_dump":
    target = [a for a in arguments if a.startswith("--file=")]
    arguments = [a for a in arguments if not a.startswith("--file=")]
    standard_output = open(target[0][len("--file="):], "wb")
elif tool == "pg_restore":
    standard_input = open(arguments.pop(), "rb")
sys.exit(
    subprocess.run(
        command + arguments, stdin=standard_input, stdout=standard_output
    ).returncode
)
"""


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        check=check,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )


def container_sql(container: str, statement: str) -> str:
    return docker(
        "exec",
        container,
        "psql",
        "--port",
        str(POSTGRES_CONTAINER_PORT),
        "--username",
        "postgres",
        "--dbname",
        POSTGRES_DATABASE,
        "--tuples-only",
        "--no-align",
        "--command",
        statement,
    ).stdout.strip()


def install_container_clients(directory: pathlib.Path) -> None:
    directory.mkdir()
    for tool in ("pg_dump", "psql", "pg_restore"):
        client = directory / tool
        client.write_text(CONTAINER_CLIENT, encoding="utf-8")
        client.chmod(client.stat().st_mode | stat.S_IXUSR)


def run_database_tool(
    script: str,
    *arguments: str,
    environment: dict[str, str],
    expect_success: bool = True,
) -> str:
    """Run one shipped backup/restore script and return everything it printed."""
    result = subprocess.run(
        [str(ROOT / "tools" / script), *arguments],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=TIMEOUT,
    )
    output = result.stdout
    for secret in (POSTGRES_PASSWORD, POSTGRES_PASSWORD_IN_URL):
        assert secret not in output, f"{script} printed the database password"
    assert (result.returncode == 0) == expect_success, (script, arguments, output)
    return output


def wait_for_postgres(container: str) -> None:
    deadline = time.monotonic() + TIMEOUT
    last_error = ""
    while time.monotonic() < deadline:
        result = docker(
            "exec",
            container,
            "pg_isready",
            "--host",
            "127.0.0.1",
            "--port",
            str(POSTGRES_CONTAINER_PORT),
            "--username",
            "postgres",
            "--dbname",
            POSTGRES_DATABASE,
            check=False,
        )
        if result.returncode == 0:
            return
        last_error = (result.stdout + result.stderr).strip()
        time.sleep(0.2)
    raise TimeoutError(f"PostgreSQL did not become ready: {last_error}")


def http_request(
    origin: str,
    path: str,
    *,
    method: str = "GET",
    timeout: float = 6.0,
) -> tuple[int, bytes]:
    request = urllib.request.Request(
        f"{origin}{path}",
        data=b"" if method == "POST" else None,
        method=method,
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def wait_for_http(origin: str, path: str, expected_status: int) -> tuple[bytes, float]:
    deadline = time.monotonic() + TIMEOUT
    last_error: Exception | None = None
    started = time.monotonic()
    while time.monotonic() < deadline:
        try:
            status, body = http_request(origin, path)
            if status == expected_status:
                return body, time.monotonic() - started
        except (OSError, urllib.error.URLError) as error:
            last_error = error
        time.sleep(0.1)
    raise TimeoutError(
        f"{path} did not return HTTP {expected_status}; last transport error: {last_error}"
    )


class IrcClient:
    def __init__(self, port: int, nick: str) -> None:
        self.nick = nick
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.socket.settimeout(0.5)
        self.buffer = b""
        self.send(f"NICK {nick}")
        self.send(f"USER {nick} 0 * :{nick}")
        self.wait_line(lambda line: f" 001 {nick} " in line, "welcome")

    def send(self, line: str) -> None:
        self.socket.sendall(line.encode("utf-8") + b"\r\n")

    def join(self, channel: str) -> None:
        self.send(f"JOIN {channel}")
        self.wait_line(
            lambda line: f" 366 {self.nick} {channel} " in line,
            f"end of NAMES for {channel}",
        )

    def wait_line(self, predicate, description: str) -> str:
        deadline = time.monotonic() + 10.0
        seen: list[str] = []
        while time.monotonic() < deadline:
            while b"\n" in self.buffer:
                raw, self.buffer = self.buffer.split(b"\n", 1)
                line = raw.rstrip(b"\r").decode("utf-8", "replace")
                seen.append(line)
                if line.startswith("PING "):
                    self.send(f"PONG {line.split(' ', 1)[1]}")
                if predicate(line):
                    return line
            try:
                chunk = self.socket.recv(8192)
            except TimeoutError:
                continue
            if not chunk:
                raise EOFError(f"IRC connection closed while waiting for {description}")
            self.buffer += chunk
        raise TimeoutError(f"timed out waiting for {description}; saw {seen!r}")

    def close(self) -> None:
        self.socket.close()


def main() -> None:
    if not SERVER.is_file():
        raise RuntimeError(f"build e6ircd before the recovery journey: {SERVER}")

    container = f"e6irc-postgres-recovery-{os.getpid()}"
    postgres_port = available_port()
    irc_port = available_port()
    http_port = available_port()
    origin = f"http://127.0.0.1:{http_port}"
    database_url = (
        f"postgres://postgres:{POSTGRES_PASSWORD_IN_URL}@127.0.0.1:"
        f"{postgres_port}/{POSTGRES_DATABASE}"
    )
    clients: list[IrcClient] = []
    server: subprocess.Popen[bytes] | None = None
    container_created = False

    with tempfile.TemporaryDirectory(prefix="e6irc-postgres-recovery-") as directory:
        temporary = pathlib.Path(directory)
        config = temporary / "e6ircd.toml"
        server_log_path = temporary / "e6ircd.log"
        config.write_text(
            'server_name = "irc.recovery.test"\n'
            'network_name = "RecoveryNet"\n'
            "[[listeners]]\n"
            f'addr = "127.0.0.1:{irc_port}"\n'
            "[http]\n"
            f'addr = "127.0.0.1:{http_port}"\n'
            f"public_url = {json.dumps(origin)}\n"
            "secure_cookies = false\n"
            "[database]\n"
            f"url = {json.dumps(database_url)}\n",
            encoding="utf-8",
        )

        try:
            docker(
                "run",
                "--detach",
                "--name",
                container,
                "--env",
                f"POSTGRES_PASSWORD={POSTGRES_PASSWORD}",
                "--env",
                f"POSTGRES_DB={POSTGRES_DATABASE}",
                "--publish",
                f"127.0.0.1:{postgres_port}:{POSTGRES_CONTAINER_PORT}",
                POSTGRES_IMAGE,
                "-c",
                f"port={POSTGRES_CONTAINER_PORT}",
            )
            container_created = True
            wait_for_postgres(container)

            with server_log_path.open("wb") as server_log:
                server = subprocess.Popen(
                    [str(SERVER), "--config", str(config)],
                    cwd=ROOT,
                    stdout=server_log,
                    stderr=subprocess.STDOUT,
                )
                ready_body, _ = wait_for_http(origin, "/readyz", 200)
                ready = json.loads(ready_body)
                assert ready == {
                    "ready": True,
                    "core": "ready",
                    "database": "ready",
                }, ready

                migration_count = int(
                    container_sql(
                        container,
                        "SELECT count(*) FROM _sqlx_migrations WHERE success",
                    )
                )
                expected_migrations = len(list((ROOT / "migrations").glob("*.sql")))
                assert migration_count == expected_migrations, (
                    migration_count,
                    expected_migrations,
                )
                settings_count = container_sql(
                    container, "SELECT count(*) FROM server_settings"
                )
                assert settings_count == "1", settings_count

                alice = IrcClient(irc_port, "alice")
                bob = IrcClient(irc_port, "bob")
                clients.extend([alice, bob])
                alice.join("#recovery")
                bob.join("#recovery")
                alice.send("PRIVMSG #recovery :before database interruption")
                bob.wait_line(
                    lambda line: " PRIVMSG #recovery :before database interruption" in line,
                    "pre-interruption channel message",
                )

                docker("stop", "--time", "5", container)
                unavailable_body, readiness_latency = wait_for_http(
                    origin, "/readyz", 503
                )
                unavailable = json.loads(unavailable_body)
                assert unavailable["ready"] is False, unavailable
                assert unavailable["database"] == "unavailable", unavailable
                assert readiness_latency < 5.0, (
                    f"readiness took {readiness_latency:.2f}s while PostgreSQL was down"
                )
                assert http_request(origin, "/healthz")[0] == 200
                assert server.poll() is None, "daemon exited during PostgreSQL interruption"

                bob.send("PRIVMSG #recovery :hot state survives")
                alice.wait_line(
                    lambda line: " PRIVMSG #recovery :hot state survives" in line,
                    "channel message during PostgreSQL interruption",
                )
                device_failure_started = time.monotonic()
                status, body = http_request(
                    origin,
                    "/api/v1/auth/device/start",
                    method="POST",
                    timeout=6.0,
                )
                device_failure_latency = time.monotonic() - device_failure_started
                assert status == 503, (status, body)
                assert json.loads(body)["title"] == "Database unavailable", body
                assert device_failure_latency < 5.0, (
                    "database-backed request took "
                    f"{device_failure_latency:.2f}s while PostgreSQL was down"
                )

                docker("start", container)
                wait_for_postgres(container)
                recovered_body, _ = wait_for_http(origin, "/readyz", 200)
                assert json.loads(recovered_body)["database"] == "ready"

                status, body = http_request(
                    origin, "/api/v1/auth/device/start", method="POST"
                )
                assert status == 200, (status, body)
                grant = json.loads(body)
                assert grant["device_code"]
                assert grant["user_code"]

                alice.send("PRIVMSG #recovery :after database recovery")
                bob.wait_line(
                    lambda line: " PRIVMSG #recovery :after database recovery" in line,
                    "post-recovery channel message",
                )

                server.send_signal(signal.SIGTERM)
                assert server.wait(timeout=10) == 0

            # Back up after real migrations, managed import, traffic, and a
            # device grant. Destroy two durable proof families, transactionally
            # restore the custom archive, and boot the daemon from it. The
            # shipped scripts do all of it, given nothing but a database URL.
            expected_grants = int(
                container_sql(container, "SELECT count(*) FROM device_grants")
            )
            assert expected_grants >= 1, expected_grants

            # The container's own bridge address, not its loopback: the image
            # trusts loopback clients, and only a password-checked connection
            # proves the scripts delivered the password.
            container_address = docker(
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                container,
            ).stdout.strip()
            assert container_address, "PostgreSQL container has no network address"

            def tool_url(password: str, sslmode: str = "disable") -> str:
                return (
                    f"postgresql://postgres:{password}@{container_address}:"
                    f"{POSTGRES_CONTAINER_PORT}/{POSTGRES_DATABASE}"
                    f"?sslmode={sslmode}&application_name=e6irc%20recovery"
                )

            client_log = temporary / "postgres-clients.log"
            install_container_clients(temporary / "bin")
            tool_environment = {
                **{
                    name: value
                    for name, value in os.environ.items()
                    if not name.startswith("PG")
                },
                "PATH": f"{temporary / 'bin'}{os.pathsep}{os.environ['PATH']}",
                "E6IRC_TEST_POSTGRES_CONTAINER": container,
                "E6IRC_TEST_CLIENT_LOG": str(client_log),
                "E6IRC_DATABASE_URL": tool_url(POSTGRES_PASSWORD_IN_URL),
            }
            backup = temporary / "e6irc.dump"

            rejected = run_database_tool(
                "backup-postgres.sh",
                str(temporary / "rejected.dump"),
                environment={
                    **tool_environment,
                    "E6IRC_DATABASE_URL": tool_url("not-the-password"),
                },
                expect_success=False,
            )
            assert "password authentication failed" in rejected, rejected
            assert not (temporary / "rejected.dump").exists()

            # This server offers no TLS, so a backup that asks for it must
            # fail: a dropped `sslmode` would connect in the clear instead.
            unencrypted = run_database_tool(
                "backup-postgres.sh",
                str(temporary / "unencrypted.dump"),
                environment={
                    **tool_environment,
                    "E6IRC_DATABASE_URL": tool_url(
                        POSTGRES_PASSWORD_IN_URL, sslmode="require"
                    ),
                },
                expect_success=False,
            )
            assert "server does not support SSL" in unencrypted, unencrypted
            assert not (temporary / "unencrypted.dump").exists()

            run_database_tool(
                "backup-postgres.sh", str(backup), environment=tool_environment
            )
            assert backup.stat().st_size > 1024, backup.stat().st_size
            container_sql(
                container, "DELETE FROM device_grants; DELETE FROM server_settings"
            )

            refused = run_database_tool(
                "restore-postgres.sh",
                str(backup),
                "another_database",
                environment={
                    **tool_environment,
                    "E6IRC_RESTORE_CONFIRM": "another_database",
                },
                expect_success=False,
            )
            assert f"connected database is {POSTGRES_DATABASE}" in refused, refused
            assert (
                container_sql(container, "SELECT count(*) FROM server_settings") == "0"
            ), "a refused restore changed the database"

            run_database_tool(
                "restore-postgres.sh",
                str(backup),
                POSTGRES_DATABASE,
                environment={
                    **tool_environment,
                    "E6IRC_RESTORE_CONFIRM": POSTGRES_DATABASE,
                },
            )
            restored = container_sql(
                container,
                "SELECT (SELECT count(*) FROM server_settings), "
                "(SELECT count(*) FROM device_grants)",
            )
            assert restored == f"1|{expected_grants}", restored
            client_arguments = client_log.read_text(encoding="utf-8")
            for secret in (POSTGRES_PASSWORD, POSTGRES_PASSWORD_IN_URL, "postgresql://"):
                assert secret not in client_arguments, (
                    "a PostgreSQL client received the database URL or password "
                    "as a command argument"
                )

            with server_log_path.open("ab") as server_log:
                server = subprocess.Popen(
                    [str(SERVER), "--config", str(config)],
                    cwd=ROOT,
                    stdout=server_log,
                    stderr=subprocess.STDOUT,
                )
                restored_body, _ = wait_for_http(origin, "/readyz", 200)
                assert json.loads(restored_body)["database"] == "ready"
                server.send_signal(signal.SIGTERM)
                assert server.wait(timeout=10) == 0

            server_output = server_log_path.read_text(encoding="utf-8", errors="replace")
            for secret in (POSTGRES_PASSWORD, POSTGRES_PASSWORD_IN_URL):
                assert secret not in server_output, (
                    "database password leaked into daemon output"
                )
            print(
                "PostgreSQL recovery journey passed: fresh boot, migrations, "
                "bounded readiness, hot IRC traffic, visible dependency failure, "
                "recovery, graceful shutdown, scripted custom backup, guarded "
                "transactional restore, "
                "and restored boot"
            )
        except Exception:
            if server_log_path.exists():
                print(server_log_path.read_text(encoding="utf-8", errors="replace"))
            if container_created:
                result = docker("logs", container, check=False)
                print(result.stdout)
                print(result.stderr)
            raise
        finally:
            for client in clients:
                client.close()
            if server is not None and server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
            if container_created:
                docker("rm", "--force", container, check=False)


if __name__ == "__main__":
    main()
