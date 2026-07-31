#!/usr/bin/env python3
"""Exercise first boot and a PostgreSQL stop/start against the real daemon."""

from __future__ import annotations

import json
import os
import pathlib
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = pathlib.Path(
    os.environ.get("E6IRC_TEST_SERVER_BINARY", ROOT / "target/debug/e6ircd")
).resolve()
POSTGRES_IMAGE = os.environ.get("E6IRC_TEST_POSTGRES_IMAGE", "postgres:18-alpine")
POSTGRES_PASSWORD = "recovery-test-password"
TIMEOUT = 30.0


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


def docker_bytes(
    *arguments: str, input_bytes: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["docker", *arguments],
        check=True,
        input=input_bytes,
        capture_output=True,
        timeout=TIMEOUT,
    )


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
            "--username",
            "postgres",
            "--dbname",
            "e6irc_recovery",
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
        f"postgres://postgres:{POSTGRES_PASSWORD}@127.0.0.1:"
        f"{postgres_port}/e6irc_recovery"
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
                "POSTGRES_DB=e6irc_recovery",
                "--publish",
                f"127.0.0.1:{postgres_port}:5432",
                POSTGRES_IMAGE,
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
                    docker(
                        "exec",
                        container,
                        "psql",
                        "--username",
                        "postgres",
                        "--dbname",
                        "e6irc_recovery",
                        "--tuples-only",
                        "--no-align",
                        "--command",
                        "SELECT count(*) FROM _sqlx_migrations WHERE success",
                    ).stdout.strip()
                )
                expected_migrations = len(list((ROOT / "migrations").glob("*.sql")))
                assert migration_count == expected_migrations, (
                    migration_count,
                    expected_migrations,
                )
                settings_count = docker(
                    "exec",
                    container,
                    "psql",
                    "--username",
                    "postgres",
                    "--dbname",
                    "e6irc_recovery",
                    "--tuples-only",
                    "--no-align",
                    "--command",
                    "SELECT count(*) FROM server_settings",
                ).stdout.strip()
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
            # restore the custom archive, and boot the daemon from it.
            expected_grants = int(
                docker(
                    "exec",
                    container,
                    "psql",
                    "--username",
                    "postgres",
                    "--dbname",
                    "e6irc_recovery",
                    "--tuples-only",
                    "--no-align",
                    "--command",
                    "SELECT count(*) FROM device_grants",
                ).stdout.strip()
            )
            assert expected_grants >= 1, expected_grants
            archive = docker_bytes(
                "exec",
                container,
                "pg_dump",
                "--username",
                "postgres",
                "--dbname",
                "e6irc_recovery",
                "--format=custom",
                "--no-owner",
                "--no-privileges",
            ).stdout
            assert len(archive) > 1024, len(archive)
            docker_bytes(
                "exec",
                "--interactive",
                container,
                "pg_restore",
                "--list",
                input_bytes=archive,
            )
            docker(
                "exec",
                container,
                "psql",
                "--username",
                "postgres",
                "--dbname",
                "e6irc_recovery",
                "--command",
                "DELETE FROM device_grants; DELETE FROM server_settings",
            )
            docker_bytes(
                "exec",
                "--interactive",
                container,
                "pg_restore",
                "--exit-on-error",
                "--single-transaction",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--username",
                "postgres",
                "--dbname",
                "e6irc_recovery",
                input_bytes=archive,
            )
            restored = docker(
                "exec",
                container,
                "psql",
                "--username",
                "postgres",
                "--dbname",
                "e6irc_recovery",
                "--tuples-only",
                "--no-align",
                "--command",
                "SELECT (SELECT count(*) FROM server_settings), "
                "(SELECT count(*) FROM device_grants)",
            ).stdout.strip()
            assert restored == f"1|{expected_grants}", restored

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
            assert POSTGRES_PASSWORD not in server_output, (
                "database password leaked into daemon output"
            )
            print(
                "PostgreSQL recovery journey passed: fresh boot, migrations, "
                "bounded readiness, hot IRC traffic, visible dependency failure, "
                "recovery, graceful shutdown, custom backup, transactional restore, "
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
