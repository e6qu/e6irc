#!/usr/bin/env python3
"""Drive the real full-screen TUI through a pseudo-terminal and real e6ircd."""

from __future__ import annotations

import fcntl
import os
import pathlib
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import tempfile
import termios
import time


ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = pathlib.Path(
    os.environ.get("E6IRC_TEST_SERVER_BINARY", ROOT / "target/debug/e6ircd")
)
TUI = pathlib.Path(
    os.environ.get("E6IRC_TEST_TUI_BINARY", ROOT / "target/debug/e6irc-tui")
)
TIMEOUT = 15.0
ANSI_CONTROL = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")


def visible_text(output: bytes | bytearray) -> bytes:
    """Remove ANSI controls so individually styled visible copy is searchable."""
    return ANSI_CONTROL.sub(b"", bytes(output))


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_server(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"e6ircd exited during startup ({process.returncode})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("e6ircd did not accept connections")


class IrcPeer:
    def __init__(self, port: int) -> None:
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
        self.socket.setblocking(False)
        self.buffer = b""

    def send(self, line: str) -> None:
        self.socket.sendall(line.encode() + b"\r\n")

    def wait_line(self, predicate, description: str) -> str:
        deadline = time.monotonic() + TIMEOUT
        seen: list[str] = []
        while time.monotonic() < deadline:
            while b"\n" in self.buffer:
                raw, self.buffer = self.buffer.split(b"\n", 1)
                line = raw.rstrip(b"\r").decode("utf-8", "replace")
                if line.startswith("PING "):
                    self.send("PONG " + line.split(" ", 1)[1])
                seen.append(line)
                if predicate(line):
                    return line
            readable, _, _ = select.select([self.socket], [], [], 0.2)
            if readable:
                chunk = self.socket.recv(8192)
                if not chunk:
                    raise EOFError(f"IRC peer closed while waiting for {description}")
                self.buffer += chunk
        raise TimeoutError(f"timed out waiting for {description}; saw {seen!r}")

    def close(self) -> None:
        self.socket.close()


def read_pty_until(master: int, output: bytearray, needle: bytes) -> None:
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if needle in output:
            return
        readable, _, _ = select.select([master], [], [], 0.2)
        if readable:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                chunk = b""
            if chunk:
                output.extend(chunk)
    raise TimeoutError(f"terminal never rendered {needle!r}")


def drain_pty(master: int, output: bytearray, duration: float) -> None:
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        readable, _, _ = select.select([master], [], [], 0.05)
        if readable:
            try:
                output.extend(os.read(master, 65536))
            except OSError:
                return


def wait_process_and_drain(
    process: subprocess.Popen[bytes],
    master: int,
    output: bytearray,
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        drain_pty(master, output, 0.05)
        if process.poll() is not None:
            drain_pty(master, output, 0.2)
            return
    raise subprocess.TimeoutExpired(process.args, timeout)


def main() -> None:
    if not SERVER.is_file() or not TUI.is_file():
        raise RuntimeError("build e6ircd and e6irc-tui before the PTY journey")

    port = available_port()
    with tempfile.TemporaryDirectory(prefix="e6irc-tui-pty-") as directory:
        temporary = pathlib.Path(directory)
        config = temporary / "e6ircd.toml"
        config.write_text(
            'server_name = "irc.tui.test"\n'
            'network_name = "TuiTest"\n'
            "[[listeners]]\n"
            f'addr = "127.0.0.1:{port}"\n',
            encoding="utf-8",
        )
        server_log = (temporary / "server.log").open("wb")
        server = subprocess.Popen(
            [str(SERVER), "--config", str(config)],
            cwd=ROOT,
            stdout=server_log,
            stderr=subprocess.STDOUT,
        )
        master = -1
        tui: subprocess.Popen[bytes] | None = None
        peer: IrcPeer | None = None
        output = bytearray()
        try:
            wait_for_server(port, server)
            peer = IrcPeer(port)
            peer.send("NICK observer")
            peer.send("USER observer 0 * :observer")
            peer.wait_line(lambda line: " 001 observer " in line, "observer welcome")
            peer.send("JOIN #pty")
            peer.wait_line(lambda line: " 366 observer #pty " in line, "observer JOIN")

            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))

            def attach_controlling_terminal() -> None:
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

            environment = os.environ.copy()
            environment["TERM"] = "xterm-256color"
            tui = subprocess.Popen(
                [
                    str(TUI),
                    "--server",
                    f"127.0.0.1:{port}",
                    "--nick",
                    "ptyclient",
                    "--channel",
                    "#pty",
                    "--history-lines",
                    "10",
                ],
                cwd=ROOT,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env=environment,
                close_fds=True,
                preexec_fn=attach_controlling_terminal,
            )
            os.close(slave)
            os.set_blocking(master, False)
            peer.wait_line(
                lambda line: line.startswith(":ptyclient!") and " JOIN #pty" in line,
                "TUI JOIN",
            )
            peer.send("PRIVMSG #pty :pty journey visible")
            read_pty_until(master, output, b"visible")
            if b"journey" not in output:
                raise AssertionError("TUI did not render the inbound message text")
            if b"\x1b[?1049h" not in output:
                raise AssertionError("TUI did not enter the alternate screen")
            for label in (b"e6/irc", b"ROUTE", b"CONNECTED", b"CONVERSATIONS"):
                if label not in output:
                    raise AssertionError(f"TUI did not render product state {label!r}")

            os.write(master, b"/help\r")
            read_pty_until(master, output, b"commands:")
            help_output = visible_text(output)
            if not all(part in help_output for part in (b"/msg", b"nick", b"text")):
                raise AssertionError("TUI help did not expose direct messages")

            os.write(master, b"hello from pty")
            drain_pty(master, output, 0.5)
            os.write(master, b"\r")
            peer.wait_line(
                lambda line: line.startswith(":ptyclient!")
                and " PRIVMSG #pty :hello from pty" in line,
                "TUI outbound PRIVMSG",
            )
            os.write(master, b"/quit\r")
            wait_process_and_drain(tui, master, output, TIMEOUT)
            if tui.returncode != 0:
                raise RuntimeError(f"TUI exited {tui.returncode}")
            if b"\x1b[?1049l" not in output:
                raise AssertionError("TUI did not restore the alternate screen")
            print(
                "TUI PTY journey passed: product state, help, inbound, outbound, "
                "clean restore"
            )
        except Exception:
            print(output.decode("utf-8", "replace"))
            server_log.flush()
            print((temporary / "server.log").read_text(encoding="utf-8", errors="replace"))
            raise
        finally:
            if peer is not None:
                peer.close()
            if tui is not None and tui.poll() is None:
                tui.terminate()
                try:
                    wait_process_and_drain(tui, master, output, 3)
                except subprocess.TimeoutExpired:
                    tui.kill()
                    wait_process_and_drain(tui, master, output, 3)
            if master >= 0:
                os.close(master)
            if server.poll() is None:
                server.send_signal(signal.SIGTERM)
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
            server_log.close()
            if server.returncode != 0:
                raise RuntimeError(f"e6ircd exited {server.returncode}")


if __name__ == "__main__":
    main()
