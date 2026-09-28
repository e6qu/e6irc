"""irctest controller for e6ircd.

Usage (from an irctest checkout, with this repo's target/ built):
    PATH="$E6IRC_REPO/target/debug:$PATH" \
    PYTHONPATH="$E6IRC_REPO/vendor/tests/irctest" \
    pytest --controller=e6ircd_controller -k 'not deprecated' <test files>

Set E6IRC_IRCTEST_DB to a PostgreSQL URL to run the persistence-backed suites
(SASL, integrated NickServ services, CHATHISTORY): the controller then embeds a
`[database]` section, advertises SASL PLAIN, and truncates the account, message,
and managed-settings tables before each server so every test starts clean and
imports that case's ephemeral listener and policy. Without it, the server runs
DB-less exactly as before (the no-account green list).

Set E6IRC_IRCTEST_EDGE=1 to run every case through an edge (DESIGN §19): the
controller mints link credentials with `e6ircd edge-credentials`, starts a core
in edge mode (`[edge_link]`, no listeners of its own) and an `e6ircd edge`
holding the case's listeners, so each client reaches the core over the
mutual-TLS core link. The server under test is the pair: either one exiting
fails the case, and stopping the server stops both.

Pinned against irctest commit a468d9fcd64abc72b02ecb20f4f8612fd72c8829
(see vendor/tests/libera-snapshot/PROVENANCE.md for the vendoring policy; the
irctest checkout itself is fetched, not vendored).
"""

import os
import subprocess
import time
from typing import Optional, Set, Type

from irctest.basecontrollers import BaseServerController, DirectoryBasedController
from irctest.runner import NotImplementedByController

_DB_URL = os.environ.get("E6IRC_IRCTEST_DB")
_EDGE = os.environ.get("E6IRC_IRCTEST_EDGE") == "1"

TEMPLATE_CONFIG = """
server_name = "My.Little.Server"
network_name = "irctest-net"
# irctest asserts this exact server description in RPL_LINKS.
description = "test server"
motd = ["Welcome to the irctest server"]
nicklen = 32

{listeners}
[[oper]]
name = "operuser"
password = "operpassword"

[limits]
# Every QUIT comment is shown, however young the connection: irctest's
# Solanum controller leaves Solanum's anti_spam_exit_message_time at its code
# default, 0, and testQuit quits a second after connecting.
anti_spam_exit_message_time_seconds = 0
"""


class E6ircdController(BaseServerController, DirectoryBasedController):
    software_name = "e6ircd"
    binary_name = "e6ircd"
    # e6ircd only advertises SASL when a database backs the account store, so
    # the mechanism set is gated on E6IRC_IRCTEST_DB.
    supported_sasl_mechanisms: Set[str] = {"PLAIN"} if _DB_URL else set()
    supports_sts = False
    # Integrated services: account registration goes through NickServ REGISTER,
    # which the base DirectoryBasedController.registerUser drives.
    nickserv = "NickServ"

    # The core behind the edge, when the case runs through one (`self.proc`
    # is then the edge, which holds the port the case connects to).
    core_proc: Optional[subprocess.Popen] = None

    def create_config(self) -> None:
        super().create_config()
        with self.open_file("e6irc.toml"):
            pass

    def check_is_alive(self) -> None:
        super().check_is_alive()
        if self.core_proc is not None:
            self.core_proc.poll()
            if self.core_proc.returncode is not None:
                raise RuntimeError(
                    f"the core behind the edge returned {self.core_proc.returncode}"
                )

    def _stop_core(self) -> None:
        if self.core_proc is None:
            return
        self.core_proc.terminate()
        try:
            self.core_proc.wait(10)
        except subprocess.TimeoutExpired:
            self.core_proc.kill()
            self.core_proc.wait(10)
        self.core_proc = None

    def kill_proc(self) -> None:
        super().kill_proc()
        self._stop_core()

    def terminate(self) -> None:
        super().terminate()
        self._stop_core()

    def _credentials(self, *args: str) -> None:
        assert self.directory
        subprocess.run(
            [self.binary_name, "edge-credentials", *args],
            cwd=self.directory,
            check=True,
            capture_output=True,
        )

    def wait_for_services(self) -> None:
        # Integrated services come up with the server, so there is nothing
        # separate to wait for (the base assumes a services_controller).
        pass

    def registerUser(self, case, username, password=None):  # type: ignore[override]
        # Integrated services: register the account by driving NickServ REGISTER
        # over IRC (the base `registerUser` assumes a separate services
        # controller, which e6ircd does not have).
        assert password, "e6ircd account registration requires a password"
        client = case.addClient(show_io=True)
        case.sendLine(client, "NICK " + username)
        case.sendLine(client, "USER r e g :user")
        while case.getRegistrationMessage(client).command != "001":
            pass
        case.getMessages(client)
        case.sendLine(client, f"PRIVMSG {self.nickserv} :REGISTER {password} foo@example.org")
        # Registration writes to the DB asynchronously, so wait for NickServ to
        # confirm before the caller authenticates. Registration runs over a
        # normal PRIVMSG, so it is subject to the 512-byte line limit: a long
        # enough password draws ERR_INPUTTOOLONG instead. Fail loudly here —
        # returning anyway would surface later as an inscrutable SASL failure
        # in whichever test asked for the account.
        confirmed = False
        deadline = time.time() + 5
        while time.time() < deadline and not confirmed:
            for msg in case.getMessages(client):
                if msg.command == "417":
                    raise RuntimeError(
                        f"cannot register {username!r}: the REGISTER line exceeds "
                        f"the 512-byte limit (password is {len(password)} bytes)"
                    )
                if msg.command == "NOTICE" and "registered" in msg.params[-1]:
                    confirmed = True
                    break
            if not confirmed:
                time.sleep(0.05)
        if not confirmed:
            raise RuntimeError(f"NickServ did not confirm registration of {username!r}")
        case.sendLine(client, "QUIT")
        case.assertDisconnected(client)

    def run(
        self,
        hostname: str,
        port: int,
        *,
        password: Optional[str],
        ssl: bool,
        run_services: bool,
        faketime: Optional[str],
        websocket_hostname: Optional[str] = None,
        websocket_port: Optional[int] = None,
    ) -> None:
        if password is not None:
            raise NotImplementedByController("PASS")
        if ssl:
            raise NotImplementedByController("TLS in irctest harness")
        if run_services and _DB_URL is None:
            raise NotImplementedByController("services (needs E6IRC_IRCTEST_DB)")
        if faketime is not None:
            raise NotImplementedByController("faketime")
        assert self.proc is None
        # irctest synchronizes a recipient by sending PING on that recipient's
        # socket. That orders commands already in the core queue, but it cannot
        # order a command still crossing another connection's independent
        # WebSocket reader task. Give only WebSocket cases time to reach the
        # shared core; raw-only cases retain the zero-delay fast path.
        self.sync_sleep_time = 0.1 if websocket_port is not None else 0.0
        self.port = port
        self.hostname = hostname
        self.create_config()
        assert self.directory

        listeners = f'[[listeners]]\naddr = "{hostname}:{port}"\n'
        # A websocket-IRC transport is served by a dedicated listener at the
        # requested host:port (served at the root path, which is what irctest's
        # WebSocketClientMock connects to: ws://host:port).
        if websocket_port is not None:
            listeners += (
                "\n[[listeners]]\n"
                f'addr = "{websocket_hostname}:{websocket_port}"\n'
                "websocket = true\n"
            )
        link_hostname, link_port = (None, None)
        if _EDGE:
            # The listeners are the edge's; the core only links.
            link_hostname, link_port = self.get_hostname_and_port()
            config = TEMPLATE_CONFIG.format(listeners="")
        else:
            config = TEMPLATE_CONFIG.format(listeners=listeners)
        # draft/account-registration policy, which irctest varies per test case.
        config += (
            "\n[registration]\n"
            f"before_connect = {str(self.test_config.account_registration_before_connect).lower()}\n"
            f"require_email = {str(self.test_config.account_registration_requires_email).lower()}\n"
        )
        if _DB_URL is not None:
            # Any non-empty password may be set: irctest registers its
            # accounts, and tests account registration, with passwords shorter
            # than e6ircd's default eight characters ("sesame"), as the
            # services it drives elsewhere accept. Without a database there
            # are no accounts, and e6ircd refuses registration policy.
            config += "minimum_password_length = 1\n"
            # Fresh persistent state per test (a no-op on the very first run,
            # before migrations create the schema). Managed settings must be
            # reset too: each irctest case supplies a new ephemeral listener
            # and may vary registration policy. Keeping the preceding case's
            # singleton would make the next daemon bind the old port.
            subprocess.run(
                [
                    "psql",
                    _DB_URL,
                    "-c",
                    "TRUNCATE accounts, messages, server_settings CASCADE",
                ],
                check=False,
                capture_output=True,
            )
            config += f'\n[database]\nurl = "{_DB_URL}"\n'

        if _EDGE:
            self._credentials("init", "--dir", "credentials")
            self._credentials("issue", "--dir", "credentials", "--edge", "irctest")
            config += (
                "\n[edge_link]\n"
                f'addr = "{link_hostname}:{link_port}"\n'
                "ca = 'credentials/ca.pem'\n"
                "cert = 'credentials/core.pem'\n"
                "key = 'credentials/core-key.pem'\n"
            )
            with self.open_file("edge.toml") as fd:
                fd.write(
                    "[edge]\n"
                    'name = "irctest"\n'
                    f'core = ["{link_hostname}:{link_port}"]\n'
                    "ca = 'credentials/ca.pem'\n"
                    "cert = 'credentials/edge-irctest.pem'\n"
                    "key = 'credentials/edge-irctest-key.pem'\n" + listeners
                )

        with self.open_file("e6irc.toml") as fd:
            fd.write(config)
        command = [self.binary_name, "--config", str(self.directory / "e6irc.toml")]
        if not _EDGE:
            self.proc = self.execute(command)
            return
        self.core_proc = self.execute(command, cwd=self.directory, proc_name="core")
        self.proc = self.execute(
            [self.binary_name, "edge", "--config", str(self.directory / "edge.toml")],
            cwd=self.directory,
            proc_name="edge",
        )


def get_irctest_controller_class() -> Type[E6ircdController]:
    return E6ircdController
