"""irctest controller for e6ircd.

Usage (from an irctest checkout, with this repo's target/ built):
    PATH="$E6IRC_REPO/target/debug:$PATH" \
    PYTHONPATH="$E6IRC_REPO/vendor/tests/irctest" \
    pytest --controller=e6ircd_controller -k 'not deprecated' <test files>

Set E6IRC_IRCTEST_DB to a PostgreSQL URL to run the persistence-backed suites
(SASL, integrated NickServ services, CHATHISTORY): the controller then embeds a
`[database]` section, advertises SASL PLAIN, and truncates the account/message
tables before each server so every test starts clean. Without it, the server
runs DB-less exactly as before (the no-account green list).

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

TEMPLATE_CONFIG = """
server_name = "My.Little.Server"
network_name = "irctest-net"
# irctest asserts this exact server description in RPL_LINKS.
description = "test server"
motd = ["Welcome to the irctest server"]
nicklen = 32

[[listeners]]
addr = "{hostname}:{port}"

[[oper]]
name = "operuser"
password = "operpassword"
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

    def create_config(self) -> None:
        super().create_config()
        with self.open_file("e6irc.toml"):
            pass

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
        if websocket_hostname is not None or websocket_port is not None:
            raise NotImplementedByController("websockets")
        if password is not None:
            raise NotImplementedByController("PASS")
        if ssl:
            raise NotImplementedByController("TLS in irctest harness")
        if run_services and _DB_URL is None:
            raise NotImplementedByController("services (needs E6IRC_IRCTEST_DB)")
        if faketime is not None:
            raise NotImplementedByController("faketime")
        assert self.proc is None
        self.port = port
        self.hostname = hostname
        self.create_config()
        assert self.directory

        config = TEMPLATE_CONFIG.format(hostname=hostname, port=port)
        if _DB_URL is not None:
            # Fresh account + message store per test (a no-op on the very first
            # run, before migrations create the schema).
            subprocess.run(
                ["psql", _DB_URL, "-c", "TRUNCATE accounts, messages CASCADE"],
                check=False,
                capture_output=True,
            )
            config += f'\n[database]\nurl = "{_DB_URL}"\n'

        with self.open_file("e6irc.toml") as fd:
            fd.write(config)
        self.proc = self.execute(
            [self.binary_name, "--config", str(self.directory / "e6irc.toml")],
        )


def get_irctest_controller_class() -> Type[E6ircdController]:
    return E6ircdController
