"""irctest controller for e6ircd.

Usage (from an irctest checkout, with this repo's target/ built):
    PATH="$E6IRC_REPO/target/debug:$PATH" \
    PYTHONPATH="$E6IRC_REPO/vendor/tests/irctest" \
    pytest --controller=e6ircd_controller -k 'not deprecated' <test files>

Pinned against irctest commit a468d9fcd64abc72b02ecb20f4f8612fd72c8829
(see vendor/tests/libera-snapshot/PROVENANCE.md for the vendoring policy; the
irctest checkout itself is fetched, not vendored).
"""

from typing import Optional, Set, Type

from irctest.basecontrollers import BaseServerController, DirectoryBasedController
from irctest.runner import NotImplementedByController

TEMPLATE_CONFIG = """
server_name = "My.Little.Server"
network_name = "irctest-net"
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
    supported_sasl_mechanisms: Set[str] = set()  # needs PostgreSQL; off here
    supports_sts = False

    def create_config(self) -> None:
        super().create_config()
        with self.open_file("e6irc.toml"):
            pass

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
        if run_services:
            raise NotImplementedByController("external services (integrated instead)")
        if faketime is not None:
            raise NotImplementedByController("faketime")
        assert self.proc is None
        self.port = port
        self.hostname = hostname
        self.create_config()
        assert self.directory
        with self.open_file("e6irc.toml") as fd:
            fd.write(TEMPLATE_CONFIG.format(hostname=hostname, port=port))
        self.proc = self.execute(
            [self.binary_name, "--config", str(self.directory / "e6irc.toml")],
        )


def get_irctest_controller_class() -> Type[E6ircdController]:
    return E6ircdController
