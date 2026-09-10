"""irctest controller for rIRCd.

irctest starts a fresh server for every test and expects it to come up empty,
while rIRCd keeps accounts, channels and history in MariaDB. Each pytest worker
therefore gets a database of its own, emptied at every server start, so an
account registered by one test is gone before the next one runs.

Point it at a MariaDB that may be freely written to:

    IRCTEST_RIRCD_DB_PORT=3399 \
    IRCTEST_RIRCD=target/release/rircd \
    pytest --controller rircd

See tests/irctest/run.sh, which sets all of this up.
"""

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Optional, Type

from irctest import patma
from irctest.basecontrollers import BaseServerController, DirectoryBasedController
from irctest.cases import BaseServerTestCase
from irctest.specifications import Capabilities, OptionalBehaviors

RIRCD_BIN = os.environ.get("IRCTEST_RIRCD", "rircd")
MARIADB_BIN = os.environ.get("IRCTEST_MARIADB", "mariadb")
DB_HOST = os.environ.get("IRCTEST_RIRCD_DB_HOST", "127.0.0.1")
DB_PORT = os.environ.get("IRCTEST_RIRCD_DB_PORT", "3399")
DB_USER = os.environ.get("IRCTEST_RIRCD_DB_USER", "root")
DB_PASSWORD = os.environ.get("IRCTEST_RIRCD_DB_PASSWORD", "")

# What irctest's operator tests log in with.
OPER_NAME = "operuser"
OPER_PASSWORD = "operpassword"

_oper_hash: Optional[str] = None


def oper_password_hash() -> str:
    """bcrypt hash of OPER_PASSWORD, computed once.

    Hashing is deliberately slow, and every test starts a server, so doing this
    per server would dominate the run.
    """
    global _oper_hash
    if _oper_hash is None:
        proc = subprocess.run(
            [RIRCD_BIN, "genpasswd"],
            input=f"{OPER_PASSWORD}\n{OPER_PASSWORD}\n",
            capture_output=True,
            text=True,
        )
        match = re.search(r"\$2[aby]\$[^\s]+", proc.stdout)
        if not match:
            raise RuntimeError(f"could not read a hash out of genpasswd: {proc.stdout!r}")
        _oper_hash = match.group(0)
    return _oper_hash


def mariadb(sql: str, database: Optional[str] = None) -> str:
    cmd = [MARIADB_BIN, "--protocol=TCP", "-h", DB_HOST, "-P", DB_PORT, "-u", DB_USER]
    if DB_PASSWORD:
        cmd.append(f"--password={DB_PASSWORD}")
    cmd += ["-N", "-B"]  # no column names, tab separated
    if database:
        cmd.append(database)
    cmd += ["-e", sql]
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return proc.stdout


def worker_database() -> str:
    """One database per pytest worker, reused by every test it runs.

    Creating the schema costs about six seconds — thirty DDL statements, each
    its own MariaDB transaction — so a fresh database per test would cost more
    than the tests themselves. Reusing one and emptying it between tests brings
    server startup down to about 0.3s. Workers get separate databases so
    `pytest -n` stays isolated.
    """
    worker = os.environ.get("PYTEST_XDIST_WORKER", "main")
    return f"irctest_rircd_{worker}"


def reset_database(name: str) -> None:
    """Create the database if needed, and empty whatever is in it.

    DELETE rather than TRUNCATE, and retried: the previous test's server is
    killed rather than shut down, so its connections can still be open when
    the next test starts. TRUNCATE wants an exclusive metadata lock and fails
    behind them, which fails a test that had not begun.
    """
    mariadb(f"CREATE DATABASE IF NOT EXISTS `{name}`")
    tables = [t for t in mariadb("SHOW TABLES", database=name).split() if t]
    if not tables:
        return
    deletes = " ".join(f"DELETE FROM `{t}`;" for t in tables)
    last: Optional[subprocess.CalledProcessError] = None
    for attempt in range(10):
        try:
            mariadb(
                f"SET FOREIGN_KEY_CHECKS=0; {deletes} SET FOREIGN_KEY_CHECKS=1;",
                database=name,
            )
            return
        except subprocess.CalledProcessError as e:
            last = e
            time.sleep(0.2 * (attempt + 1))
    raise RuntimeError(
        f"could not empty {name} after 10 attempts: "
        f"{last.stderr.strip() if last else 'unknown'}"
    )


# Which names count as the same name. The suite parameterises its channel
# casemapping tests over `ascii` and `rfc1459` and skips whichever the server
# does not advertise, so proving both means running it twice:
#
#     IRCTEST_RIRCD_CASEMAPPING=rfc1459 tests/irctest/run.sh
CASEMAPPING = os.environ.get("IRCTEST_RIRCD_CASEMAPPING", "ascii")

CONFIG = """\
[server]
name = "My.Little.Server"
casemapping = "{casemapping}"
listen = [{listen}]
listen_tls = [{listen_tls}]
listen_ws = [{listen_ws}]
motd = "irctest"
description = "test server"
register_before_connect = {register_before_connect}
{password_line}
# The read-marker tests reconnect and expect to resume their session, and open
# a second connection on one account.
persistent_sessions = true
multiclient = true
# irctest asserts on exact 005 values, and a cloak would change the host
# halfway through registration.
nick_protection = {nick_protection}
admin_name = "Test Admin"
admin_location = "Test Location"
admin_email = "admin@example.com"

[network]
name = "IRCTestNet"

[database]
host = "{db_host}"
port = {db_port}
user = "{db_user}"
password = "{db_password}"
database = "{db_name}"

[limits]
# Every test connects from 127.0.0.1 and several open many connections at once.
max_connections_per_ip = 0
max_channels_per_client = 100
# The tests send bursts far faster than a person types, and are checking the
# protocol rather than the rate limiter. The default 10-command allowance
# throttles them into timeouts.
flood_burst = 1000.0
flood_rate = 1000.0
# Several tests register accounts with passwords like "bar"; they are checking
# SASL, not our password policy.
min_password_length = 1
{tls_section}
{email_section}
[[opers]]
name = "{oper_name}"
hostmask = "*"
password_hash = "{oper_hash}"
"""


class RircdController(BaseServerController, DirectoryBasedController):
    software_name = "rIRCd"
    supported_sasl_mechanisms = {"PLAIN", "SCRAM-SHA-256", "EXTERNAL"}
    supports_sts = True
    extban_mute_char = "m"

    capabilities = frozenset(
        (
            Capabilities.ACCOUNT_NOTIFY,
            Capabilities.ACCOUNT_TAG,
            Capabilities.AWAY_NOTIFY,
            Capabilities.BATCH,
            Capabilities.ECHO_MESSAGE,
            Capabilities.EXTENDED_JOIN,
            Capabilities.EXTENDED_MONITOR,
            Capabilities.LABELED_RESPONSE,
            Capabilities.MESSAGE_REDACTION,
            Capabilities.MESSAGE_TAGS,
            Capabilities.MULTILINE,
            Capabilities.MULTI_PREFIX,
            Capabilities.READ_MARKER,
            Capabilities.SERVER_TIME,
            Capabilities.SETNAME,
            Capabilities.STS,
        )
    )

    # Behaviours the specifications leave optional. Anything not declared here
    # is skipped rather than run, so under-declaring flatters the result: these
    # are the ones rIRCd actually does.
    optional_behaviors = frozenset(
        (
            OptionalBehaviors.BAN_EXCEPTION_MODE,
            OptionalBehaviors.CAP_REQ_MINUS,
            OptionalBehaviors.ELIST_U,
            OptionalBehaviors.INVITE_EXCEPTION_MODE,
            OptionalBehaviors.INVITE_OVERRIDES_LIMIT,
            OptionalBehaviors.MULTI_JOIN,
            OptionalBehaviors.MULTI_NAMES_COMMAND,
            OptionalBehaviors.NO_CTCP,
            OptionalBehaviors.SASL_AFTER_REGISTRATION,
            OptionalBehaviors.SASL_REAUTHENTICATION,
        )
    )

    isupport = {
        "BOT": "B",
        # Whichever one this run configured; the suite asserts the server
        # says what its controller expects.
        "CASEMAPPING": CASEMAPPING,
        "CHATHISTORY": patma.ANYSTR,
        "ELIST": patma.StrRe(".*U.*"),
        "EXCEPTS": patma.ANYOPTSTR,
        "INVEX": patma.ANYOPTSTR,
        "MONITOR": patma.ANYSTR,
        "MSGREFTYPES": "msgid,timestamp",
        "PREFIX": "(ohv)@%+",
        "STATUSMSG": "@+",
        "TARGMAX": patma.ANYSTR,
        "UTF8ONLY": None,
        "WHOX": None,
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._db_name: Optional[str] = None
        self._config_path: Optional[Path] = None
        self._password: Optional[str] = None

    def run(
        self,
        hostname: str,
        port: int,
        *,
        password: Optional[str],
        ssl: bool,
        run_services: bool,
        faketime: Optional[str],
        config: Optional[Any] = None,
        websocket_hostname: Optional[str] = None,
        websocket_port: Optional[int] = None,
    ) -> None:
        self._password = password

        self.create_config()
        assert self.directory
        self.port = port
        self.hostname = hostname

        self._db_name = worker_database()
        reset_database(self._db_name)

        listen = listen_tls = ""
        tls_section = ""
        if ssl:
            self.gen_ssl()
            listen_tls = f'"{hostname}:{port}"'
            # Naming a certificate is what turns TLS on, whether or not a TLS
            # listener exists, so the section is only written for SSL runs.
            tls_section = f'\n[tls]\ncert = "{self.pem_path}"\nkey = "{self.key_path}"\n'
        else:
            listen = f'"{hostname}:{port}"'

        listen_ws = ""
        if websocket_hostname and websocket_port:
            listen_ws = f'"{websocket_hostname}:{websocket_port}"'

        config_path = self.directory / "config.toml"
        self._config_path = config_path
        config_path.write_text(
            CONFIG.format(
                casemapping=CASEMAPPING,
                listen=listen,
                listen_tls=listen_tls,
                listen_ws=listen_ws,
                nick_protection="true" if run_services else "false",
                register_before_connect=(
                    "false"
                    if self.test_config.account_registration_before_connect is False
                    else "true"
                ),
                password_line=(
                    f'password = "{self._password}"' if self._password else ""
                ),
                # Only the capability value and REGISTER's answer are under test,
                # so the address this points at never has to accept mail.
                email_section=(
                    '[email]\nsmtp_host = "127.0.0.1"\nsmtp_port = 1\n'
                    'encryption = "none"\nfrom = "irctest <noreply@example.com>"\n'
                    if self.test_config.account_registration_requires_email
                    else ""
                ),
                db_host=DB_HOST,
                db_port=DB_PORT,
                db_user=DB_USER,
                db_password=DB_PASSWORD,
                db_name=self._db_name,
                tls_section=tls_section,
                oper_name=OPER_NAME,
                oper_hash=oper_password_hash(),
            )
        )

        self.proc = self.execute(
            [RIRCD_BIN, "--config", str(config_path), "run"],
            env={**os.environ, "RUST_LOG": "rircd=debug" if self.debug_mode else "rircd=warn"},
        )

    def registerUser(
        self,
        case: BaseServerTestCase,
        username: str,
        password: Optional[str] = None,
    ) -> None:
        # rIRCd registers accounts itself (draft/account-registration); there is
        # no separate services package to talk to.
        if not case.run_services:
            raise ValueError(
                "Attempted to register a nick, but `run_services` is not True."
            )
        assert password
        # Created straight in the database rather than over IRC: a REGISTER
        # carrying one of the long passwords these tests use does not fit in a
        # 512-byte line, and this is setup, not the thing under test.
        assert self._config_path, "server must be running"
        proc = subprocess.run(
            [RIRCD_BIN, "--config", str(self._config_path), "adduser", username, password],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"could not create account {username}: {proc.stderr.strip()}")

    def wait_for_services(self) -> None:
        # Accounts are handled by the server itself, so there is nothing extra
        # to wait for.
        pass

    # The database is reused by the next test on this worker and emptied when
    # that one starts, so teardown leaves it alone.


def get_irctest_controller_class() -> Type[RircdController]:
    return RircdController
