"""Shared helpers for the rIRCd smoke tests.

Standard library only — the suites talk raw IRC over a socket so they exercise
the same wire format a real client would.
"""

import base64
import os
import socket
import subprocess
import sys
import time

IRC_HOST = os.environ.get("SMOKE_IRC_HOST", "127.0.0.1")
IRC_PORT = int(os.environ.get("SMOKE_IRC_PORT", "16667"))
DB_SOCKET = os.environ.get("SMOKE_DB_SOCKET", "")  # also used to stop/start it in the outage suite
MAIL_DIR = os.environ.get("SMOKE_MAIL_DIR", "")
# Distinct per run, so suites can be re-run against a live server (--reuse)
# without tripping over accounts and channels they created last time.
RUN_ID = os.environ.get("SMOKE_RUN_ID") or format(int(time.time()) % 100000, "05d")
OPER_NAME = os.environ.get("SMOKE_OPER_NAME", "smokeoper")
OPER_PASSWORD = os.environ.get("SMOKE_OPER_PASSWORD", "smoke-oper-password")

# A valid P-256 subscription key pair, from the RFC 8291 section 5 example.
P256DH = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
AUTH_SECRET = "BTBZMqHH6r4Tts7J_aSIgg"


class Client:
    """One IRC connection, with a record of every line the server sent."""

    def __init__(self, nick=None, user=None, realname=None, caps=None, timeout=10):
        self.sock = socket.create_connection((IRC_HOST, IRC_PORT), timeout=timeout)
        self.buf = ""
        self.lines = []
        self.nick = nick
        if nick:
            self.register(nick, user, realname, caps)

    # ── connection ────────────────────────────────────────────────────────────

    def send(self, line):
        self.sock.sendall((line + "\r\n").encode())
        return self

    def register(self, nick, user=None, realname=None, caps=None):
        """Complete connection registration, optionally negotiating capabilities."""
        self.nick = nick
        self.send("CAP LS 302")
        self.read(0.5)
        if caps:
            self.send("CAP REQ :" + " ".join(caps))
        self.send(f"NICK {nick}")
        self.send(f"USER {nick} 0 * :{realname or nick}")
        self.send("CAP END")
        self.wait_for(" 376 ", " 422 ", " 001 ", seconds=5)
        return self

    def join(self, channel, key=None, seconds=5.0):
        """JOIN and wait for the server to confirm, so join order is deterministic.

        Two clients joining a new channel without waiting race for who creates it —
        and therefore who gets +o.
        """
        self.send(f"JOIN {channel} {key}" if key else f"JOIN {channel}")
        self.wait_for(f"JOIN {channel}", f"JOIN :{channel}", " 366 ", " 473 ", " 475 ", seconds=seconds)
        return self

    def read(self, seconds=1.0):
        """Collect lines for a while. Answers PING so the connection stays up."""
        self.sock.settimeout(seconds)
        end = time.time() + seconds
        while time.time() < end:
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            self.buf += data.decode("utf-8", "replace")
            while "\r\n" in self.buf:
                line, self.buf = self.buf.split("\r\n", 1)
                self.lines.append(line)
                if line.startswith("PING"):
                    self.send("PONG " + line.split(" ", 1)[1])
        return self.lines

    def wait_for(self, *needles, seconds=5.0):
        """Read until a *new* line contains any of `needles`, or the deadline passes.

        Only lines that arrive after this call count: an earlier 473 from a
        previous attempt must not satisfy a wait for the next one.
        """
        start = len(self.lines)
        end = time.time() + seconds
        while time.time() < end:
            for line in self.lines[start:]:
                if any(n in line for n in needles):
                    return line
            self.read(0.3)
        for line in self.lines[start:]:
            if any(n in line for n in needles):
                return line
        return None

    def close(self):
        try:
            self.send("QUIT :smoke test over")
            self.sock.close()
        except OSError:
            pass

    # ── inspection ────────────────────────────────────────────────────────────

    def mark(self):
        """Remember the current position, so `since()` returns only newer lines."""
        return len(self.lines)

    def since(self, mark):
        return self.lines[mark:]

    def find(self, *needles, lines=None):
        pool = self.lines if lines is None else lines
        return [l for l in pool if all(n in l for n in needles)]

    def sasl_plain(self, account, password):
        """Authenticate mid-handshake. Call before CAP END."""
        self.send("AUTHENTICATE PLAIN")
        self.read(0.7)
        payload = base64.b64encode(f"\0{account}\0{password}".encode()).decode()
        self.send("AUTHENTICATE " + payload)
        self.read(1.5)
        return self


def connect_negotiating(nick, caps=None):
    """A client that has sent CAP LS but not yet completed registration."""
    c = Client()
    c.send("CAP LS 302")
    c.read(0.7)
    if caps:
        c.send("CAP REQ :" + " ".join(caps))
        c.read(0.3)
    c.send(f"NICK {nick}")
    c.send(f"USER {nick} 0 * :{nick}")
    c.nick = nick
    return c


# ── database access ───────────────────────────────────────────────────────────


def db(query):
    """Run one query against the smoke-test database, returning stripped output."""
    if not DB_SOCKET:
        raise RuntimeError("SMOKE_DB_SOCKET is not set")
    out = subprocess.run(
        ["mariadb", f"--socket={DB_SOCKET}", "-N", "-B", "rircdb", "-e", query],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"query failed: {out.stderr.strip()}")
    return out.stdout.strip()


# ── mail sink ─────────────────────────────────────────────────────────────────


def mails():
    """Every message the SMTP sink has captured, oldest first.

    A file that is still being written is skipped: the sink creates it before
    filling it, so a reader can otherwise see an empty message.
    """
    if not MAIL_DIR or not os.path.isdir(MAIL_DIR):
        return []
    names = sorted(
        (n for n in os.listdir(MAIL_DIR) if n.startswith("mail-")),
        key=lambda n: int(n.split("-")[1].split(".")[0]),
    )
    out = []
    for name in names:
        body = open(os.path.join(MAIL_DIR, name)).read()
        if "Subject:" in body:
            out.append(body)
    return out


def wait_for_mail(count=1, seconds=15.0):
    """Block until at least `count` messages have arrived."""
    end = time.time() + seconds
    while time.time() < end:
        found = mails()
        if len(found) >= count:
            return found
        time.sleep(0.3)
    return mails()


def clear_mail():
    if MAIL_DIR and os.path.isdir(MAIL_DIR):
        for name in os.listdir(MAIL_DIR):
            if name.startswith("mail-"):
                os.remove(os.path.join(MAIL_DIR, name))


# ── result reporting ──────────────────────────────────────────────────────────

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = DIM = RESET = ""

_failures = []
_passed = 0


def section(title):
    print(f"\n{DIM}── {title}{RESET}")


def check(name, condition, detail=""):
    """Record one assertion. `detail` is printed only on failure."""
    global _passed
    if condition:
        _passed += 1
        print(f"  {GREEN}ok{RESET}   {name}")
    else:
        _failures.append(name)
        print(f"  {RED}FAIL{RESET} {name}")
        if detail:
            text = detail if isinstance(detail, str) else "\n         ".join(map(str, detail))
            print(f"         {DIM}{text}{RESET}")
    return condition


def summary(suite):
    """Print totals and exit non-zero if anything failed."""
    total = _passed + len(_failures)
    if _failures:
        print(f"\n{RED}{suite}: {len(_failures)}/{total} checks failed{RESET}")
        for name in _failures:
            print(f"  - {name}")
        sys.exit(1)
    print(f"\n{GREEN}{suite}: {total}/{total} checks passed{RESET}")
    sys.exit(0)
