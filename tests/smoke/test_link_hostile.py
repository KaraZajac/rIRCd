#!/usr/bin/env python3
"""A peer that lies, and a server that has to survive being lied to.

A link is the most trusted connection a server has: whatever a peer says about
its users is believed, because there is no way to check it. That trust has a
boundary, and this is where it is: a link speaks for the servers it carries and
for nothing else. One server on a network being compromised has to stay one
server, rather than becoming every server on it.

Run after test_link.py, which ends by killing server B — so B's place on the
network is free, and this takes it. Everything here talks to server A's link
port directly, speaking the link protocol by hand.
"""

import os
import re
import socket
import time

from harness import Client, check, section, summary

HOST = os.environ.get("SMOKE_IRC_HOST", "127.0.0.1")
A_PORT = int(os.environ.get("LINK_A_PORT", "16687"))
A_LINK_PORT = int(os.environ.get("LINK_A_LINK_PORT", "17000"))
A_NAME = os.environ.get("LINK_A_NAME", "a.link.test")
B_NAME = os.environ.get("LINK_B_NAME", "b.link.test")
LINK_DIR = os.environ.get("LINK_DIR", "")
LINK_TLS = os.environ.get("LINK_TLS") == "1"
RUN = format(int(time.time()) % 100000, "05d")

B_SID = "2BB"
STRANGER_SID = "9ZZ"


def config_value(side, key):
    """Read one key out of a generated server config."""
    try:
        text = open(os.path.join(LINK_DIR, f"{side}.toml")).read()
    except OSError:
        return ""
    found = re.search(rf'^{key} = "([^"]*)"', text, re.M)
    return found.group(1) if found else ""


def a_log():
    try:
        return open(os.path.join(LINK_DIR, "a.log")).read()
    except OSError:
        return ""


def still_serving(what):
    """The only thing that really matters: A is still a server afterwards."""
    try:
        c = Client(f"h{RUN}{abs(hash(what)) % 1000}", port=A_PORT)
        c.send(f"PING alive{RUN}")
        answered = bool(c.wait_for(f"alive{RUN}", seconds=5))
        c.close()
        return answered
    except OSError:
        return False


class Peer:
    """A hand-written link peer, saying whatever it is told to say."""

    def __init__(self, sid=B_SID, name=B_NAME, password=None, timeout=6):
        self.sock = socket.create_connection((HOST, A_LINK_PORT), timeout=timeout)
        if LINK_TLS:
            import ssl

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            cert = os.path.join(LINK_DIR, "b.cert.pem")
            key = os.path.join(LINK_DIR, "b.key.pem")
            if os.path.exists(cert):
                context.load_cert_chain(cert, key)
            self.sock = context.wrap_socket(self.sock)
        self.sid = sid
        self.name = name
        # What B sends towards A is what A expects to receive.
        self.password = password if password is not None else config_value("b", "send_password")
        self.buf = b""

    def send(self, line):
        self.sock.sendall((line + "\r\n").encode())
        return self

    def greet(self):
        self.send(f"PASS {self.password} TS 1 {self.sid}")
        self.send("CAPAB :TAGS MSGID ACCOUNT CHATHISTORY METADATA")
        self.send(f"SERVER {self.name} 1 :a peer that lies")
        return self

    def read(self, seconds=1.5):
        self.sock.settimeout(seconds)
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                data = self.sock.recv(65536)
                if not data:
                    break
                self.buf += data
            except (socket.timeout, OSError):
                break
        return self.buf.decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ── before it has proved anything ────────────────────────────────────────────

section("a peer that has not proved who it is")

wrong = Peer(password="not-the-password")
wrong.greet()
text = wrong.read(2.0)
check("a wrong password is refused", " 001 " not in text and "Linked" not in text, text[:200])
wrong.close()
check("and A is still serving", still_serving("a wrong password"))

unknown = Peer(sid="7XX", name=f"stranger{RUN}.test")
unknown.greet()
text = unknown.read(2.0)
check("a server A has no link block for is refused", "ERROR" in text or text == "", text[:200])
unknown.close()

# The SERVER line names which link block the password is checked against, so a
# peer that claims B's name with B's password but a different id is claiming to
# be somewhere B is not.
wrong_sid = Peer(sid=STRANGER_SID)
wrong_sid.greet()
text = wrong_sid.read(2.0)
check("the right password with the wrong server id is refused",
      "ERROR" in text or text == "", text[:200])
wrong_sid.close()

silent = socket.create_connection((HOST, A_LINK_PORT), timeout=5)
silent.sendall(b"PASS ")           # a line that never ends
time.sleep(1.0)
silent.close()
check("a peer that never finishes its first line costs nothing",
      still_serving("an unfinished greeting"))

# ── once it is on the network ────────────────────────────────────────────────

section("a peer that lies about who it speaks for")

before = a_log()
peer = Peer()
peer.greet()
peer.read(2.0)
linked = "Linked" in a_log()[len(before):]
check("the peer is on the network", linked, a_log()[-300:])

if linked:
    # A user of its own, introduced properly. Everything else is measured
    # against this working.
    # UID <nick> <hops> <nick ts> <user> <host> <uid> <account> :<realname>
    mine = f"{B_SID}AAAAAA"
    peer.send(f":{B_SID} UID liar 1 {int(time.time())} liar liar.test {mine} * :A Liar")
    peer.send(f":{B_SID} EOB")
    time.sleep(1.0)
    watcher = Client(f"w{RUN}", port=A_PORT)
    mark = watcher.mark()
    watcher.send("WHOIS liar")
    watcher.read(1.5)
    check("a user it does introduce is accepted",
          bool(watcher.find(" 311 ", "liar", lines=watcher.since(mark))), watcher.since(mark)[-3:])

    # Now the lie: acting on a user belonging to a server this link does not
    # carry. A is linked to nobody else, so 9ZZ is not behind this peer.
    victim = Client(f"v{RUN}", port=A_PORT)
    time.sleep(0.4)
    before = a_log()
    peer.send(f":{STRANGER_SID}AAAAAA QUIT :not mine to quit")
    peer.send(f":{STRANGER_SID}AAAAAA NICK stolen{RUN}")
    peer.send(f":{STRANGER_SID}AAAAAA KILL {mine} :not mine to kill")
    peer.send(f":{STRANGER_SID}AAAAAA PRIVMSG #anywhere :not mine to say")
    time.sleep(1.2)
    new_log = a_log()[len(before):]
    check("A refuses to let it speak for a server it does not carry",
          "does not carry" in new_log,
          [l for l in new_log.splitlines() if "Refus" in l][:3])

    mark = victim.mark()
    victim.send(f"WHOIS stolen{RUN}")
    victim.read(1.5)
    check("and the nick it tried to take does not exist",
          bool(victim.find(" 401 ", lines=victim.since(mark))), victim.since(mark)[-3:])

    mark = watcher.mark()
    watcher.send("WHOIS liar")
    watcher.read(1.5)
    check("nor did the kill it had no right to make land",
          bool(watcher.find(" 311 ", "liar", lines=watcher.since(mark))), watcher.since(mark)[-3:])

    # The one that matters. A's own users are keyed by A's own ids, so a peer
    # that may speak for any id can disconnect anybody on the server it linked
    # to. The ids are handed out in order from a counter, so saying QUIT for the
    # first few hundred is saying it for everyone here, this watcher included.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    def a_uid(n):
        tail = ""
        for _ in range(6):
            tail = alphabet[n % len(alphabet)] + tail
            n //= len(alphabet)
        return "1AA" + tail

    for n in range(300):
        peer.send(f":{a_uid(n)} QUIT :you do not work here any more")
    time.sleep(1.5)
    mark = watcher.mark()
    watcher.send(f"PING survived{RUN}")
    check("a peer cannot disconnect the users of the server it linked to",
          bool(watcher.wait_for(f"survived{RUN}", seconds=5)), watcher.since(mark)[-3:])
    mark = victim.mark()
    victim.send(f"WHOIS w{RUN}")
    victim.read(1.5)
    check("and they are all still here",
          bool(victim.find(" 311 ", f"w{RUN}", lines=victim.since(mark))), victim.since(mark)[-3:])

    # An answer to a question nobody asked. The token was never issued here, so
    # there is nothing for it to finish.
    before = a_log()
    peer.send(f":{mine} WHOISREP {mine} deadbeef 999999 1")
    peer.send(f":{mine} WHOISREP {mine} 1 0 0")
    time.sleep(0.8)
    check("an answer to a question nobody asked changes nothing",
          still_serving("an unasked answer"))

    # A prefix that is neither a user nor a server.
    before = a_log()
    peer.send("::: QUIT :nonsense")
    peer.send(f":{'z' * 60} NICK nope")
    peer.send(":a NICK nope")
    time.sleep(0.8)
    check("a prefix that names nothing is refused",
          "neither a user nor a server" in a_log()[len(before):],
          [l for l in a_log()[len(before):].splitlines() if "Refus" in l][:2])
    check("and A is still serving", still_serving("a nonsense prefix"))

    # Nonsense at volume, on a connection that has been believed.
    junk = 0
    stop = time.time() + 4
    while time.time() < stop:
        try:
            peer.send(f":{B_SID}AAAAAB " + "X" * 400)
            peer.send(f":{B_SID} SJOIN {int(time.time())} #flood{junk} + :" + " ".join(
                f"{B_SID}{n:06d}" for n in range(20)))
            junk += 2
        except OSError:
            break
    time.sleep(1.0)
    check(f"{junk} lines of nonsense from a trusted peer do not take A down",
          still_serving("a flood from a peer"))

    victim.close()
    watcher.close()

peer.close()
time.sleep(0.5)
check("A survives the peer going away", still_serving("the peer leaving"))
check("and nothing panicked", "panicked" not in a_log(),
      [l for l in a_log().splitlines() if "panicked" in l][:2])

summary("link-hostile")
