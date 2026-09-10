#!/usr/bin/env python3
"""Two linked servers, many clients, everything at once.

Every command a client sends goes through one dispatch loop, and every message
from a linked server is handled on its own task at the same time. The two touch
the same tables — users, channels, the connections to write to — so the order
they take them in is a property nobody can see by reading one function.

A deadlock does not announce itself. It looks like a server that stopped
answering, which is what the check at the end is: after all of this, can a
client that was not part of it still connect, join, speak and be answered?
"""

import os
import random
import socket
import string
import sys
import threading
import time

from harness import Client, check, section, summary

HOST = os.environ.get("SMOKE_IRC_HOST", "127.0.0.1")
A_PORT = int(os.environ.get("LINK_A_PORT", "16687"))
B_PORT = int(os.environ.get("LINK_B_PORT", "16697"))
SECONDS = float(os.environ.get("SMOKE_STRESS_SECONDS", "20"))
PER_SIDE = int(os.environ.get("SMOKE_STRESS_CLIENTS", "8"))

RUN = format(int(time.time()) % 100000, "05d")
CHANNELS = [f"#s{RUN}a", f"#s{RUN}b", f"#s{RUN}c"]

CAPS = [
    "message-tags", "server-time", "echo-message", "batch", "account-tag",
    "extended-join", "away-notify", "chghost", "setname", "invite-notify",
    "multi-prefix", "labeled-response", "draft/metadata-3", "draft/chathistory",
]

errors = []
lock = threading.Lock()


def note(msg):
    with lock:
        if len(errors) < 40:
            errors.append(msg)


def one_client(index, port, stop_at):
    """Do arbitrary things until the clock runs out, and never stop reading."""
    nick = f"s{RUN}{'a' if port == A_PORT else 'b'}{index}"
    rng = random.Random(index * 7919 + port)
    try:
        c = Client(nick, caps=rng.sample(CAPS, rng.randint(2, len(CAPS))), port=port)
    except Exception as e:  # noqa: BLE001 — a failure to connect is the finding
        note(f"{nick}: could not connect: {e}")
        return
    joined = set()
    try:
        while time.time() < stop_at:
            action = rng.randrange(14)
            chan = rng.choice(CHANNELS)
            if action == 0:
                c.send(f"JOIN {chan}")
                joined.add(chan)
            elif action == 1 and joined:
                gone = joined.pop()
                c.send(f"PART {gone} :bye")
            elif action == 2:
                c.send(f"PRIVMSG {chan} :{''.join(rng.choices(string.ascii_letters, k=20))}")
            elif action == 3:
                c.send(f"NOTICE {chan} :note")
            elif action == 4:
                other = f"s{RUN}{'b' if port == A_PORT else 'a'}{rng.randrange(PER_SIDE)}"
                c.send(f"PRIVMSG {other} :across the link")
            elif action == 5:
                c.send(f"NICK {nick}{rng.randrange(9)}")
            elif action == 6:
                c.send(f"MODE {chan} +{rng.choice('mntisR')}")
            elif action == 7:
                c.send(f"MODE {chan} -{rng.choice('mntisR')}")
            elif action == 8:
                c.send(f"TOPIC {chan} :topic {rng.randrange(1000)}")
            elif action == 9:
                c.send(rng.choice([f"WHO {chan}", "WHO *", f"NAMES {chan}", "LIST"]))
            elif action == 10:
                c.send(f"WHOIS s{RUN}{'b' if port == A_PORT else 'a'}0")
            elif action == 11:
                c.send(rng.choice(["AWAY :busy", "AWAY", f"SETNAME :name {rng.randrange(99)}"]))
            elif action == 12:
                c.send(f"METADATA * SET display-name :d{rng.randrange(99)}")
            else:
                other = f"s{RUN}{'b' if port == A_PORT else 'a'}{rng.randrange(PER_SIDE)}"
                c.send(rng.choice([f"INVITE {other} {chan}", f"MODE {chan} +o {other}"]))
            # Always keep reading: a client that stops is a client the server
            # has to queue for, and this is not a test of the send queue.
            c.read(rng.uniform(0.01, 0.06))
    except Exception as e:  # noqa: BLE001
        note(f"{nick}: {type(e).__name__}: {e}")
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass


section(f"{PER_SIDE * 2} clients across two linked servers, {SECONDS:.0f}s")
stop_at = time.time() + SECONDS
threads = [
    threading.Thread(target=one_client, args=(i, port, stop_at), daemon=True)
    for port in (A_PORT, B_PORT)
    for i in range(PER_SIDE)
]
for t in threads:
    t.start()
for t in threads:
    t.join(SECONDS + 30)

check("every client finished rather than hanging", not any(t.is_alive() for t in threads))
check("no client hit an error while it ran", not errors, errors[:5])


def still_answers(port, name):
    """A server that deadlocked accepts the connection and then says nothing.

    So the check is not that nothing is wrong but that something comes back:
    registration, a channel to join, and a round trip the server has to answer.
    """
    try:
        c = Client(f"post{RUN}{name}", caps=["echo-message"], port=port, timeout=15)
        if not c.find(" 001 "):
            return False, ["no welcome"] + c.lines[:4]
        c.join(f"#after{RUN}")
        if not c.find(" 366 ", lines=c.lines):
            return False, ["no end of names"] + c.lines[-4:]
        mark = c.mark()
        c.send(f"PRIVMSG #after{RUN} :still here")
        c.send("PING alive")
        c.wait_for("PONG", seconds=10)
        seen = c.since(mark)
        c.close()
        if not [l for l in seen if "PONG" in l]:
            return False, ["no pong"] + seen[-4:]
        if not [l for l in seen if "still here" in l]:
            return False, ["no echo of the message"] + seen[-4:]
        return True, None
    except Exception as e:  # noqa: BLE001
        return False, str(e)


section("both servers are still there")
for port, name in ((A_PORT, "A"), (B_PORT, "B")):
    ok, detail = still_answers(port, name)
    check(f"server {name} still registers a client and carries its message", ok, detail)

summary("stress")
