#!/usr/bin/env python3
"""Hostile input: what a client sends when it is not trying to be a client.

Every check here ends the same way — the server is still serving. A server that
answers one of these badly is a server one connection can take away from
everybody else, because rIRCd runs every client's commands through a single
dispatch loop.
"""

import os
import socket
import time

from harness import (
    IRC_HOST,
    IRC_PORT,
    OPER_PASSWORD,
    Client,
    check,
    section,
    summary,
)

RUN = format(int(time.time()) % 100000, "05d")


def raw(timeout=5):
    """A bare socket, with none of the harness's politeness."""
    return socket.create_connection((IRC_HOST, IRC_PORT), timeout=timeout)


def still_alive(what, nick):
    """The whole point: after `what`, a normal client can still use the server.

    Registering, joining and getting a PONG back after a PRIVMSG covers the
    whole path — the listener, the dispatch loop, and the writer.
    """
    try:
        c = Client(nick)
        c.join(f"#alive{RUN}")
        joined = bool(c.find(" 366 "))
        c.send(f"PRIVMSG #alive{RUN} :still here")
        c.send(f"PING :alive{RUN}")
        answered = bool(c.wait_for(f"alive{RUN}", seconds=5))
        c.close()
        return joined and answered
    except OSError as e:
        return check(f"server still serving after {what}", False, str(e))


def survives(name, body, nick):
    """Run `body` against a raw socket, then prove the server survived it."""
    try:
        body()
    except OSError:
        # The server hanging up on us is a fine answer; dying is not.
        pass
    check(f"server survives {name}", still_alive(name, nick))


# ── oversized and malformed lines ────────────────────────────────────────────

section("oversized input")


def megabyte_with_no_newline():
    s = raw()
    s.sendall(b"NICK " + b"a" * (1024 * 1024))
    time.sleep(0.3)
    s.close()


survives("a megabyte with no line ending", megabyte_with_no_newline, f"h1{RUN}")


def ten_megabytes_of_junk():
    s = raw()
    chunk = b"x" * 65536
    try:
        for _ in range(160):
            s.sendall(chunk)
    except OSError:
        pass
    s.close()


survives("ten megabytes of junk", ten_megabytes_of_junk, f"h2{RUN}")


def many_parameters():
    s = raw()
    s.sendall(b"NICK n\r\nUSER n 0 * :n\r\n")
    time.sleep(0.3)
    s.sendall(b"PRIVMSG " + b" ".join(b"p" for _ in range(400)) + b"\r\n")
    time.sleep(0.2)
    s.close()


survives("a command with four hundred parameters", many_parameters, f"h3{RUN}")

# ── bytes that are not text ──────────────────────────────────────────────────

def one_absurd_line():
    """A single line far past the limit gets 417, not a closed server."""
    c = Client(f"h13{RUN}")
    mark = c.mark()
    c.send("PRIVMSG #x :" + "y" * 4000)
    c.read(1.0)
    got = bool(c.find(" 417 ", lines=c.since(mark)))
    c.close()
    return got


check("a line past the limit is answered with 417", one_absurd_line())

section("bytes that are not text")


def control_bytes():
    s = raw()
    s.sendall(b"NICK \x00\x01\x02\x03\r\n")
    s.sendall(b"USER \xff\xfe\xfd 0 * :\x07\x08\r\n")
    s.sendall(b"\r\n\r\n\r\n")
    s.sendall(b":\r\n")
    s.sendall(b"@\r\n")
    s.sendall(b"@;;;;;; \r\n")
    s.sendall(b"@a=\\\r\n")
    time.sleep(0.3)
    s.close()


survives("NUL bytes and invalid UTF-8", control_bytes, f"h4{RUN}")


def lone_cr_and_lf():
    s = raw()
    s.sendall(b"NICK a\rNICK b\nNICK c\r\n")
    s.sendall(b"USER a 0 * :a\n")
    time.sleep(0.3)
    s.close()


survives("bare CR and bare LF as separators", lone_cr_and_lf, f"h5{RUN}")


def enormous_tag_block():
    s = raw()
    tags = b"@" + b";".join(b"t%d=v" % i for i in range(4000))
    s.sendall(tags + b" PRIVMSG #x :hi\r\n")
    time.sleep(0.3)
    s.close()


survives("a tag block far past the tag limit", enormous_tag_block, f"h6{RUN}")

# ── commands used as weapons ─────────────────────────────────────────────────

section("commands used as weapons")

c = Client(f"h7{RUN}")

mark = c.mark()
# Kept inside the 512-byte line limit on purpose: the point is the channel
# cap, not the line cap, and a longer line would only prove the latter.
for batch in range(3):
    c.send("JOIN " + ",".join(f"#f{batch}{i}" for i in range(30)))
    c.read(1.0)
check(
    "joining past CHANLIMIT is refused with 405",
    bool(c.find(" 405 ", lines=c.since(mark))),
    c.since(mark)[-3:],
)

# Twenty targets in one line, well inside the byte limit: what is under test
# is TARGMAX, not the line cap.
mark = c.mark()
c.send("PRIVMSG " + ",".join(f"nb{i}" for i in range(20)) + " :spam")
c.read(1.5)
refusals = len(c.find(" 401 ", lines=c.since(mark)))
check(
    "a twenty-target PRIVMSG is cut off at TARGMAX",
    0 < refusals <= 8,
    f"{refusals} replies",
)

mark = c.mark()
c.send("MODE #alive%s %s" % (RUN, "+b" * 20 + " " + " ".join("m%d!*@*" % i for i in range(20))))
c.read(1.5)
check("a twenty-mode MODE is answered", bool(c.since(mark)), "no reply at all")

mark = c.mark()
c.send("AWAY :" + "z" * 5000)
c.read(1.0)
c.send("PING :awaycheck")
check("an oversized AWAY is truncated, not fatal", bool(c.wait_for("awaycheck", seconds=3)))

mark = c.mark()
c.send("TOPIC #alive%s :%s" % (RUN, "t" * 5000))
c.read(1.0)
c.send("PING :topiccheck")
check("an oversized TOPIC is truncated, not fatal", bool(c.wait_for("topiccheck", seconds=3)))

mark = c.mark()
for batch in range(4):
    c.send("MONITOR + " + ",".join(f"w{batch}{i}" for i in range(50)))
    c.read(0.6)
check(
    "MONITOR past the advertised limit is refused with 734",
    bool(c.find(" 734 ", lines=c.since(mark))),
    c.since(mark)[-3:],
)

mark = c.mark()
c.send("CHATHISTORY LATEST #alive%s * 99999999" % RUN)
c.read(1.5)
c.send("PING :histcheck")
check("an absurd CHATHISTORY limit is clamped", bool(c.wait_for("histcheck", seconds=3)))

for line in [
    "MODE",
    "MODE #",
    "MODE #x +l 99999999999999999999999999",
    "MODE #x +l -1",
    "KICK",
    "TOPIC",
    "WHOWAS x -99999999",
    "NAMES " + "#" * 300,
    "LIST >-1",
    "CHATHISTORY BETWEEN",
    "CHATHISTORY AROUND #x timestamp=not-a-time 5",
    "AUTHENTICATE " + "!" * 900,
    "AUTHENTICATE *",
    "REDACT",
    "SETNAME",
    "TAGMSG",
    "INVITE",
    "WEBPUSH REGISTER not json at all",
    "METADATA * SET " + "k" * 500 + " :v",
]:
    c.send(line)
c.read(1.5)
c.send("PING :garbagecheck")
check(
    "every malformed command is answered rather than fatal",
    bool(c.wait_for("garbagecheck", seconds=4)),
)
c.close()

# ── connections that misbehave ───────────────────────────────────────────────

section("connections that misbehave")


def connect_and_vanish():
    for _ in range(150):
        s = raw(timeout=2)
        s.close()


survives("150 connections opened and dropped at once", connect_and_vanish, f"h8{RUN}")


def half_open_and_silent():
    held = []
    for _ in range(30):
        try:
            held.append(raw(timeout=2))
        except OSError:
            break
    time.sleep(1.0)
    for s in held:
        s.close()


survives("30 connections that register nothing", half_open_and_silent, f"h9{RUN}")


def flood_without_reading():
    """A client that talks and never listens. Its send queue must be dropped,
    not allowed to back up into the dispatch loop."""
    s = raw()
    s.sendall(b"NICK deaf%s\r\nUSER deaf 0 * :deaf\r\n" % RUN.encode())
    time.sleep(0.5)
    s.sendall(b"JOIN #deaf%s\r\n" % RUN.encode())
    time.sleep(0.3)
    try:
        for i in range(20000):
            s.sendall(b"PRIVMSG #deaf%s :%d\r\n" % (RUN.encode(), i))
    except OSError:
        pass
    s.close()


start = time.time()
survives("a client that floods and never reads", flood_without_reading, f"h10{RUN}")
check(
    "the flood did not stall the dispatch loop",
    time.time() - start < 60,
    f"{time.time() - start:.1f}s",
)

# ── unregistered connections ─────────────────────────────────────────────────

section("before registration")


def commands_before_registration():
    s = raw()
    for line in [
        b"PRIVMSG #x :hi",
        b"JOIN #x",
        b"OPER root hunter2",
        b"KILL somebody :because",
        b"WHO *",
        b"LIST",
        b"CHATHISTORY LATEST #x * 50",
        b"CAP REQ :nonexistent-capability",
        b"CAP LS 99999",
        b"CAP",
        b"AUTHENTICATE PLAIN",
        b"AUTHENTICATE " + b"A" * 400,
        b"AUTHENTICATE " + b"A" * 400,
        b"AUTHENTICATE " + b"A" * 400,
    ]:
        s.sendall(line + b"\r\n")
    time.sleep(0.5)
    s.close()


survives("privileged commands before registration", commands_before_registration, f"h11{RUN}")

section("two listeners, two people")
# Connection ids came from a counter per listener, so the first client on each
# port was handed the same one — and everything about a user is keyed by it.
from harness import IRC_PORT2  # noqa: E402

one = Client(f"port1{RUN}")
two = Client(f"port2{RUN}", port=IRC_PORT2)
check("both clients registered", bool(one.find(" 001 ")) and bool(two.find(" 001 ")))

mark = two.mark()
one.send(f"PRIVMSG port2{RUN} :meant for the second one")
two.read(1.5)
check(
    "a message reaches the client it was addressed to",
    bool(two.find("meant for the second one", lines=two.since(mark))),
    two.since(mark)[-3:],
)

mark = one.mark()
two.send(f"PRIVMSG port1{RUN} :and back the other way")
one.read(1.5)
check(
    "and the reply reaches the other",
    bool(one.find("and back the other way", lines=one.since(mark))),
    one.since(mark)[-3:],
)

mark = one.mark()
one.send("WHOIS port2%s" % RUN)
one.read(1.5)
check(
    "each is a user in its own right",
    bool(one.find(" 311 ", f"port2{RUN}", lines=one.since(mark))),
    one.since(mark)[-3:],
)
one.close()
two.close()

section("one message, one line")
# A carriage return or a line feed inside a message would end it early, and
# everything after it would arrive at the reader looking exactly like something
# the server had said. A bare CR survives being read up to the newline, so it
# has to be refused rather than trimmed.
INJ = f"#inj{RUN}"
victim = Client(f"vic{RUN}")
victim.join(INJ)
attacker = Client(f"att{RUN}")
attacker.join(INJ)
victim.read(0.5)

for label, payload in [
    ("a bare carriage return", f"PRIVMSG {INJ} :hi\r:evil!e@e PRIVMSG {INJ} :FORGED-CR\r\n"),
    ("a NUL", f"PRIVMSG {INJ} :hi\x00:evil!e@e PRIVMSG {INJ} :FORGED-NUL\r\n"),
]:
    mark = victim.mark()
    attacker.sock.sendall(payload.encode())
    time.sleep(0.5)
    victim.read(1.0)
    seen = victim.since(mark)
    check(f"{label} does not smuggle a second message", not [l for l in seen if "FORGED" in l], seen)

# Refusing the line must not cost the client its connection.
mark = victim.mark()
attacker.send(f"PRIVMSG {INJ} :still here")
victim.read(1.5)
check(
    "the connection survives a message that was refused",
    bool(victim.find("still here", lines=victim.since(mark))),
    victim.since(mark)[-3:],
)
victim.close()
attacker.close()

section("a table a client can put things in")
# `STATS m` counts commands by name, and the name is whatever word the client
# sent. Nothing removes one, so an unknown command left alone is a string this
# server holds until it stops — and the client can disconnect and come back to
# send more names.
OPER_NAME = os.environ.get("SMOKE_OPER_NAME", "smokeoper")


def counted_commands(nick):
    c = Client(nick)
    c.send(f"OPER {OPER_NAME} {OPER_PASSWORD}")
    c.wait_for(" 381 ", " 464 ", seconds=5)
    mark = c.mark()
    c.send("STATS m")
    c.wait_for(" 219 ", seconds=8)
    n = len([l for l in c.since(mark) if " 212 " in l])
    c.close()
    return n


before_counted = counted_commands(f"h15{RUN}")
offered = 0
for round_ in range(30):
    try:
        junk = socket.create_connection((IRC_HOST, IRC_PORT), timeout=5)
        junk.sendall(f"NICK j{round_}{RUN}\r\nUSER j 0 * :j\r\n".encode())
        junk.sendall("".join(f"ZQ{offered + i:08d}\r\n" for i in range(8)).encode())
        offered += 8
        time.sleep(0.03)
        junk.close()
    except OSError:
        break
time.sleep(0.5)
after_counted = counted_commands(f"h16{RUN}")
check(
    f"{offered} invented command names do not each become an entry",
    after_counted - before_counted <= 2,
    f"{before_counted} -> {after_counted} entries in STATS m",
)

section("a peer that never finishes its line")
# Reading up to the newline means a peer that never sends one decides how much
# memory this server spends on it. The bytes cost the sender a socket; they
# must not cost the server anything it keeps.
PIDFILE = os.environ.get("SMOKE_RIRCD_PID", "")


def server_rss_kb():
    if not PIDFILE or not os.path.exists(PIDFILE):
        return None
    try:
        pid = int(open(PIDFILE).read().strip())
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


before = server_rss_kb()
if before is None:
    check("the server's memory could be measured", False, PIDFILE)
else:
    hogs = [socket.create_connection((IRC_HOST, IRC_PORT), timeout=5) for _ in range(4)]
    chunk = b"x" * 65536
    sent = 0
    deadline = time.time() + 6
    try:
        while time.time() < deadline:
            for h in hogs:
                h.sendall(chunk)
                sent += len(chunk)
    except OSError:
        pass
    time.sleep(0.5)
    after = server_rss_kb() or before
    for h in hogs:
        h.close()
    grew = (after - before) / 1024.0
    check(
        f"{sent // 1000000} MB with no newline does not grow the server",
        grew < 32,
        f"RSS {before} kB -> {after} kB ({grew:.1f} MiB)",
    )
    check("and it is still serving afterwards", still_alive("the flood", f"h14{RUN}"))

section("credentials offered as fast as they can be typed")
# Checking a password is deliberately slow, and every client's commands go
# through one dispatch loop. A connection that offers credentials back to back
# must not decide when everybody else gets served — and AUTHENTICATE is exempt
# from flood control, because a long SASL response arrives in several lines.
import base64  # noqa: E402  (only this section needs it)


def round_trip_ms(nick):
    """How long the server takes to answer a client that is doing nothing odd."""
    c = Client(nick)
    worst = 0.0
    for i in range(6):
        started = time.time()
        c.send(f"PING :beat{i}")
        if not c.wait_for(f"beat{i}", seconds=20):
            c.close()
            return None
        worst = max(worst, (time.time() - started) * 1000)
        time.sleep(0.05)
    c.close()
    return worst


quiet = round_trip_ms(f"h17{RUN}")
flooders = []
payload = base64.b64encode(b"\0nosuchaccount\0wrongpassword").decode()
try:
    for i in range(2):
        f = raw(timeout=10)
        f.sendall(f"CAP LS 302\r\nNICK sf{i}{RUN}\r\nUSER s 0 * :s\r\n".encode())
        flooders.append(f)
    time.sleep(0.5)
    stop = time.time() + 8
    while time.time() < stop:
        for f in flooders:
            try:
                f.sendall(f"AUTHENTICATE PLAIN\r\nAUTHENTICATE {payload}\r\n".encode() * 4)
                f.setblocking(False)
                try:
                    f.recv(1 << 20)
                except (BlockingIOError, OSError):
                    pass
                f.setblocking(True)
            except OSError:
                pass
        under = round_trip_ms(f"h18{RUN}")
        break
finally:
    for f in flooders:
        try:
            f.close()
        except OSError:
            pass

if quiet is None or under is None:
    check("a client can still be served during a flood of logins", False,
          f"quiet={quiet} under flood={under}")
else:
    check(
        "credentials offered as fast as possible do not stall everyone else",
        under < 1000,
        f"slowest answer {quiet:.1f} ms quiet, {under:.1f} ms under the flood",
    )
check("and it is still serving afterwards", still_alive("a flood of logins", f"h19{RUN}"))

section("a client renaming itself as fast as it can")
# A nick change is cheap to send and expensive to deliver: every member of
# every channel the client is in hears about it, and so does every other
# server. NICK is part of registration, so it used to be exempt from flood
# control for the whole life of the connection.
watchers = []
flood_channel = f"#rename{RUN}"
try:
    for i in range(8):
        w = Client(f"h20{i}{RUN}")
        w.join(flood_channel)
        watchers.append(w)
    renamer = Client(f"h21{RUN}")
    renamer.join(flood_channel)
    quiet_rename = round_trip_ms(f"h22{RUN}")

    renamer.sock.setblocking(False)
    stop_at = time.time() + 5
    lines = 0
    while time.time() < stop_at:
        try:
            renamer.sock.sendall(
                b"".join(f"NICK r{(lines + n) % 9000:04d}{RUN[:2]}\r\n".encode() for n in range(50))
            )
            lines += 50
        except (BlockingIOError, OSError):
            time.sleep(0.005)
        for w in watchers:
            w.sock.setblocking(False)
            try:
                w.sock.recv(1 << 20)
            except (BlockingIOError, OSError):
                pass
            w.sock.setblocking(True)
    under_rename = round_trip_ms(f"h23{RUN}")
finally:
    for w in watchers:
        try:
            w.close()
        except OSError:
            pass

if quiet_rename is None or under_rename is None:
    check("a client can still be served during a rename flood", False,
          f"quiet={quiet_rename} under flood={under_rename}")
else:
    check(
        f"{lines} nick changes do not stall everyone else",
        under_rename < 1000,
        f"slowest answer {quiet_rename:.1f} ms quiet, {under_rename:.1f} ms under the flood",
    )
check("and it is still serving afterwards", still_alive("a rename flood", f"h24{RUN}"))

section("still standing")
check("the server is still accepting and serving clients", still_alive("everything", f"h12{RUN}"))

summary("hostile")
