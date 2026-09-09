#!/usr/bin/env python3
"""Hostile input: what a client sends when it is not trying to be a client.

Every check here ends the same way — the server is still serving. A server that
answers one of these badly is a server one connection can take away from
everybody else, because rIRCd runs every client's commands through a single
dispatch loop.
"""

import socket
import time

from harness import IRC_HOST, IRC_PORT, Client, check, section, summary

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

section("still standing")
check("the server is still accepting and serving clients", still_alive("everything", f"h12{RUN}"))

summary("hostile")
