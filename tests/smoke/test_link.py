#!/usr/bin/env python3
"""Two servers, linked: what each one knows about the other.

Run through tests/smoke/run-link.sh, which brings up both servers with their own
databases and links them.
"""

import os
import socket
import time

from harness import Client, check, section, summary

HOST = os.environ.get("SMOKE_IRC_HOST", "127.0.0.1")
A_PORT = int(os.environ.get("LINK_A_PORT", "16687"))
B_PORT = int(os.environ.get("LINK_B_PORT", "16697"))
A_NAME = os.environ.get("LINK_A_NAME", "a.link.test")
B_NAME = os.environ.get("LINK_B_NAME", "b.link.test")
LINK_DIR = os.environ.get("LINK_DIR", "")
RUN = format(int(time.time()) % 100000, "05d")


def log(side):
    path = os.path.join(LINK_DIR, f"{side}.log")
    try:
        return open(path).read()
    except OSError:
        return ""


section("the link came up")
a_log, b_log = log("a"), log("b")
check("server A reports a link", "Linked" in a_log, a_log[-400:])
check("server B reports a link", "Linked" in b_log, b_log[-400:])
check("neither refused the other", "Refusing link" not in a_log + b_log,
      [l for l in (a_log + b_log).splitlines() if "Refusing link" in l][:3])

section("each server names the other in LINKS")
a = Client(f"la{RUN}", port=A_PORT)
b = Client(f"lb{RUN}", port=B_PORT)

mark = a.mark()
a.send("LINKS")
a.wait_for(" 365 ", seconds=5)
a_links = " ".join(a.find(" 364 ", lines=a.since(mark)))
check(f"A lists itself ({A_NAME})", A_NAME in a_links, a_links)
check(f"A lists B ({B_NAME})", B_NAME in a_links, a_links)

mark = b.mark()
b.send("LINKS")
b.wait_for(" 365 ", seconds=5)
b_links = " ".join(b.find(" 364 ", lines=b.since(mark)))
check(f"B lists itself ({B_NAME})", B_NAME in b_links, b_links)
check(f"B lists A ({A_NAME})", A_NAME in b_links, b_links)

section("each server is its own")
check("A welcomed its client", bool(a.find(" 001 ")), a.lines[:3])
check("B welcomed its client", bool(b.find(" 001 ")), b.lines[:3])
check("the two servers have different names", A_NAME != B_NAME)

section("the link port is not a client port")
# A client that reaches the link port must get nothing out of it: the two speak
# different protocols and answer to different secrets.
link_port = int(os.environ.get("LINK_B_LINK_PORT", "17010"))
s = socket.create_connection((HOST, link_port), timeout=5)
s.sendall(b"NICK intruder\r\nUSER intruder 0 * :intruder\r\n")
s.settimeout(3)
got = b""
try:
    while b"\r\n" not in got:
        chunk = s.recv(4096)
        if not chunk:
            break
        got += chunk
except (socket.timeout, OSError):
    pass
s.close()
text = got.decode("utf-8", "replace")
check("a client on the link port is not registered", " 001 " not in text, text[:200])
if os.environ.get("LINK_TLS") == "1":
    # A TLS link port answers something that is not IRC at all: a TLS alert,
    # whose first byte is the record type 0x15. Anything readable would mean
    # the port had spoken IRC to a stranger before asking who it was.
    check("it is answered in TLS, not in IRC",
          got == b"" or got[:1] == b"\x15", repr(got[:32]))
else:
    check("it is told why, or simply dropped",
          text == "" or "ERROR" in text, text[:200])

section("users are shared across the link")
# A user on A must be a user on B: the burst carries everyone who was already
# there, and everyone who arrives afterwards is announced.
burst_nick = f"burst{RUN}"
late_nick = f"late{RUN}"
alice = Client(burst_nick, port=A_PORT)


def whois(client, nick, seconds=5):
    mark = client.mark()
    client.send(f"WHOIS {nick}")
    client.wait_for(" 318 ", " 401 ", seconds=seconds)
    return client.since(mark)


def eventually(fn, seconds=8):
    """Retry until it returns something. For anything that asks the server."""
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(0.3)
    return last


def arrives(client, needle, mark, seconds=8):
    """Wait for a line to turn up unprompted — a message from somebody else.

    Nothing here asks the server a question, so there is no reply to wait for:
    the socket has to be read until the line shows up or the time is gone.
    """
    deadline = time.time() + seconds
    while time.time() < deadline:
        client.read(0.5)
        hits = [l for l in client.since(mark) if needle in l]
        if hits:
            return hits
    return []


found = eventually(lambda: [l for l in whois(b, burst_nick) if " 311 " in l])
check(f"B knows {burst_nick}, who registered on A", bool(found), found)

answer = whois(b, burst_nick)
server_line = [l for l in answer if " 312 " in l]
check("B says which server they are on", any(A_NAME in l for l in server_line), server_line)
# How long somebody has been quiet is known to the server they type at, so B
# has to ask A and wait. A number invented here would look exactly like a real
# one, so the answer either comes from A or is left out.
idle = [l for l in answer if " 317 " in l]
check("B asks A how long they have been quiet, and says so", bool(idle), answer[-4:])
if idle:
    fields = idle[0].split()
    seconds = fields[4] if len(fields) > 4 else ""
    signon = fields[5] if len(fields) > 5 else ""
    check("the idle time is a number of seconds", seconds.isdigit(), idle[0])
    check("and it is a plausible one", seconds.isdigit() and int(seconds) < 3600, idle[0])
    check("the signon time is a timestamp", signon.isdigit() and int(signon) > 1_600_000_000,
          idle[0])
# The line that ends the list must still come last, and exactly once, however
# long the answer took to arrive.
ends = [l for l in answer if " 318 " in l]
check("and the list still ends, once", len(ends) == 1, ends)

# A user who is not anywhere gets no idle line and no waiting: the reply ends
# straight away rather than hanging until the question times out.
import time as _time  # noqa: E402
started = _time.time()
missing = whois(b, f"nobody{RUN}")
check("a WHOIS for nobody ends without waiting for an answer",
      _time.time() - started < 2.5, f"{_time.time() - started:.1f}s")
check("and says there is no such nick", bool([l for l in missing if " 401 " in l]), missing[-3:])

late = Client(late_nick, port=A_PORT)
found = eventually(lambda: [l for l in whois(b, late_nick) if " 311 " in l])
check(f"B learns about {late_nick}, who arrived after the link", bool(found), found)

check("A does not know a nick nobody took",
      not [l for l in whois(a, f"ghost{RUN}") if " 311 " in l])

section("LUSERS counts the whole network")
mark = b.mark()
b.send("LUSERS")
b.wait_for(" 266 ", seconds=5)
lusers = b.since(mark)
check("B reports two servers", any(" 2 servers" in l for l in lusers if " 251 " in l),
      [l for l in lusers if " 251 " in l])
global_line = [l for l in lusers if " 266 " in l]
local_line = [l for l in lusers if " 265 " in l]
check("global users outnumber local ones",
      bool(global_line) and bool(local_line), global_line + local_line)

section("messages cross the link")
mark = alice.mark()
b.send(f"PRIVMSG {burst_nick} :hello from the other side")
got = arrives(alice, "hello from the other side", mark)
check("a message from B reaches a user on A", bool(got), got)
check("it comes from the sender, not from a server",
      bool(got) and got[0].startswith(f":lb{RUN}!"), got)
check("it is addressed to the name the recipient answers to",
      bool(got) and f"PRIVMSG {burst_nick} " in got[0], got)

mark = b.mark()
alice.send(f"PRIVMSG lb{RUN} :and back again")
got = arrives(b, "and back again", mark)
check("a message from A reaches a user on B", bool(got), got)

section("a nick change is seen on both sides")
renamed = f"moved{RUN}"
alice.send(f"NICK {renamed}")
alice.wait_for(" NICK ", seconds=5)
found = eventually(lambda: [l for l in whois(b, renamed) if " 311 " in l])
check(f"B knows the new nick {renamed}", bool(found), found)
gone = eventually(lambda: [l for l in whois(b, burst_nick) if " 401 " in l])
check("B has let the old nick go", bool(gone), gone)

section("a quit is seen on both sides")
late.send("QUIT :done")
late.close()
gone = eventually(lambda: [l for l in whois(b, late_nick) if " 401 " in l])
check(f"B saw {late_nick} leave", bool(gone), gone)

section("a channel is one channel on both servers")
CHAN = f"#link{RUN}"
alice.send(f"JOIN {CHAN}")
alice.wait_for(" 366 ", seconds=5)

mark_a = alice.mark()
mark = b.mark()
b.send(f"JOIN {CHAN}")
b.wait_for(" 366 ", seconds=5)
names = " ".join(b.find(" 353 ", lines=b.since(mark)))
check(f"B sees the user from A in {CHAN}", renamed in names, names)

got = arrives(alice, f"JOIN {CHAN}", mark_a)
check("A was told when the user on B joined",
      bool(got) and got[0].startswith(f":lb{RUN}!"), got)

mark = alice.mark()
b.send(f"PRIVMSG {CHAN} :hello the channel")
got = arrives(alice, "hello the channel", mark)
check("a channel message from B reaches the channel on A", bool(got), got)
check("it comes from the person who sent it",
      bool(got) and got[0].startswith(f":lb{RUN}!"), got)

mark = b.mark()
alice.send(f"PRIVMSG {CHAN} :and the other way")
got = arrives(b, "and the other way", mark)
check("a channel message from A reaches the channel on B", bool(got), got)

section("channel state crosses too")
# The channel was made on A, so its user holds the op there and the topic is
# theirs to set.
mark = b.mark()
alice.send(f"TOPIC {CHAN} :shared topic")
got = arrives(b, "shared topic", mark)
check("a topic set on A is seen on B", bool(got), got)

mark = b.mark()
alice.send(f"MODE {CHAN} +m")
got = arrives(b, f"MODE {CHAN} +m", mark)
check("a channel mode set on A is seen on B", bool(got), got)

mark = b.mark()
alice.send(f"MODE {CHAN} +v lb{RUN}")
got = arrives(b, f"+v", mark)
check("voice given on A reaches the user on B",
      bool(got) and f"lb{RUN}" in got[0], got)

# +m is set and the user on B now has voice, so they may still speak.
mark = alice.mark()
b.send(f"PRIVMSG {CHAN} :voiced and moderated")
got = arrives(alice, "voiced and moderated", mark)
check("a voiced user on B can speak in a moderated channel on A", bool(got), got)

mark = b.mark()
alice.send(f"MODE {CHAN} -m")
arrives(b, f"MODE {CHAN} -m", mark)

section("what a user is, not just what they say")
# A client on B that asked to hear about the people it shares a channel with.
watcher = Client(f"w{RUN}", caps=["setname", "chghost", "account-notify",
                                  "invite-notify", "message-tags"], port=B_PORT)
watcher.join(CHAN)
mark = watcher.mark()
alice.send("SETNAME :a whole new name")
got = arrives(watcher, "SETNAME", mark)
check("a name change on A reaches the channel on B",
      bool(got) and "a whole new name" in got[0], got)

alone = Client(f"solo{RUN}", port=B_PORT)
mark = alone.mark()
alice.send(f"INVITE solo{RUN} {CHAN}")
got = arrives(alone, "INVITE", mark)
check("an invitation from A reaches a user on B",
      bool(got) and CHAN.lower() in got[0].lower(), got)

# The invitation has to be on the channel there too, or an invite-only door
# would still be shut to the person who was asked through it.
mark = b.mark()
alice.send(f"MODE {CHAN} +i")
arrives(b, "+i", mark)
mark = alone.mark()
alone.send(f"JOIN {CHAN}")
got = arrives(alone, f"JOIN {CHAN}", mark)
check("and lets them in through an invite-only door", bool(got), alone.since(mark)[-3:])
alone.send(f"PART {CHAN}")
mark = b.mark()
alice.send(f"MODE {CHAN} -i")
arrives(b, "-i", mark)
# METADATA on a user is visible to the people who share a channel with them.
meta = Client(f"m{RUN}", caps=["draft/metadata-2", "message-tags"], port=B_PORT)
meta.join(CHAN)
meta.send("METADATA * SUB display-name")
meta.read(1.0)
mark = meta.mark()
alice.send("METADATA * SET display-name :Alice Across")
got = arrives(meta, "METADATA", mark)
check("a key set on A reaches a subscriber on B",
      bool(got) and "Alice Across" in got[0], got)

# A rename on A moves the keys on B too: they describe the person, and the name
# they let go belongs to whoever asks for it next.
alice_renamed = f"ar{RUN}"
alice.send(f"NICK {alice_renamed}")
meta.read(1.5)
mark = meta.mark()
meta.send(f"METADATA {alice_renamed} GET display-name")
meta.read(1.5)
check("metadata follows a rename across the link",
      bool(meta.find("Alice Across", lines=meta.since(mark))), meta.since(mark))
mark = meta.mark()
meta.send(f"METADATA {renamed} GET display-name")
meta.read(1.5)
check("and does not stay on the name that was let go",
      not meta.find("Alice Across", lines=meta.since(mark)), meta.since(mark))
# Put the name back: the rest of this file addresses her by it.
alice.send(f"NICK {renamed}")
meta.read(1.0)
alice.read(1.0)
meta.close()

watcher.close()
alone.close()

section("a channel a user leaves")
mark = alice.mark()
b.send(f"PART {CHAN} :going")
got = arrives(alice, f"PART {CHAN}", mark)
check("a part on B is seen on A", bool(got), got)

mark = alice.mark()
b.send(f"JOIN {CHAN}")
arrives(alice, f"JOIN {CHAN}", mark)
alice.send(f"KICK {CHAN} lb{RUN} :out you go")
got = arrives(b, f"KICK {CHAN}", mark, seconds=6)
check("a kick from A removes the user on B", bool(got), got)

section("a rehash does not take the link down")
# REHASH replaces the whole configuration. The servers already attached are not
# re-linked by it, so what the running server knows about them has to survive —
# otherwise the link would still be up with nothing able to reach it.
oper = Client(f"op{RUN}", port=A_PORT)
oper.send(f"OPER linkoper {os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
oper.wait_for(" 381 ", " 464 ", seconds=5)
check("the operator logged in", bool(oper.find(" 381 ")), oper.lines[-3:])
mark = oper.mark()
oper.send("REHASH")
oper.wait_for(" 382 ", seconds=5)

mark = a.mark()
a.send("LINKS")
a.wait_for(" 365 ", seconds=5)
rehashed = " ".join(a.find(" 364 ", lines=a.since(mark)))
check("A still lists B after a rehash", B_NAME in rehashed, rehashed)

mark = alice.mark()
b.send(f"PRIVMSG {renamed} :still talking after the rehash")
got = arrives(alice, "still talking after the rehash", mark)
check("messages still cross the link after a rehash", bool(got), got)
oper.close()

section("a split is noticed")
# Stop B and watch A report the split rather than carrying on as if nothing
# happened.
pid_path = os.path.join(LINK_DIR, "b.pid")
if os.path.exists(pid_path):
    os.kill(int(open(pid_path).read().strip()), 15)
    deadline = time.time() + 15
    saw_split = False
    while time.time() < deadline:
        if "Netsplit" in log("a"):
            saw_split = True
            break
        time.sleep(0.5)
    check("A noticed B going away", saw_split, log("a")[-400:])

    mark = a.mark()
    a.send("LINKS")
    a.wait_for(" 365 ", seconds=5)
    after = " ".join(a.find(" 364 ", lines=a.since(mark)))
    check("A no longer lists B", B_NAME not in after, after)
    check("A still lists itself", A_NAME in after, after)
    check("A is still serving", bool(Client(f"after{RUN}", port=A_PORT).find(" 001 ")))

    gone = eventually(lambda: [l for l in whois(a, f"lb{RUN}") if " 401 " in l])
    check("the users behind the split are gone from A", bool(gone), gone)

    mark = a.mark()
    a.send(f"NAMES {CHAN}")
    a.wait_for(" 366 ", seconds=5)
    left = " ".join(a.find(" 353 ", lines=a.since(mark)))
    check("and out of the channels they were in", f"lb{RUN}" not in left, left)
else:
    check("server B's pid file was written", False, pid_path)

a.close()
summary("link")
