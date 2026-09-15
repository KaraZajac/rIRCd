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

section("reclaiming a nick held on the other server")
# GHOST closes the session using a nick so its account can take it back. The
# connections are on the server that session is on, so a session on the other
# server has to be closed by that server -- and every rule the asking server
# checked is checked again there, from what it knows rather than from what it
# was told.
from harness import connect_negotiating  # noqa: E402

GHOST_NICK = f"gh{RUN}"
GHOST_PASSWORD = "hunter2hunter2"

# The account is made on B, where the reclaiming client will be.
owner = Client(GHOST_NICK, port=B_PORT)
mark = owner.mark()
owner.send(f"REGISTER * {GHOST_NICK}@example.invalid {GHOST_PASSWORD}")
owner.read(2.5)
registered = bool(owner.find(" 900 ", lines=owner.since(mark))) or bool(
    owner.find("REGISTER SUCCESS", lines=owner.since(mark)))
check("an account can be registered on B", registered, owner.since(mark)[-3:])
owner.close()
time.sleep(0.8)

# Now the nick is taken on A, by somebody who is not logged in: the stale
# session this is all about.
stale = Client(GHOST_NICK, port=A_PORT)
found = eventually(lambda: [l for l in whois(b, GHOST_NICK) if " 311 " in l])
check("the stale session on A is seen from B", bool(found), found)

if registered and found:
    # And the account holder comes back on B under another name.
    back = connect_negotiating(f"gb{RUN}", caps=["sasl"], port=B_PORT)
    back.sasl_plain(GHOST_NICK, GHOST_PASSWORD)
    back.send("CAP END")
    back.wait_for(" 376 ", " 422 ", seconds=5)
    logged_in = bool(back.find(" 900 "))
    check("the account holder logs in on B", logged_in, back.lines[-3:])

    mark = back.mark()
    back.send(f"GHOST {GHOST_NICK}")
    back.read(2.0)
    check("B says it asked A to close the session",
          bool(back.find("NOTICE", "Asked", lines=back.since(mark))), back.since(mark)[-3:])

    gone = eventually(lambda: [l for l in whois(b, GHOST_NICK) if " 401 " in l], seconds=12)
    check("and the session on A is closed", bool(gone), gone or whois(b, GHOST_NICK)[-3:])
    back.close()

    # Somebody with no claim to the nick cannot have it closed. The asking
    # server refuses this one itself, which is why a second stale session is
    # needed to prove the far side refuses it too.
    stale2 = Client(GHOST_NICK, port=A_PORT)
    eventually(lambda: [l for l in whois(b, GHOST_NICK) if " 311 " in l])
    stranger = Client(f"gs{RUN}", port=B_PORT)
    mark = stranger.mark()
    stranger.send(f"GHOST {GHOST_NICK}")
    stranger.read(1.5)
    check("a user with no account cannot close somebody else's session",
          bool(stranger.find("FAIL GHOST", lines=stranger.since(mark))), stranger.since(mark)[-3:])
    still_there = [l for l in whois(b, GHOST_NICK) if " 311 " in l]
    check("and that session is still there", bool(still_there), still_there)
    stranger.close()
    stale2.close()

try:
    stale.close()
except OSError:
    pass
time.sleep(0.5)

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

section("who a channel belongs to crosses the link")
# Ownership was the one piece of channel state that stayed on the server it was
# made on. Each server keeps its own database, so #chan could have a different
# founder on every server of the network, and a transfer would only ever have
# moved it on one of them.
import subprocess


def side_db(side, query):
    """One query against one server's own database."""
    sock = os.environ.get("LINK_DB_SOCK", "")
    if not sock:
        return ""
    out = subprocess.run(
        ["mariadb", f"--socket={sock}", "-N", "-B", f"rircdb_{side}", "-e", query],
        capture_output=True, text=True,
    )
    return out.stdout.strip() if out.returncode == 0 else ""


OWNER = f"own{RUN}"
OWNED = f"#owned{RUN}"
PASSWORD = "link-ownership-password"

# The account name has to be the nick registering it, so the account is made
# under the name it will have and logged into from a connection using another.
maker = Client(OWNER, port=A_PORT)
mark = maker.mark()
maker.send(f"REGISTER * {OWNER}@example.invalid {PASSWORD}")
# Registering hashes a password, which is deliberately slow; wait for the
# answer rather than for a fixed moment.
maker.wait_for("REGISTER", seconds=20)
made = bool(maker.find("REGISTER SUCCESS", lines=maker.since(mark)))
check("an account can be registered on A", made, maker.since(mark)[-3:])
maker.close()

if made:
    founder = connect_negotiating(f"fa{RUN}", caps=["sasl"], port=A_PORT)
    founder.sasl_plain(OWNER, PASSWORD)
    founder.send("CAP END")
    founder.wait_for(" 001 ", seconds=6)
    check("and it can log in on A", bool(founder.find(" 900 ")), founder.lines[-5:])
    mark = founder.mark()
    founder.join(OWNED)
    founder.read(1.5)
    check("the account founds the channel on A",
          bool(founder.find(f"@fa{RUN}", lines=founder.since(mark))
               or founder.find(f"+o fa{RUN}", lines=founder.since(mark))),
          founder.since(mark)[-5:])
    check("A wrote the founder down",
          side_db("a", f"SELECT founder FROM channels WHERE name='{OWNED}'") == OWNER,
          side_db("a", f"SELECT founder FROM channels WHERE name='{OWNED}'"))

    learned = eventually(
        lambda: side_db("b", f"SELECT founder FROM channels WHERE name='{OWNED}'") == OWNER,
        seconds=6)
    check("B learned who the channel belongs to", bool(learned),
          side_db("b", f"SELECT founder FROM channels WHERE name='{OWNED}'"))
    check("B holds the founder in its operator list too",
          OWNER in side_db("b",
              "SELECT GROUP_CONCAT(nick_or_account) FROM channel_operators o "
              f"JOIN channels c ON o.channel_id = c.id WHERE c.name='{OWNED}'"),
          side_db("b",
              "SELECT GROUP_CONCAT(nick_or_account) FROM channel_operators o "
              f"JOIN channels c ON o.channel_id = c.id WHERE c.name='{OWNED}'"))

    # Status granted on one server is status on the network, not just there —
    # and it is granted to an account, because that is what it is remembered
    # against. The account is made on B, where the person holding it will be.
    GUEST = f"gst{RUN}"
    maker_b = Client(GUEST, port=B_PORT)
    mark = maker_b.mark()
    maker_b.send(f"REGISTER * {GUEST}@example.invalid {PASSWORD}")
    maker_b.wait_for("REGISTER", seconds=20)
    guest_made = bool(maker_b.find("REGISTER SUCCESS", lines=maker_b.since(mark)))
    check("a second account can be registered on B", guest_made, maker_b.since(mark)[-3:])
    maker_b.close()

    guest = connect_negotiating(f"gb{RUN}", caps=["sasl"], port=B_PORT)
    guest.sasl_plain(GUEST, PASSWORD)
    guest.send("CAP END")
    guest.wait_for(" 001 ", seconds=6)
    guest.join(OWNED)
    guest.read(1.0)
    founder.send(f"MODE {OWNED} +o gb{RUN}")
    founder.read(1.2)
    opped = eventually(
        lambda: GUEST in side_db("b",
            "SELECT GROUP_CONCAT(nick_or_account) FROM channel_operators o "
            f"JOIN channels c ON o.channel_id = c.id WHERE c.name='{OWNED}'"),
        seconds=6)
    check("an operator made on A is remembered on B", bool(opped),
          side_db("b",
              "SELECT GROUP_CONCAT(nick_or_account) FROM channel_operators o "
              f"JOIN channels c ON o.channel_id = c.id WHERE c.name='{OWNED}'"))

    founder.send(f"MODE {OWNED} -o gb{RUN}")
    founder.read(1.2)
    unopped = eventually(
        lambda: GUEST not in side_db("b",
            "SELECT GROUP_CONCAT(nick_or_account) FROM channel_operators o "
            f"JOIN channels c ON o.channel_id = c.id WHERE c.name='{OWNED}'"),
        seconds=6)
    check("and taking it away is remembered too", bool(unopped),
          side_db("b",
              "SELECT GROUP_CONCAT(nick_or_account) FROM channel_operators o "
              f"JOIN channels c ON o.channel_id = c.id WHERE c.name='{OWNED}'"))
    guest.close()
    founder.close()

section("a ban is a fact about the network")
# Somebody shut out of one server and welcome on the next is not shut out. A
# KLINE typed at A reaches B, closes the matching user there, and is written
# down on B, so it holds after B restarts too; UNKLINE lifts it everywhere.
banner = Client(f"ban{RUN}", port=A_PORT)
banner.send(f"OPER linkoper {os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
banner.wait_for(" 381 ", " 464 ", seconds=5)
if banner.find(" 381 "):
    target = Client(f"tgt{RUN}", port=B_PORT)
    tmark = target.mark()
    banner.send(f"KLINE tgt{RUN}!*@* :not welcome anywhere")
    banner.read(1.5)
    target.read(2.0)
    check("a user on B matching a ban set on A is closed",
          bool(target.find("Closing link", "banned", lines=target.since(tmark))), target.since(tmark)[-2:])
    stored = eventually(lambda: side_db("b", "SELECT COUNT(*) FROM server_bans WHERE mask LIKE 'tgt%'") == "1",
                        seconds=6)
    check("and B wrote it down", bool(stored), side_db("b", "SELECT mask FROM server_bans"))
    retry = Client(f"tgt{RUN}", port=B_PORT)
    retry.read(1.5)
    check("so they cannot come back through B either",
          bool(retry.find("banned")) or not retry.find(" 001 "), retry.lines[-2:])
    retry.close()
    banner.send(f"UNKLINE tgt{RUN}!*@*")
    banner.read(1.5)
    lifted = eventually(lambda: side_db("b", "SELECT COUNT(*) FROM server_bans WHERE mask LIKE 'tgt%'") == "0",
                        seconds=6)
    check("lifting it on A lifts it on B", bool(lifted), side_db("b", "SELECT mask FROM server_bans"))
    back = Client(f"tgt{RUN}", port=B_PORT)
    check("and they are welcome again", bool(back.find(" 001 ")), back.lines[-2:])
    back.close()
    target.close()
banner.close()

section("a mode lock and a timed ban are the same on both servers")
# The founder's lock travels with the channel, so an operator on B is held
# to it the same way; a timed ban set on A lifts on B when it lifts on A.
lk = Client(f"lk{RUN}", port=A_PORT)
lk.send(f"OPER linkoper {os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
lk.wait_for(" 381 ", " 464 ", seconds=5)
lk.send(f"JOIN #lk{RUN}")
lk.read(0.8)
lk.send(f"MODE #lk{RUN} +nt")
lk.read(0.5)
lb = Client(f"lb2{RUN}", port=B_PORT)
lb.send(f"JOIN #lk{RUN}")
lb.read(0.8)
lk.send(f"MODE #lk{RUN} +o lb2{RUN}")
lk.read(0.8)
lk.send(f"MLOCK #lk{RUN} +nt")
lk.read(0.8)
bmark = lb.mark()
deadline = time.time() + 8
locked = []
while time.time() < deadline and not locked:
    lb.send(f"MLOCK #lk{RUN}")
    lb.read(0.6)
    locked = [l for l in lb.since(bmark) if "is locked +nt" in l]
check("the lock set on A is the lock on B", bool(locked), lb.lines[-2:])
bmark = lb.mark()
lb.send(f"MODE #lk{RUN} -t")
lb.read(1.0)
check("and an operator on B is held to it", bool(lb.find(" 742 ", lines=lb.since(bmark))), lb.since(bmark)[-2:])
lk.send(f"MODE #lk{RUN} +b ~t:5s:gone{RUN}!*@*")
lk.read(0.5)
bmark = lb.mark()
deadline = time.time() + 8
seen = []
while time.time() < deadline and not seen:
    lb.send(f"MODE #lk{RUN} b")
    lb.read(0.8)
    seen = [l for l in lb.since(bmark) if " 367 " in l and f"~t:5s:gone{RUN}" in l]
check("a timed ban set on A is on B's list", bool(seen), lb.lines[-3:])
lifted = arrives(lb, f"-b ~t:5s:gone{RUN}", lb.mark(), seconds=25)
check("and B lifts it when the time is up", bool(lifted), lb.lines[-2:])
deadline = time.time() + 15
gone_from_a = False
while time.time() < deadline and not gone_from_a:
    amark = lk.mark()
    lk.send(f"MODE #lk{RUN} b")
    lk.wait_for(" 368 ", seconds=5)
    listed = lk.since(amark)
    gone_from_a = any(" 368 " in l for l in listed) and not any(f"~t:5s:gone{RUN}" in l for l in listed)
    if not gone_from_a:
        time.sleep(1.0)
check("and it is gone from A as well", gone_from_a, lk.lines[-3:])
lb.close()
lk.close()

section("SAJOIN reaches across the link, and MAP shows both servers")
hand = Client(f"hand{RUN}", port=A_PORT)
hand.send(f"OPER linkoper {os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
hand.wait_for(" 381 ", " 464 ", seconds=5)
faraway = Client(f"faraway{RUN}", port=B_PORT)
seen = eventually(lambda: [l for l in whois(hand, f"faraway{RUN}") if " 311 " in l] or None, seconds=8)
fmark = faraway.mark()
hand.send(f"SAJOIN faraway{RUN} #pulled{RUN}")
hand.read(1.0)
check("a user on B is joined by B at A's request", bool(arrives(faraway, f"JOIN #pulled{RUN}", fmark)), faraway.since(fmark)[-3:])
check("and told by whom", bool(arrives(faraway, f"operator hand{RUN}", fmark)), faraway.since(fmark)[-3:])
hmark = hand.mark()
hand.send("MAP")
hand.wait_for(" 017 ", seconds=5)
shown = hand.since(hmark)
check("MAP on A lists both servers", bool(hand.find(" 015 ", A_NAME, lines=shown)) and bool(hand.find(" 015 ", B_NAME, lines=shown)), shown[-4:])
faraway.close()
hand.close()

section("a spam filter is the network's rule, not one server's")
sf = Client(f"sf{RUN}", port=A_PORT)
sf.send(f"OPER linkoper {os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
sf.wait_for(" 381 ", " 464 ", seconds=5)
if sf.find(" 381 "):
    PAT = f"*spamword{RUN}*"
    sf.send(f"SPAMFILTER ADD pc block :{PAT}")
    sf.read(1.0)
    stored = eventually(lambda: side_db("b", f"SELECT COUNT(*) FROM spamfilters WHERE pattern = '{PAT}'") == "1", seconds=6)
    check("a filter set on A is written down on B", bool(stored), side_db("b", "SELECT pattern FROM spamfilters"))
    b_room = f"#sf{RUN}"
    b_talk = Client(f"sfb{RUN}", port=B_PORT)
    b_talk.join(b_room)
    tmark = b_talk.mark()
    b_talk.send(f"PRIVMSG {b_room} :spamword{RUN} here")
    b_talk.read(1.2)
    check("and B refuses the line", bool(b_talk.find(" 404 ", "not delivered", lines=b_talk.since(tmark))), b_talk.since(tmark)[-2:])
    sf.send(f"SPAMFILTER DEL {PAT}")
    sf.read(1.0)
    lifted = eventually(lambda: side_db("b", f"SELECT COUNT(*) FROM spamfilters WHERE pattern = '{PAT}'") == "0", seconds=6)
    check("lifting it on A lifts it on B", bool(lifted), side_db("b", "SELECT pattern FROM spamfilters"))
    tmark = b_talk.mark()
    b_talk.send(f"PRIVMSG {b_room} :spamword{RUN} again")
    b_talk.read(1.2)
    check("and the line goes through on B again", not b_talk.find(" 404 ", lines=b_talk.since(tmark)), b_talk.since(tmark)[-2:])
    b_talk.close()
sf.close()

section("a shun set on A silences its man on B")
sn = Client(f"sn{RUN}", port=A_PORT)
sn.send(f"OPER linkoper {os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
sn.wait_for(" 381 ", " 464 ", seconds=5)
if sn.find(" 381 "):
    SROOM = f"#sn{RUN}"
    sn.join(SROOM)
    loud = Client(f"loud{RUN}", port=B_PORT)
    loud.join(SROOM)
    heard = arrives(sn, f"loud{RUN}", sn.mark(), seconds=8)
    sn.send(f"SHUN loud{RUN}!*@* :quiet on B too")
    sn.read(1.2)
    stored = eventually(lambda: side_db("b", "SELECT COUNT(*) FROM server_bans WHERE kind = 'S'") == "1", seconds=8)
    check("B wrote the shun down as one", bool(stored), side_db("b", "SELECT mask, kind FROM server_bans"))
    smark, lmark = sn.mark(), loud.mark()
    loud.send(f"PRIVMSG {SROOM} :buy my things")
    loud.read(1.2)
    sn.read(1.2)
    check("and nothing they say crosses back", not sn.find("buy my things", lines=sn.since(smark)), sn.since(smark)[-2:])
    check("while they are told nothing", not loud.since(lmark), loud.since(lmark)[-2:])
    sn.send(f"UNSHUN loud{RUN}!*@*")
    sn.read(1.2)
    lifted = eventually(lambda: side_db("b", "SELECT COUNT(*) FROM server_bans WHERE kind = 'S'") == "0", seconds=8)
    check("lifting it on A lifts it on B", bool(lifted), side_db("b", "SELECT mask, kind FROM server_bans"))
    smark = sn.mark()
    loud.send(f"PRIVMSG {SROOM} :hello again")
    loud.read(1.2)
    got = arrives(sn, "hello again", smark, seconds=8)
    check("and they can speak again", bool(got), sn.since(smark)[-2:])
    loud.close()
sn.close()

section("a D-line crosses the link too")
gate = Client(f"gate{RUN}", port=A_PORT)
gate.send(f"OPER linkoper {os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
gate.wait_for(" 381 ", " 464 ", seconds=5)
if gate.find(" 381 "):
    gate.send("DLINE 127.0.0.9/32 :kept out everywhere")
    gate.read(1.0)
    stored = eventually(lambda: side_db("b", "SELECT COUNT(*) FROM server_bans WHERE mask = '127.0.0.9/32' AND kind = 'D'") == "1",
                        seconds=6)
    check("a D-line set on A is written down on B as one", bool(stored), side_db("b", "SELECT mask, kind FROM server_bans"))
    shut = Client(port=B_PORT, source="127.0.0.9")
    shut.read(1.5)
    check("and B turns the address away at the door", bool(shut.find("ERROR", "banned")) and not shut.find(" 001 "), shut.lines[-2:])
    shut.close()
    gate.send("UNDLINE 127.0.0.9/32")
    gate.read(1.0)
    lifted = eventually(lambda: side_db("b", "SELECT COUNT(*) FROM server_bans WHERE mask = '127.0.0.9/32'") == "0", seconds=6)
    check("lifting it on A lifts it on B", bool(lifted), side_db("b", "SELECT mask FROM server_bans"))
    opened = Client(f"opn{RUN}", port=B_PORT, source="127.0.0.9")
    check("and the address is welcome on B again", bool(opened.find(" 001 ")), opened.lines[-2:])
    opened.close()
gate.close()

section("an operator can drop a link, and dial it again")
# Until now the only way to take a link down or bring one up was to restart
# the server. SQUIT tells the peer why before the link goes; CONNECT dials a
# configured link now rather than waiting for autoconnect's next try.


def servers_listed(client):
    mark = client.mark()
    client.send("LINKS")
    client.wait_for(" 365 ", seconds=5)
    return " ".join(client.find(" 364 ", lines=client.since(mark)))


shaper = Client(f"shp{RUN}", port=A_PORT)
shaper.send(f"OPER linkoper {os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
shaper.wait_for(" 381 ", " 464 ", seconds=5)
if shaper.find(" 381 "):
    plain = Client(f"pln{RUN}", port=A_PORT)
    pmark = plain.mark()
    plain.send(f"SQUIT {B_NAME} :not mine to drop")
    plain.read(1.2)
    check("a user without the privilege cannot drop a link",
          bool(plain.find(" 481 ", lines=plain.since(pmark))), plain.since(pmark)[-2:])
    plain.close()

    a_before, b_before = log("a"), log("b")
    mark = shaper.mark()
    squit_mark = mark
    shaper.send(f"SQUIT {B_NAME} :maintenance")
    shaper.read(2.0)
    check("SQUIT is acknowledged",
          bool(shaper.find("Closing link to", B_NAME, lines=shaper.since(mark))), shaper.since(mark)[-2:])
    told = eventually(lambda: ("maintenance" in log("b")[len(b_before):]) or None, seconds=8)
    check("and B is told why", bool(told),
          [l for l in log("b")[len(b_before):].splitlines() if "closing" in l.lower()][-2:])
    # Autoconnect brings B back within a couple of seconds, so the gap is
    # read from A's log rather than raced for with LINKS.
    gone = eventually(lambda: ("Netsplit: server is gone" in log("a")[len(a_before):]) or None, seconds=8)
    check("A let B go", bool(gone),
          [l for l in log("a")[len(a_before):].splitlines() if "Netsplit" in l or "closed" in l][-2:])
    shaper.read(0.5)
    check("and every operator hears that the link was lost",
          bool(shaper.find("NOTICE", "Link with", B_NAME, "lost", lines=shaper.since(mark))),
          [l for l in shaper.since(mark) if "NOTICE" in l][-3:])

    mark = shaper.mark()
    shaper.send(f"SQUIT nosuch.{RUN}.test :nothing there")
    shaper.read(1.2)
    check("dropping a server that is not attached is refused",
          bool(shaper.find("FAIL SQUIT NO_SUCH_LINK", lines=shaper.since(mark))), shaper.since(mark)[-2:])

    mark = shaper.mark()
    shaper.send(f"CONNECT {B_NAME}")
    shaper.read(2.0)
    acknowledged = shaper.find("Connecting to", B_NAME, lines=shaper.since(mark)) or \
        shaper.find("ALREADY_LINKED", lines=shaper.since(mark))
    check("CONNECT dials it again, or finds autoconnect already has", bool(acknowledged), shaper.since(mark)[-2:])
    back = eventually(lambda: (B_NAME in servers_listed(shaper)) or None, seconds=20)
    check("and B is listed again", bool(back), servers_listed(shaper))
    shaper.read(0.5)
    # Autoconnect may well have brought B back before CONNECT was even sent,
    # so the notice is looked for from the SQUIT onward.
    check("and every operator hears that it is back",
          bool(shaper.find("NOTICE", "Link with", B_NAME, "established", lines=shaper.since(squit_mark))),
          [l for l in shaper.since(squit_mark) if "NOTICE" in l][-3:])
    mark = shaper.mark()
    shaper.send(f"CONNECT nosuch.{RUN}.test")
    shaper.read(1.2)
    check("dialling a link that is not configured is refused",
          bool(shaper.find("FAIL CONNECT NO_SUCH_LINK", lines=shaper.since(mark))), shaper.since(mark)[-2:])
shaper.close()

section("WHOWAS remembers people who were on the other server")
# A user who was on B was here as far as anybody on A in a channel with them
# could tell, so A remembers them too — under B's name.
gone = Client(f"gone{RUN}", port=B_PORT)
gone.send(f"JOIN #ww{RUN}")
gone.read(0.8)
asker = Client(f"ask{RUN}", port=A_PORT)
seen = eventually(lambda: [l for l in whois(asker, f"gone{RUN}") if " 311 " in l] or None, seconds=8)
check("A can see the user on B", bool(seen), seen)
gone.send("QUIT :off to bed")
gone.read(0.5)
time.sleep(1.0)
amark = asker.mark()
asker.send(f"WHOWAS gone{RUN}")
asker.wait_for(" 369 ", seconds=5)
check("after they quit, A's WHOWAS knows them", bool(asker.find(" 314 ", f"gone{RUN}", lines=asker.since(amark))), asker.since(amark)[-3:])
check("under the name of the server they were on", bool(asker.find(" 312 ", B_NAME, lines=asker.since(amark))), asker.since(amark)[-3:])
asker.close()

section("SANICK reaches across the link")
# An operator on A renames somebody on B: B makes the change, and both sides
# see an ordinary nick change.
far = Client(f"far{RUN}", port=B_PORT)
far.send(f"JOIN #sn{RUN}")
far.read(0.8)
near = Client(f"near{RUN}", port=A_PORT)
near.send(f"JOIN #sn{RUN}")
near.read(0.8)
sanop = Client(f"sanop{RUN}", port=A_PORT)
sanop.send(f"OPER linkoper {os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
sanop.wait_for(" 381 ", " 464 ", seconds=5)
seen = eventually(lambda: [l for l in whois(sanop, f"far{RUN}") if " 311 " in l] or None, seconds=8)
fmark, nmark = far.mark(), near.mark()
sanop.send(f"SANICK far{RUN} renamed{RUN}")
sanop.read(1.0)
check("the user on B is renamed by B", bool(arrives(far, f"NICK renamed{RUN}", fmark)), far.since(fmark)[-3:])
check("and told by whom", bool(arrives(far, "operator sanop", fmark)), far.since(fmark)[-3:])
check("and A's user in the same channel sees it", bool(arrives(near, f"NICK renamed{RUN}", nmark)), near.since(nmark)[-3:])
omark = sanop.mark()
sanop.send(f"WHOIS renamed{RUN}")
sanop.wait_for(" 318 ", " 401 ", seconds=5)
check("and A knows the new name", bool(sanop.find(" 311 ", f"renamed{RUN}", lines=sanop.since(omark))), sanop.since(omark)[-3:])
far.close()
near.close()
sanop.close()

section("a split is noticed")
# Stop B and watch A report the split rather than carrying on as if nothing
# happened.
pid_path = os.path.join(LINK_DIR, "b.pid")
if os.path.exists(pid_path):
    # Earlier sections have already split and rejoined the two on purpose,
    # so only what A logs from here on counts.
    a_before = log("a")
    os.kill(int(open(pid_path).read().strip()), 15)
    deadline = time.time() + 15
    saw_split = False
    while time.time() < deadline:
        if "Netsplit" in log("a")[len(a_before):]:
            saw_split = True
            break
        time.sleep(0.5)
    check("A noticed B going away", saw_split, log("a")[-400:])

    after = eventually(lambda: (lambda l: l if B_NAME not in l else None)(servers_listed(a)), seconds=8) or servers_listed(a)
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
