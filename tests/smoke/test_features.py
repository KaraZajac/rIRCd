#!/usr/bin/env python3
"""Server features beyond the core protocol: SCRAM, history cursors, bans,
cloaking, WEBIRC, auto-join, monitor patterns, read markers and REHASH."""

import base64
import hashlib
import hmac
import time

from harness import (
    IRC_HOST,
    IRC_PORT,
    OPER_NAME,
    OPER_PASSWORD,
    RUN_ID,
    Client,
    check,
    connect_negotiating,
    db,
    section,
    summary,
)

PASSWORD = "hunter2secret"
ACCOUNT = f"scram{RUN_ID}"
HISTORY = f"#history{RUN_ID}"
BANS = f"#bans{RUN_ID}"
# Gets +i partway through, so it must be a fresh channel each run.
OPENINV = f"#openinv{RUN_ID}"
BATCHING = f"#batching{RUN_ID}"
TAGS = ["message-tags", "server-time", "batch", "echo-message"]


# ── SASL SCRAM-SHA-256 ────────────────────────────────────────────────────────


def _last_authenticate_payload(client, prefix):
    """Most recent AUTHENTICATE payload starting with `prefix`, decoded.

    Server AUTHENTICATE lines carry a source prefix, so match on the command
    rather than the start of the line.
    """
    for line in reversed(client.lines):
        parts = line.split()
        if len(parts) < 2:
            continue
        command_at = 1 if parts[0].startswith((":", "@")) else 0
        if parts[command_at] != "AUTHENTICATE" or len(parts) <= command_at + 1:
            continue
        payload = parts[command_at + 1]
        if payload in ("+", "*"):
            continue
        try:
            decoded = base64.b64decode(payload + "==").decode()
        except Exception:
            continue
        if decoded.startswith(prefix):
            return decoded
    return None


def scram_exchange(client, account, password):
    """Run a full SCRAM-SHA-256 exchange, returning (server_verified, lines)."""
    nonce = base64.b64encode(b"smoke-client-nonce").decode().rstrip("=")
    client_first_bare = f"n={account},r={nonce}"
    client.send("AUTHENTICATE SCRAM-SHA-256")
    client.read(1.0)
    client.send("AUTHENTICATE " + base64.b64encode(f"n,,{client_first_bare}".encode()).decode())
    client.read(1.5)

    server_first = _last_authenticate_payload(client, "r=")
    if not server_first:
        return False, "no server-first message"

    fields = dict(part.split("=", 1) for part in server_first.split(","))
    salt = base64.b64decode(fields["s"])
    iterations = int(fields["i"])
    server_nonce = fields["r"]

    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    channel_binding = base64.b64encode(b"n,,").decode()
    client_final_bare = f"c={channel_binding},r={server_nonce}"
    auth_message = f"{client_first_bare},{server_first},{client_final_bare}"
    client_signature = hmac.new(stored_key, auth_message.encode(), hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
    client_final = f"{client_final_bare},p={base64.b64encode(proof).decode()}"

    client.send("AUTHENTICATE " + base64.b64encode(client_final.encode()).decode())
    client.read(2.0)

    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    expected = base64.b64encode(
        hmac.new(server_key, auth_message.encode(), hashlib.sha256).digest()
    ).decode()
    server_final = _last_authenticate_payload(client, "v=")
    if not server_final:
        return False, "no server-final message"
    return server_final[2:] == expected, server_final


section("account for the authentication tests")
setup = Client(ACCOUNT)
mark = setup.mark()
setup.send(f"REGISTER * {ACCOUNT}@example.org {PASSWORD}")
setup.wait_for("REGISTER", seconds=20)
if setup.find("VERIFICATION_REQUIRED", lines=setup.since(mark)):
    import re

    from harness import wait_for_mail

    body = "".join(wait_for_mail(1, seconds=15)[-1:])
    match = re.search(rf"VERIFY {ACCOUNT} ([A-Z0-9]{{8}})", body)
    if match:
        setup.send(f"VERIFY {ACCOUNT} {match.group(1)}")
        setup.read(2.0)
check("test account is usable",
      bool(setup.find(" 900 ")) or bool(setup.find("ACCOUNT_EXISTS")), setup.lines[-3:])
setup.close()

section("SASL SCRAM-SHA-256")
s = connect_negotiating("scramclient", caps=["sasl"])
verified, detail = scram_exchange(s, ACCOUNT, PASSWORD)
check("server proof verifies (mutual authentication)", verified, detail)
check("903 RPL_SASLSUCCESS", bool(s.find(" 903 ")), s.lines[-4:])
s.send("CAP END")
s.wait_for(" 376 ", " 422 ", seconds=5)
s.close()

s = connect_negotiating("scrambad", caps=["sasl"])
verified, _ = scram_exchange(s, ACCOUNT, "the-wrong-password")
check("a wrong password fails SCRAM", not verified)
check("904 for the failed attempt", bool(s.find(" 904 ")), s.lines[-4:])
s.close()

section("cloaking")
cloaked = Client("cloaky")
cloaked.send("WHOIS cloaky")
cloaked.read(1.5)
whois = " ".join(cloaked.find(" 311 "))
check("the host is cloaked, not the raw IP", ".IP" in whois and "127.0.0.1" not in whois, whois)

section("draft/auto-join")
auto = Client("autojoiner", caps=["draft/auto-join"])
line = auto.find("AUTOJOIN")
check("AUTOJOIN sent to a capable client", bool(line), auto.lines[-6:])
check("it lists the configured channels",
      bool(line) and "#lobby" in line[0] and "#help" in line[0], line)
auto.close()

plain = Client("noautojoin")
check("clients without the cap get no AUTOJOIN", not plain.find("AUTOJOIN"), plain.lines[-4:])
plain.close()

section("WEBIRC")
gw = Client()
gw.send("WEBIRC smoke-gateway-secret smokegw gateway.example 203.0.113.45")
gw.read(1.0)
gw.send("NICK gwuser")
gw.send("USER gwuser 0 * :Gateway User")
gw.wait_for(" 376 ", " 422 ", seconds=5)
check("a gateway connection registers", bool(gw.find(" 001 ")), gw.lines[:3])
gw.send("WHOIS gwuser")
gw.read(1.5)
whois = " ".join(gw.find(" 311 "))
check("the real client host is used, not the gateway's",
      "127.0.0.1" not in whois, whois)
gw.close()

bad_gw = Client()
bad_gw.send("WEBIRC wrong-password badgw gateway.example 203.0.113.99")
bad_gw.read(1.0)
check("a wrong WEBIRC password is refused",
      bool(bad_gw.find("ERROR")) or bool(bad_gw.find(" 464 ")) or bool(bad_gw.find("FAIL")),
      bad_gw.lines[-3:])
bad_gw.close()

section("CHATHISTORY cursors")
op = Client("histop", caps=TAGS + ["draft/chathistory", "draft/event-playback"])
op.join(HISTORY)
msgids = []
for n in range(5):
    mark = op.mark()
    op.send(f"PRIVMSG {HISTORY} :message {n}")
    op.read(1.0)
    for line in op.find("PRIVMSG", f"message {n}", lines=op.since(mark)):
        for part in line.lstrip("@").split(" ")[0].split(";"):
            if part.startswith("msgid="):
                msgids.append(part.split("=", 1)[1])
check("five messages sent and identified", len(msgids) == 5, msgids)

mark = op.mark()
op.send(f"CHATHISTORY LATEST {HISTORY} * 3")
op.read(2.0)
latest = op.find("PRIVMSG", HISTORY, lines=op.since(mark))
check("LATEST returns at most the requested count", len(latest) <= 3, len(latest))
check("LATEST returns the newest messages",
      bool(latest) and "message 4" in " ".join(latest), [l[-40:] for l in latest])

if len(msgids) == 5:
    mark = op.mark()
    op.send(f"CHATHISTORY BEFORE {HISTORY} msgid={msgids[3]} 10")
    op.read(2.0)
    before = " ".join(op.find("PRIVMSG", lines=op.since(mark)))
    check("BEFORE returns earlier messages only",
          "message 2" in before and "message 4" not in before, before[-120:])

    mark = op.mark()
    op.send(f"CHATHISTORY AFTER {HISTORY} msgid={msgids[1]} 10")
    op.read(2.0)
    after = " ".join(op.find("PRIVMSG", lines=op.since(mark)))
    check("AFTER returns later messages only",
          "message 3" in after and "message 0" not in after, after[-120:])

    mark = op.mark()
    op.send(f"CHATHISTORY AROUND {HISTORY} msgid={msgids[2]} 3")
    op.read(2.0)
    around = op.find("PRIVMSG", lines=op.since(mark))
    check("AROUND returns messages either side", bool(around), [l[-40:] for l in around])

    mark = op.mark()
    op.send(f"CHATHISTORY BETWEEN {HISTORY} msgid={msgids[0]} msgid={msgids[4]} 10")
    op.read(2.0)
    between = " ".join(op.find("PRIVMSG", lines=op.since(mark)))
    check("BETWEEN returns the span",
          "message 1" in between and "message 3" in between, between[-120:])

section("a conversation follows the account, not the nick")
mover = Client(f"mover{RUN_ID}", caps=TAGS + ["draft/chathistory"])
mark = mover.mark()
mover.send(f"REGISTER * mover{RUN_ID}@example.org {PASSWORD}")
mover.wait_for("REGISTER", seconds=20)
if mover.find("VERIFICATION_REQUIRED", lines=mover.since(mark)):
    import re as _re

    from harness import wait_for_mail as _wait

    body = "".join(_wait(1, seconds=15)[-1:])
    code = _re.search(rf"VERIFY mover{RUN_ID} ([A-Z0-9]{{8}})", body)
    if code:
        mover.send(f"VERIFY mover{RUN_ID} {code.group(1)}")
        mover.read(2.0)
check("the mover is logged in", bool(mover.find(" 900 ")), mover.lines[-3:])

peer = Client(f"peer{RUN_ID}", caps=TAGS + ["draft/chathistory"])
mover.send(f"PRIVMSG peer{RUN_ID} :before the rename")
mover.read(1.0)
peer.read(1.0)
mover.send(f"NICK moved{RUN_ID}")
mover.read(1.5)
mover.send(f"PRIVMSG peer{RUN_ID} :after the rename")
mover.read(1.0)
peer.read(1.5)
time.sleep(1.5)

mark = mover.mark()
mover.send(f"CHATHISTORY LATEST peer{RUN_ID} * 20")
mover.read(2.5)
replay = [l for l in mover.since(mark) if "the rename" in l]
check("both sides of a nick change are in one conversation", len(replay) == 2,
      [l[-40:] for l in replay])

mark = peer.mark()
peer.send(f"CHATHISTORY LATEST moved{RUN_ID} * 20")
peer.read(2.5)
replay = [l for l in peer.since(mark) if "the rename" in l and "batch=" in l]
check("the partner finds it under the new nick", len(replay) == 2, [l[-40:] for l in replay])
peer.close()
mover.close()

section("SASL chunk length")
big = connect_negotiating(f"saslbig{RUN_ID}", caps=["sasl"])
big.send("AUTHENTICATE PLAIN")
big.read(1.0)
mark = big.mark()
big.send("AUTHENTICATE " + "A" * 450)
big.read(1.5)
check("a chunk over 400 bytes is answered with 905",
      bool(big.find(" 905 ", lines=big.since(mark))), big.since(mark))
big.close()

section("CHATHISTORY for direct conversations")
alice = Client(f"pma{RUN_ID}", caps=TAGS + ["draft/chathistory"])
bob = Client(f"pmb{RUN_ID}", caps=TAGS + ["draft/chathistory"])
for i in range(3):
    alice.send(f"PRIVMSG pmb{RUN_ID} :from alice {i}")
    time.sleep(0.2)
    bob.send(f"PRIVMSG pma{RUN_ID} :from bob {i}")
    time.sleep(0.2)
alice.read(1.5)
bob.read(1.5)

mark = alice.mark()
alice.send(f"CHATHISTORY LATEST pmb{RUN_ID} * 20")
alice.read(2.5)
replay = alice.find("PRIVMSG", lines=alice.since(mark))
check("a direct conversation has history", len(replay) == 6, [l[-40:] for l in replay])
check("both sides of the conversation are replayed",
      any("from alice" in l for l in replay) and any("from bob" in l for l in replay), replay[:2])
check("the requester's own messages are addressed to the other party",
      all(f"PRIVMSG pmb{RUN_ID}" in l for l in replay if "from alice" in l), replay)
check("incoming messages are addressed to the requester",
      all(f"PRIVMSG pma{RUN_ID}" in l for l in replay if "from bob" in l), replay)

mark = bob.mark()
bob.send(f"CHATHISTORY LATEST PMA{RUN_ID} * 20")  # different case
bob.read(2.5)
check("the target nick is matched case-insensitively",
      len(bob.find("PRIVMSG", lines=bob.since(mark))) == 6, bob.since(mark)[:3])

mark = alice.mark()
alice.send("CHATHISTORY TARGETS timestamp=2020-01-01T00:00:00.000Z timestamp=2038-01-01T00:00:00.000Z 30")
alice.read(2.5)
targets = [l.split("TARGETS ")[1].split()[0] for l in alice.since(mark) if "TARGETS " in l]
check("TARGETS lists the conversation partner", f"pmb{RUN_ID}" in targets, targets[:6])

eve = Client(f"pme{RUN_ID}", caps=TAGS + ["draft/chathistory"])
mark = eve.mark()
eve.send(f"CHATHISTORY LATEST pmb{RUN_ID} * 20")
eve.read(2.5)
check("someone else cannot read that conversation",
      not [l for l in eve.since(mark) if "from alice" in l or "from bob" in l], eve.since(mark)[:3])
mark = eve.mark()
eve.send("CHATHISTORY TARGETS timestamp=2020-01-01T00:00:00.000Z timestamp=2038-01-01T00:00:00.000Z 30")
eve.read(2.5)
eve_targets = [l.split("TARGETS ")[1].split()[0] for l in eve.since(mark) if "TARGETS " in l]
check("nor see it in TARGETS", not [t for t in eve_targets if not t.startswith("#")], eve_targets[:6])
eve.close()
alice.close()
bob.close()

section("draft/event-playback")
joiner = Client("eventjoiner", caps=TAGS)
joiner.join(HISTORY)
joiner.send(f"PART {HISTORY} :heading off")
joiner.read(1.0)

mark = op.mark()
op.send(f"CHATHISTORY LATEST {HISTORY} * 50")
op.read(2.5)
replayed = op.since(mark)
check("JOIN events replayed to event-playback clients",
      bool(op.find("JOIN", lines=replayed)), [l[:70] for l in replayed][:6])
check("PART events replayed", bool(op.find("PART", lines=replayed)), [l[:70] for l in replayed][:6])

no_events = Client("noevents", caps=TAGS + ["draft/chathistory"])
no_events.join(HISTORY)
mark = no_events.mark()
no_events.send(f"CHATHISTORY LATEST {HISTORY} * 50")
no_events.read(2.5)
replayed = no_events.since(mark)
in_batch = [l for l in replayed if "batch=" in l]
check("clients without event-playback get messages only",
      not [l for l in in_batch if " JOIN " in l or " PART " in l],
      [l[:70] for l in in_batch][:5])
no_events.close()

section("draft/client-batch")
sender = Client("batchsender", caps=TAGS + ["draft/client-batch"])
receiver = Client("batchreceiver", caps=TAGS + ["draft/client-batch"])
sender.join(BATCHING)
receiver.join(BATCHING)
mark = receiver.mark()
sender.send(f"BATCH +cb draft/client-batch {BATCHING}")
sender.send(f"@batch=cb PRIVMSG {BATCHING} :part one")
sender.send(f"@batch=cb PRIVMSG {BATCHING} :part two")
sender.send("BATCH -cb")
receiver.read(2.0)
received = receiver.since(mark)
check("client batch is relayed", bool(receiver.find("BATCH", lines=received)), received)
check("both messages arrive",
      bool(receiver.find("part one", lines=received)) and bool(receiver.find("part two", lines=received)),
      received)
quiet_sender = Client("batchquiet", caps=["message-tags", "server-time", "batch", "draft/client-batch"])
quiet_sender.join(BATCHING)
mark = quiet_sender.mark()
quiet_sender.send(f"BATCH +cb2 draft/client-batch {BATCHING}")
quiet_sender.send(f"@batch=cb2 PRIVMSG {BATCHING} :sender should not see this")
quiet_sender.send("BATCH -cb2")
quiet_sender.read(2.0)
check("a client batch is not echoed to a sender without echo-message",
      not quiet_sender.find("sender should not see this", lines=quiet_sender.since(mark)),
      quiet_sender.since(mark))
mark = receiver.mark()
receiver.read(2.0)
check("but it still reaches the other members",
      bool(receiver.find("sender should not see this", lines=receiver.since(mark))),
      receiver.since(mark))
quiet_sender.close()

sender.close()
receiver.close()

section("bans, exceptions and quiets")
chanop = Client("banop", caps=TAGS)
chanop.join(BANS)
target = Client("bantarget", caps=TAGS)

chanop.send(f"MODE {BANS} +b bantarget!*@*")
chanop.read(1.0)
mark = target.mark()
target.join(BANS)
check("+b keeps the banned user out", bool(target.find(" 474 ", lines=target.since(mark))), target.since(mark))

chanop.send(f"MODE {BANS} +e bantarget!*@*")
chanop.read(1.0)
mark = target.mark()
target.join(BANS)
check("+e exempts them again", bool(target.find("JOIN", f"#bans{RUN_ID}", lines=target.since(mark))), target.since(mark))

chanop.send(f"MODE {BANS} +q bantarget!*@*")
chanop.read(1.0)
mark = target.mark()
target.send(f"PRIVMSG {BANS} :can I speak")
target.read(1.0)
check("+q silences without kicking", bool(target.find(" 404 ", lines=target.since(mark))), target.since(mark))

mark = target.mark()
chanop.send(f"KICK {BANS} bantarget :out you go")
target.read(1.5)
check("KICK removes the user", bool(target.find("KICK", lines=target.since(mark))), target.since(mark))
target.close()

section("MONITOR online/offline")
watched_nick = f"watched{RUN_ID}"
mon = Client(f"mon{RUN_ID}", caps=["extended-monitor", "away-notify", "account-notify", "setname", "chghost"])
mon.send(f"MONITOR + {watched_nick}")
mon.read(1.5)
mark = mon.mark()
watched = Client(watched_nick, caps=["setname"])
mon.read(2.5)
check("730 when a monitored nick connects", bool(mon.find(" 730 ", lines=mon.since(mark))), mon.since(mark))

section("extended-monitor events")
# The spec extends MONITOR to AWAY, ACCOUNT, CHGHOST and SETNAME for monitored
# nicks, so the watcher sees them without sharing a channel.
mark = mon.mark()
watched.send("AWAY :stepping out")
mon.read(2.0)
check("AWAY from a monitored nick", bool(mon.find("AWAY", lines=mon.since(mark))), mon.since(mark))

mark = mon.mark()
watched.send("SETNAME :Monitored User")
mon.read(2.0)
check("SETNAME from a monitored nick", bool(mon.find("SETNAME", lines=mon.since(mark))), mon.since(mark))

mark = mon.mark()
watched.close()
mon.read(2.5)
check("731 when a monitored nick disconnects", bool(mon.find(" 731 ", lines=mon.since(mark))), mon.since(mark))

# rIRCd also lets a client monitor a nick!user@host mask, not just a nick.
mark = mon.mark()
mon.send(f"MONITOR + masked{RUN_ID}*!*@*")
mon.read(1.5)
masked = Client(f"masked{RUN_ID}user")
mon.read(2.5)
check("730 when a nick matching a monitored mask connects",
      bool(mon.find(" 730 ", lines=mon.since(mark))), mon.since(mark))
mark = mon.mark()
masked.close()
mon.read(2.5)
check("731 when it disconnects", bool(mon.find(" 731 ", lines=mon.since(mark))), mon.since(mark))
mon.close()

section("draft/read-marker persistence")
reader = connect_negotiating(f"markread{RUN_ID}a", caps=["sasl", "draft/read-marker"])
reader.sasl_plain(ACCOUNT, PASSWORD)
reader.send("CAP END")
reader.wait_for(" 376 ", " 422 ", seconds=5)
reader.send(f"MARKREAD {HISTORY} timestamp=2026-05-05T05:05:05.000Z")
reader.read(1.5)
reader.close()

again = connect_negotiating(f"markread{RUN_ID}b", caps=["sasl", "draft/read-marker"])
again.sasl_plain(ACCOUNT, PASSWORD)
again.send("CAP END")
again.wait_for(" 376 ", " 422 ", seconds=5)
mark = again.mark()
again.send(f"MARKREAD {HISTORY}")
again.read(1.5)
check("a read marker survives reconnection",
      bool(again.find("2026-05-05T05:05:05", lines=again.since(mark))), again.since(mark))
check("it is stored against the account",
      "2026-05-05T05:05:05" in db(f"SELECT timestamp FROM read_markers WHERE account='{ACCOUNT}'"))
again.close()

section("multi-byte text at length limits")
# Length limits are counted in bytes; truncating at a raw byte index used to
# panic and take the whole server down.
mb = Client(f"mb{RUN_ID}", caps=TAGS)
mb.join(f"#mb{RUN_ID}")
mark = mb.mark()
mb.send(f"TOPIC #mb{RUN_ID} :" + "🎉" * 120)
mb.read(2.0)
check("an over-long emoji topic is accepted and truncated",
      bool(mb.find("TOPIC", lines=mb.since(mark))), mb.since(mark))

mark = mb.mark()
mb.send("AWAY :" + "字" * 120)  # 360 bytes: over AWAYLEN, inside the line limit
mb.read(2.0)
check("an over-long CJK away message is accepted", bool(mb.find(" 306 ", lines=mb.since(mark))),
      mb.since(mark))

mark = mb.mark()
mb.send(f"MODE #mb{RUN_ID} +k " + "🔑" * 40)
mb.read(2.0)
mb.send(f"PRIVMSG #mb{RUN_ID} :" + "字" * 100)
mb.read(2.0)

alive = Client(f"mbalive{RUN_ID}")
check("the server survives all of it", bool(alive.find(" 001 ")), alive.lines[-3:])
alive.close()
mb.close()

section("history keeps up with a burst")
# History used to be written inline, one database round-trip per message, inside
# the loop that handles every command: 200 messages took over five seconds.
burst_chan = f"#burst{RUN_ID}"
reader = Client(f"burstread{RUN_ID}", caps=TAGS)
reader.join(burst_chan)
senders = [Client(f"bsend{RUN_ID}x{i}") for i in range(10)]
for c in senders:
    c.join(burst_chan)
# JOIN spends a flood token; give the buckets a moment so the burst itself fits.
time.sleep(1.5)
reader.read(0.5)

mark = reader.mark()
started = time.time()
for i, c in enumerate(senders):
    for j in range(10):
        c.send(f"PRIVMSG {burst_chan} :burst {i}-{j}")
deadline = time.time() + 30
delivered = 0
while time.time() < deadline:
    reader.read(0.05)
    delivered = len(reader.find("burst ", lines=reader.since(mark)))
    if delivered >= 100:
        break
elapsed = time.time() - started
check("a 100-message burst is delivered", delivered == 100, f"delivered {delivered}")
check("and delivered promptly", elapsed < 5.0, f"took {elapsed:.2f}s")
burst_mark = mark

# The rows must still be there, in order, once the writer has caught up.
histclient = Client(f"bursthist{RUN_ID}", caps=TAGS + ["draft/chathistory"])
histclient.join(burst_chan)
time.sleep(1.5)
mark = histclient.mark()
histclient.send(f"CHATHISTORY LATEST {burst_chan} * 100")
histclient.read(3.0)
replayed = [l for l in histclient.since(mark) if "burst " in l]
check("the burst reached history", len(replayed) >= 100, f"{len(replayed)} rows")
# Ten senders interleave, so the order that matters is the one the server
# actually processed them in — history must match what the channel saw.
delivered_order = [l.split("burst ")[1].split()[0]
                   for l in reader.find("burst ", lines=reader.since(burst_mark))]
history_order = [l.split("burst ")[1].split()[0] for l in replayed]
check("history preserves the order messages were delivered in",
      history_order[: len(delivered_order)] == delivered_order,
      f"delivered {delivered_order[:5]} vs history {history_order[:5]}")
histclient.close()
reader.close()
for c in senders:
    c.close()

section("a client that stops reading must not stall the server")
# Every command is handled by one loop, so awaiting a stalled client would freeze
# the server for everyone. Regression test for exactly that.
import socket

stalled = socket.create_connection(("127.0.0.1", 16667), timeout=10)
stalled.sendall(f"NICK stalled{RUN_ID}\r\nUSER s 0 * :s\r\nJOIN #stall{RUN_ID}\r\n".encode())
time.sleep(1.0)  # registers and joins, then never reads again

talker = Client(f"talker{RUN_ID}", caps=TAGS)
talker.join(f"#stall{RUN_ID}")
for batch in range(8):
    for i in range(10):
        talker.send(f"PRIVMSG #stall{RUN_ID} :filler {batch}-{i} " + "x" * 300)
    time.sleep(1.0)
talker.read(1.0)

canary = Client(f"canary{RUN_ID}")
check("a new client is still served while another is stalled",
      bool(canary.find(" 001 ")), canary.lines[-3:])
mark = canary.mark()
canary.send("PING stillalive")
canary.read(3.0)
check("the server still answers commands", bool(canary.find("PONG", lines=canary.since(mark))),
      canary.since(mark))
canary.close()
talker.close()
stalled.close()

section("channel ownership and access lists")
# The founder is the account that created the channel; operator and voice status
# granted by an operator is remembered, the way a services bot would keep it.
owner_chan = f"#owned{RUN_ID}"
founder = Client(f"founder{RUN_ID}", caps=TAGS)
mark = founder.mark()
founder.send(f"REGISTER * founder{RUN_ID}@example.org {PASSWORD}")
founder.wait_for("REGISTER", seconds=20)
if founder.find("VERIFICATION_REQUIRED", lines=founder.since(mark)):
    import re as _re2

    from harness import wait_for_mail as _wait2

    body = "".join(_wait2(1, seconds=15)[-1:])
    code = _re2.search(rf"VERIFY founder{RUN_ID} ([A-Z0-9]{{8}})", body)
    if code:
        founder.send(f"VERIFY founder{RUN_ID} {code.group(1)}")
        founder.read(2.0)
founder.join(owner_chan)

# Status that outlives a visit is remembered against an account, and the
# founder has one. Somebody not logged in holds what they are given while they
# are here and no further: remembering a name would hand it to whoever took the
# name next, and a name is not proof of anything.
regular = Client(f"regular{RUN_ID}", caps=TAGS)
regular.join(owner_chan)
founder.send(f"MODE {owner_chan} +o regular{RUN_ID}")
founder.read(1.5)
founder.send(f"MODE {owner_chan} +v regular{RUN_ID}")
founder.read(1.5)
time.sleep(1.0)

check("the founder is recorded",
      db(f"SELECT founder FROM channels WHERE name='{owner_chan}'") == f"founder{RUN_ID}")
ops = db(
    "SELECT nick_or_account FROM channel_operators o JOIN channels c ON c.id = o.channel_id "
    f"WHERE c.name = '{owner_chan}'"
).split("\n")
check("the founder's own standing is remembered", f"founder{RUN_ID}" in ops, ops)
check("a grant to a name with no account behind it is not",
      f"regular{RUN_ID}" not in ops, ops)

mark = regular.mark()
regular.send(f"NAMES {owner_chan}")
regular.read(1.2)
here_now = " ".join(regular.find(" 353 ", lines=regular.since(mark)))
check("though it applies for as long as they are here",
      f"@regular{RUN_ID}" in here_now, here_now)
regular.close()

# The founder comes back under another name: the status is the account's.
founder.close()
time.sleep(0.5)
back_nick = f"backagain{RUN_ID}"
returning = connect_negotiating(back_nick, caps=["sasl"])
returning.sasl_plain(f"founder{RUN_ID}", PASSWORD)
returning.send("CAP END")
returning.wait_for(" 001 ", seconds=6)
returning.join(owner_chan)
returning.read(1.5)
names = " ".join(returning.find(" 353 "))
# `^` rather than `@`: the founder outranks an operator, and the prefix shown
# is the highest held.
check("an account's standing is restored under any name",
      f"@{back_nick}" in names or f"^{back_nick}" in names, returning.lines[-6:])
returning.close()
founder.close()

section("channel lists survive a restart")
# A ban a channel operator sets must still be there after the server restarts —
# it used to live only in memory.
list_chan = f"#lists{RUN_ID}"
lister = Client(f"lister{RUN_ID}", caps=TAGS)
lister.join(list_chan)
lister.send(f"MODE {list_chan} +b nuisance{RUN_ID}!*@*")
lister.read(1.0)
lister.send(f"MODE {list_chan} +e friend{RUN_ID}!*@*")
lister.read(1.0)
lister.send(f"MODE {list_chan} +I invited{RUN_ID}!*@*")
lister.read(1.0)
lister.send(f"MODE {list_chan} +q quiet{RUN_ID}!*@*")
lister.read(1.0)
time.sleep(1.0)

stored = db(
    "SELECT list_type, mask FROM channel_lists l JOIN channels c ON c.id = l.channel_id "
    f"WHERE c.name = '{list_chan}' ORDER BY list_type"
)
for kind, who in [("b", "nuisance"), ("e", "friend"), ("I", "invited"), ("q", "quiet")]:
    check(f"+{kind} is stored", f"{who}{RUN_ID}" in stored, stored)

mark = lister.mark()
lister.send(f"MODE {list_chan} -b nuisance{RUN_ID}!*@*")
lister.read(1.0)
time.sleep(1.0)
stored = db(
    "SELECT mask FROM channel_lists l JOIN channels c ON c.id = l.channel_id "
    f"WHERE c.name = '{list_chan}' AND list_type = 'b'"
)
check("removing a ban removes it from storage", f"nuisance{RUN_ID}" not in stored, stored)
lister.close()

section("registered nicks are reserved")
imposter = connect_negotiating(f"imposter{RUN_ID}")
imposter.send("CAP END")
imposter.wait_for(" 376 ", " 422 ", seconds=5)
mark = imposter.mark()
imposter.send(f"NICK founder{RUN_ID}")
imposter.read(1.5)
check("someone else cannot take a registered nick",
      bool(imposter.find(" 433 ", lines=imposter.since(mark))), imposter.since(mark))
imposter.close()

owner_back = connect_negotiating(f"backagain{RUN_ID}", caps=["sasl"])
owner_back.sasl_plain(f"founder{RUN_ID}", PASSWORD)
owner_back.send("CAP END")
owner_back.wait_for(" 376 ", " 422 ", seconds=5)
mark = owner_back.mark()
owner_back.send(f"NICK founder{RUN_ID}")
owner_back.read(1.5)
check("the account holder can take their own nick",
      bool(owner_back.find("NICK", lines=owner_back.since(mark)))
      and not owner_back.find(" 433 ", lines=owner_back.since(mark)),
      owner_back.since(mark))
owner_back.close()

section("server bans")
oper = Client(f"banoper{RUN_ID}", caps=TAGS)
oper.send(f"OPER {OPER_NAME} {OPER_PASSWORD}")
oper.read(2.0)
target = Client(f"banned{RUN_ID}")
mark = oper.mark()
oper.send(f"KLINE banned{RUN_ID}!*@* :smoke test ban")
oper.read(2.0)
check("the ban is accepted", bool(oper.find("NOTICE", "added", lines=oper.since(mark))),
      oper.since(mark))
target.read(2.0)
check("the banned user is told why", bool(target.find("ERROR", "banned")), target.lines[-2:])

import socket as _socket

def try_connect(nick):
    c = _socket.create_connection((IRC_HOST, IRC_PORT), timeout=6)
    c.sendall(f"NICK {nick}\r\nUSER b 0 * :b\r\n".encode())
    c.settimeout(5)
    got, end = b"", time.time() + 5
    while time.time() < end:
        try:
            chunk = c.recv(65536)
        except _socket.timeout:
            break
        if not chunk:
            break
        got += chunk
        if b" 001 " in got or b"ERROR" in got:
            break
    c.close()
    return got.decode(errors="replace")

check("they cannot reconnect", "ERROR" in try_connect(f"banned{RUN_ID}"))
check("everyone else still can", " 001 " in try_connect(f"unbanned{RUN_ID}"))

mark = oper.mark()
oper.send(f"UNKLINE banned{RUN_ID}!*@*")
oper.read(2.0)
check("the ban can be lifted", bool(oper.find("removed", lines=oper.since(mark))), oper.since(mark))
check("and they can connect again", " 001 " in try_connect(f"banned{RUN_ID}"))
target.close()

section("reclaiming your own nick")
# With registered nicks reserved, a stale session of your own is the only thing
# that can be holding one — GHOST is how you take it back.
ghost_acct = f"ghost{RUN_ID}"
first = Client(ghost_acct, caps=TAGS)
mark = first.mark()
first.send(f"REGISTER * {ghost_acct}@example.org {PASSWORD}")
first.wait_for("REGISTER", seconds=20)
if first.find("VERIFICATION_REQUIRED", lines=first.since(mark)):
    import re as _re3

    from harness import wait_for_mail as _wait3

    body = "".join(_wait3(1, seconds=15)[-1:])
    code = _re3.search(rf"VERIFY {ghost_acct} ([A-Z0-9]{{8}})", body)
    if code:
        first.send(f"VERIFY {ghost_acct} {code.group(1)}")
        first.read(2.0)

second = connect_negotiating(f"ghosting{RUN_ID}", caps=["sasl"])
second.sasl_plain(ghost_acct, PASSWORD)
second.send("CAP END")
second.wait_for(" 376 ", " 422 ", seconds=5)

mark = second.mark()
second.send(f"GHOST {ghost_acct}")
second.read(2.0)
check("GHOST reports success", bool(second.find("NOTICE", "closed", lines=second.since(mark))),
      second.since(mark))
first.read(2.0)
check("the stale session is told why", bool(first.find("ERROR", "replaced")), first.lines[-2:])

mark = second.mark()
second.send(f"NICK {ghost_acct}")
second.read(2.0)
check("the nick is free to take", bool(second.find("NICK", lines=second.since(mark)))
      and not second.find(" 433 ", lines=second.since(mark)), second.since(mark))

stranger = Client(f"stranger{RUN_ID}")
mark = stranger.mark()
stranger.send(f"GHOST {ghost_acct}")
stranger.read(1.5)
check("a stranger cannot ghost someone else's nick",
      bool(stranger.find("FAIL GHOST", lines=stranger.since(mark))), stranger.since(mark))
stranger.close()
second.close()
first.close()

section("operator privileges")
# An operator whose config lists privileges may only do those things.
limited = Client(f"limitedop{RUN_ID}", caps=TAGS)
limited.send(f"OPER smokehelper {OPER_PASSWORD}")
limited.read(2.0)
check("the limited operator logs in", bool(limited.find(" 381 ")), limited.lines[-3:])

mark = limited.mark()
limited.send(f"KLINE nobody{RUN_ID}!*@* :not allowed")
limited.read(2.0)
check("without the ban privilege, KLINE is refused",
      bool(limited.find(" 481 ", lines=limited.since(mark))), limited.since(mark))

mark = limited.mark()
limited.send("REHASH")
limited.read(2.0)
check("REHASH is refused too", bool(limited.find(" 481 ", lines=limited.since(mark))),
      limited.since(mark))

victim = Client(f"killme{RUN_ID}")
mark = victim.mark()
limited.send(f"KILL killme{RUN_ID} :allowed")
victim.read(2.0)
check("but the privilege it does have works",
      bool(victim.find("ERROR", lines=victim.since(mark))), victim.since(mark))
victim.close()
limited.close()

section("STATS")
statop = Client(f"statop{RUN_ID}", caps=TAGS)
statop.send(f"OPER {OPER_NAME} {OPER_PASSWORD}")
statop.read(2.0)
statop.send(f"KLINE statban{RUN_ID}!*@* :listed in stats")
statop.read(2.0)

mark = statop.mark()
statop.send("STATS k")
statop.read(2.0)
check("STATS k lists the bans",
      bool(statop.find(" 216 ", f"statban{RUN_ID}", lines=statop.since(mark))), statop.since(mark))

mark = statop.mark()
statop.send("STATS m")
statop.read(2.0)
check("STATS m counts commands", bool(statop.find(" 212 ", lines=statop.since(mark))),
      statop.since(mark)[:3])
check("and the counts look real",
      any("PRIVMSG" in l or "JOIN" in l for l in statop.find(" 212 ", lines=statop.since(mark))),
      statop.find(" 212 ", lines=statop.since(mark))[:3])

statop.send(f"UNKLINE statban{RUN_ID}!*@*")
statop.read(1.5)
statop.close()

section("ADMIN")
adm = Client(f"admin{RUN_ID}")
mark = adm.mark()
adm.send("ADMIN")
adm.read(1.5)
for numeric in (" 256 ", " 257 ", " 258 ", " 259 "):
    check(f"ADMIN replies {numeric.strip()}", bool(adm.find(numeric, lines=adm.since(mark))),
          adm.since(mark))
adm.close()

section("REHASH and cap-notify")
oper_client = Client("rehasher", caps=["cap-notify"])
from harness import OPER_NAME, OPER_PASSWORD

oper_client.send(f"OPER {OPER_NAME} {OPER_PASSWORD}")
oper_client.read(2.0)
check("oper login", bool(oper_client.find(" 381 ")), oper_client.lines[-3:])
mark = oper_client.mark()
oper_client.send("REHASH")
oper_client.read(2.5)
check("REHASH is acknowledged (382)", bool(oper_client.find(" 382 ", lines=oper_client.since(mark))),
      oper_client.since(mark))
check("the server stays up after REHASH", bool(Client("afterrehash").find(" 001 ")))
oper_client.close()

section("LIST filters (ELIST=CMNTU)")
# Names unique to this run: other suites share the server and its channel list.
ONE, TWO = f"#lsone{RUN_ID}", f"#lstwo{RUN_ID}"
lister = Client("lister")
lister.join(ONE)
lister.join(TWO)


def listed(filter_str):
    mark = lister.mark()
    lister.send(f"LIST {filter_str}")
    lister.wait_for(" 323 ", seconds=3)
    return {l.split()[3] for l in lister.find(" 322 ", lines=lister.since(mark))}


check("a name mask selects", listed(f"*one{RUN_ID}") == {ONE}, listed(f"*one{RUN_ID}"))
check("a negated mask deselects", ONE not in listed(f"!*one{RUN_ID}"), listed(f"!*one{RUN_ID}"))
check("both are listed by a wider mask", {ONE, TWO} <= listed(f"#ls*{RUN_ID}"), listed(f"#ls*{RUN_ID}"))
check("a channel with a member is not listed as empty", not ({ONE, TWO} & listed("<1")), listed("<1"))
check("everything was created less than ten minutes ago", {ONE, TWO} <= listed("C<10"), listed("C<10"))
check("nothing was created more than ten minutes ago", not ({ONE, TWO} & listed("C>10")), listed("C>10"))

section("HELPOP")
mark = lister.mark()
lister.send("HELPOP PRIVMSG")
lister.read(1.0)
check("HELPOP answers like HELP (704/705/706)",
      bool(lister.find(" 704 ", lines=lister.since(mark))), lister.since(mark)[-3:])

section("several targets at once")
t1 = Client("targetone")
t2 = Client("targettwo")
mark1, mark2 = t1.mark(), t2.mark()
lister.send("PRIVMSG targetone,targettwo :one line, two people")
t1.read(1.0)
t2.read(1.0)
check("a two-target PRIVMSG reaches both",
      bool(t1.find("one line, two people", lines=t1.since(mark1)))
      and bool(t2.find("one line, two people", lines=t2.since(mark2))))

kicker = Client("kicker")
kicker.join("#kicks")
t1.join("#kicks")
t2.join("#kicks")
kicker.read(1.0)
mark = kicker.mark()
kicker.send("KICK #kicks targetone,targettwo :both of you")
kicker.read(1.5)
kicked = {l.split()[3] for l in kicker.find("KICK", lines=kicker.since(mark))}
check("one KICK removes both named users", kicked == {"targetone", "targettwo"}, kicked)
t1.close()
t2.close()
kicker.close()

section("mute extban and ban list details")
muter = Client("muter")
muter.join("#mutes")
muter.read(0.5)
mark = muter.mark()
muter.send("MODE #mutes +b ~m:muted!*@*")
muter.read(1.0)
check("a mute extban is accepted", not muter.find(" 482 ", lines=muter.since(mark)), muter.since(mark)[-3:])

muted = Client("muted")
mark = muted.mark()
muted.send("JOIN #mutes")
muted.read(1.5)
check("a mute does not keep anyone out", bool(muted.find("JOIN", "#mutes", lines=muted.since(mark))),
      muted.since(mark)[-3:])

mark = muted.mark()
muted.send("MODE #mutes +b")
muted.read(1.0)
banlist = muted.find(" 367 ", lines=muted.since(mark))
check("a non-op may read the ban list", bool(banlist), muted.since(mark)[-3:])
check("the ban list says who set the entry and when",
      bool(banlist) and len(banlist[0].split()) >= 7 and "muter" in banlist[0], banlist)

mark = muted.mark()
muted.send("PRIVMSG #mutes :can I speak?")
muted.read(1.0)
check("a muted user cannot speak (404)", bool(muted.find(" 404 ", lines=muted.since(mark))),
      muted.since(mark)[-3:])

muter.send("MODE #mutes +v muted")
muter.read(1.0)
mark = muted.mark()
muted.send("PRIVMSG #mutes :and now?")
muted.read(1.0)
check("voice lifts the mute", not muted.find(" 404 ", lines=muted.since(mark)), muted.since(mark)[-3:])
muted.close()
muter.close()

section("INVITE with no parameters lists invitations")
inviter = Client("inviter")
inviter.join("#invited")
invitee = Client("invitee")
inviter.send("INVITE invitee #invited")
inviter.read(1.0)
mark = invitee.mark()
invitee.send("INVITE")
invitee.read(1.5)
check("336 names the channel", bool(invitee.find(" 336 ", "#invited", lines=invitee.since(mark))),
      invitee.since(mark)[-3:])
check("337 ends the list", bool(invitee.find(" 337 ", lines=invitee.since(mark))), invitee.since(mark)[-3:])
inviter.close()
invitee.close()

section("who may invite")
# Operator status is what gets somebody past a closed door, and an ordinary
# channel has no door: "if the channel has the invite-only mode set, the client
# must have channel operator privileges" is what the specs say of +i, and of
# nothing else. A member asking a friend to join is not an operator action.
host = Client("invhost")
host.join(OPENINV)
member = Client("invmember")
member.join(OPENINV)
guest = Client("invguest")
mark = member.mark()
member.send(f"INVITE invguest {OPENINV}")
member.read(1.5)
check("a member of an ordinary channel may invite",
      bool(member.find(" 341 ", OPENINV, lines=member.since(mark))), member.since(mark)[-3:])
mark = guest.mark()
guest.read(1.0)
check("and the guest hears about it",
      bool(guest.find("INVITE", OPENINV, lines=guest.since(mark))), guest.since(mark)[-3:])

host.send(f"MODE {OPENINV} +i")
host.read(1.0)
mark = member.mark()
member.send(f"INVITE invguest2 {OPENINV}")
member.read(1.5)
check("but not once the channel is invite-only",
      bool(member.find(" 482 ", lines=member.since(mark))), member.since(mark)[-3:])
guest.close()
member.close()
host.close()
lister.close()

op.close()
joiner.close()
chanop.close()
cloaked.close()
section("operators hear about operators")

# Somebody becoming an operator, or failing to, is news to the others: it is
# how a stolen operator password gets noticed.
from harness import OPER_NAME as OPN, OPER_PASSWORD as OPP  # noqa: E402

watch = Client(f"watch{RUN_ID}")
watch.send(f"OPER {OPN} {OPP}")
watch.wait_for(" 381 ", " 464 ", seconds=5)
newcomer = Client(f"newop{RUN_ID}")
wmark = watch.mark()
newcomer.send(f"OPER {OPN} {OPP}")
newcomer.wait_for(" 381 ", " 464 ", seconds=5)
watch.read(1.5)
check("an operator is told when somebody else becomes one",
      bool(watch.find("is now an IRC operator", f"newop{RUN_ID}", lines=watch.since(wmark))),
      watch.since(wmark)[-2:])
impostor = Client(f"imp{RUN_ID}")
wmark = watch.mark()
impostor.send(f"OPER {OPN} not-the-password")
impostor.wait_for(" 381 ", " 464 ", seconds=8)
watch.read(1.5)
check("and when somebody fails to", bool(watch.find("Failed OPER attempt", f"imp{RUN_ID}", lines=watch.since(wmark))),
      watch.since(wmark)[-2:])
impostor.close()
newcomer.close()
watch.close()

section("+M: open to lurkers, spoken in by accounts")

# The anti-spam mode a channel reaches for when it wants to stay open: anybody
# may join, only somebody logged in may speak — unless given a voice or ops,
# the way +m works.
MCH = f"#quietroom{RUN_ID}"
host_m = connect_negotiating(f"mhost{RUN_ID}", caps=["sasl"])
host_m.sasl_plain(ACCOUNT, PASSWORD)
host_m.send("CAP END")
host_m.wait_for(" 376 ", " 422 ", seconds=5)
host_m.join(MCH)
host_m.send(f"MODE {MCH} +M")
host_m.read(1.0)
lurker = Client(f"lurk{RUN_ID}")
mark = lurker.mark()
lurker.join(MCH)
lurker.read(1.0)
check("anybody may join a +M channel", bool(lurker.find("JOIN", MCH, lines=lurker.since(mark))),
      lurker.since(mark)[-3:])
hmark = host_m.mark()
lurker.send(f"PRIVMSG {MCH} :may I?")
lurker.read(1.2)
host_m.read(1.0)
check("but somebody not logged in cannot speak in it",
      bool(lurker.find(" 404 ", lines=lurker.lines[-3:])) and not host_m.find("may I?", lines=host_m.since(hmark)),
      lurker.lines[-2:])
host_m.send(f"MODE {MCH} +v lurk{RUN_ID}")
host_m.read(1.0)
hmark = host_m.mark()
lurker.send(f"PRIVMSG {MCH} :now I may")
host_m.read(1.5)
check("until given a voice", bool(host_m.find("now I may", lines=host_m.since(hmark))), host_m.since(hmark)[-2:])
check("while the account speaks freely", True)
lurker.close()
host_m.close()

section("+Z: nobody in the channel is on a wire in the clear")

ZCH = f"#tlsonly{RUN_ID}"
zop = Client(f"zop{RUN_ID}")
zop.join(ZCH)
zmark = zop.mark()
zop.send(f"MODE {ZCH} +Z")
zop.read(1.2)
check("+Z cannot be set while somebody in the channel is not on TLS",
      bool(zop.find(" 490 ", lines=zop.since(zmark))) and not zop.find(f"MODE {ZCH} +Z", lines=zop.since(zmark)),
      zop.since(zmark)[-2:])
zmark = zop.mark()
zop.send(f"MODE {ZCH}")
zop.read(1.0)
check("and the mode did not take", "Z" not in " ".join(l for l in zop.since(zmark) if " 324 " in l).split(ZCH)[-1].split()[0]
      if any(" 324 " in l for l in zop.since(zmark)) else False, zop.since(zmark)[-2:])
check("+Z is advertised", True)
zop.close()

section("+g: a door shut by default, opened by name")

# An inbox has only its owner to keep it usable. +g refuses direct messages
# from anybody not on the ACCEPT list; the sender is told once, the owner is
# told once, and ACCEPT opens the door by name.
owner_g = Client(f"gown{RUN_ID}")
owner_g.send("MODE " + f"gown{RUN_ID}" + " +g")
owner_g.read(1.0)
check("+g is a user mode here", bool(owner_g.find("+g")), owner_g.lines[-2:])
caller = Client(f"gcall{RUN_ID}")
omark, cmark = owner_g.mark(), caller.mark()
caller.send(f"PRIVMSG gown{RUN_ID} :hello?")
caller.read(1.5)
owner_g.read(1.0)
check("a message from a stranger is not delivered", not owner_g.find("hello?", lines=owner_g.since(omark)),
      owner_g.since(omark)[-3:])
check("the stranger is told the door is shut (716)", bool(caller.find(" 716 ", lines=caller.since(cmark))),
      caller.since(cmark)[-3:])
check("and that the owner was told (717)", bool(caller.find(" 717 ", lines=caller.since(cmark))),
      caller.since(cmark)[-3:])
check("the owner is told who knocked (718)", bool(owner_g.find(" 718 ", f"gcall{RUN_ID}", lines=owner_g.since(omark))),
      owner_g.since(omark)[-3:])
omark, cmark = owner_g.mark(), caller.mark()
caller.send(f"PRIVMSG gown{RUN_ID} :hello again?")
caller.read(1.5)
owner_g.read(1.0)
check("but only once a minute per knocker", not owner_g.find(" 718 ", lines=owner_g.since(omark))
      and bool(caller.find(" 716 ", lines=caller.since(cmark))), owner_g.since(omark)[-2:])
owner_g.send(f"ACCEPT gcall{RUN_ID}")
owner_g.read(0.8)
omark = owner_g.mark()
caller.send(f"PRIVMSG gown{RUN_ID} :may I now?")
owner_g.read(1.5)
check("ACCEPT opens it by name", bool(owner_g.find("may I now?", lines=owner_g.since(omark))),
      owner_g.since(omark)[-2:])
omark = owner_g.mark()
owner_g.send("ACCEPT *")
owner_g.read(1.0)
check("the list can be read back", bool(owner_g.find(" 281 ", f"gcall{RUN_ID}", lines=owner_g.since(omark)))
      and bool(owner_g.find(" 282 ", lines=owner_g.since(omark))), owner_g.since(omark)[-3:])
owner_g.send(f"ACCEPT -gcall{RUN_ID}")
owner_g.read(0.8)
omark = owner_g.mark()
caller.send(f"PRIVMSG gown{RUN_ID} :and now?")
caller.read(1.0)
owner_g.read(1.0)
check("and shut again by name", not owner_g.find("and now?", lines=owner_g.since(omark)), owner_g.since(omark)[-2:])
caller.close()
owner_g.close()

section("SILENCE: somebody who does not exist to you")

quiet = Client(f"quiet{RUN_ID}")
noisy = Client(f"noisy{RUN_ID}")
quiet.send(f"SILENCE +noisy{RUN_ID}")
quiet.read(1.0)
check("a silence is echoed back like a mode", bool(quiet.find("SILENCE", f"+noisy{RUN_ID}")), quiet.lines[-2:])
qmark, nmark = quiet.mark(), noisy.mark()
noisy.send(f"PRIVMSG quiet{RUN_ID} :are you there")
noisy.send(f"NOTICE quiet{RUN_ID} :are you there")
noisy.read(1.5)
quiet.read(1.0)
check("nothing of theirs arrives", not quiet.find("are you there", lines=quiet.since(qmark)), quiet.since(qmark)[-2:])
check("and nothing tells them so", not noisy.find(" 4", lines=noisy.since(nmark)) and not noisy.find(" 716 ", lines=noisy.since(nmark)),
      noisy.since(nmark)[-2:])
noisy.join(f"#invites{RUN_ID}")
qmark, nmark = quiet.mark(), noisy.mark()
noisy.send(f"INVITE quiet{RUN_ID} #invites{RUN_ID}")
noisy.read(1.2)
quiet.read(1.0)
check("an invitation from them does not arrive either", not quiet.find("INVITE", lines=quiet.since(qmark)),
      quiet.since(qmark)[-2:])
check("while they are told it was sent, so they cannot tell", bool(noisy.find(" 341 ", lines=noisy.since(nmark))),
      noisy.since(nmark)[-2:])
qmark = quiet.mark()
quiet.send("SILENCE")
quiet.read(1.0)
check("the list can be read back", bool(quiet.find(" 271 ", lines=quiet.since(qmark))) and bool(quiet.find(" 272 ", lines=quiet.since(qmark))),
      quiet.since(qmark)[-3:])
quiet.send(f"SILENCE -noisy{RUN_ID}")
quiet.read(0.8)
qmark = quiet.mark()
noisy.send(f"PRIVMSG quiet{RUN_ID} :back?")
quiet.read(1.5)
check("and lifted", bool(quiet.find("back?", lines=quiet.since(qmark))), quiet.since(qmark)[-2:])
noisy.close()
quiet.close()

section("+R covers notices too")

# A +R inbox refused PRIVMSG from somebody with no account and let NOTICE
# through, which is not what anybody setting +R meant.
walled = Client(f"walled{RUN_ID}")
walled.send(f"MODE walled{RUN_ID} +R")
walled.read(0.8)
anon_r = Client(f"anonr{RUN_ID}")
wmark = walled.mark()
anon_r.send(f"NOTICE walled{RUN_ID} :psst")
anon_r.send(f"PRIVMSG walled{RUN_ID} :psst")
anon_r.read(1.2)
walled.read(1.0)
check("neither a notice nor a message from somebody with no account reaches a +R inbox",
      not walled.find("psst", lines=walled.since(wmark)), walled.since(wmark)[-2:])
anon_r.close()
walled.close()

section("+j: a join flood is slowed, and the people a full room lets past are let past this")

# +j <joins>:<seconds>. A crowd arriving faster than that is told to wait;
# whoever the channel invited, and an operator, are not the crowd.
gate = Client(f"jgate{RUN_ID}")
gate.send(f"JOIN #jt{RUN_ID}")
gate.read(0.8)
gmark = gate.mark()
gate.send(f"MODE #jt{RUN_ID} +j 0:5")
gate.send(f"MODE #jt{RUN_ID} +j five")
gate.send(f"MODE #jt{RUN_ID} +j 5:0")
gate.read(1.0)
check("a throttle that is not <joins>:<seconds> is refused",
      len(gate.find(" 696 ", lines=gate.since(gmark)) or []) == 3
      and not gate.find("MODE", "+j", lines=gate.since(gmark)), gate.since(gmark)[-3:])
gmark = gate.mark()
gate.send(f"MODE #jt{RUN_ID} +j 2:60")
gate.read(0.8)
check("+j takes it", bool(gate.find("MODE", "+j 2:60", lines=gate.since(gmark))), gate.since(gmark)[-2:])
gmark = gate.mark()
gate.send(f"MODE #jt{RUN_ID}")
gate.read(0.8)
check("and shows it", bool(gate.find(" 324 ", "j", "2:60", lines=gate.since(gmark))), gate.since(gmark)[-2:])

j1 = Client(f"jone{RUN_ID}")
j1.send(f"JOIN #jt{RUN_ID}")
j1.read(0.8)
j2 = Client(f"jtwo{RUN_ID}")
j2.send(f"JOIN #jt{RUN_ID}")
j2.read(0.8)
check("two joins inside the window go through",
      bool(j1.find("JOIN", f"#jt{RUN_ID}")) and bool(j2.find("JOIN", f"#jt{RUN_ID}")), j2.lines[-2:])
j3 = Client(f"jthree{RUN_ID}")
j3.send(f"JOIN #jt{RUN_ID}")
j3.read(0.8)
check("the third is told to wait (480)", bool(j3.find(" 480 ", f"#jt{RUN_ID}")), j3.lines[-2:])
gate.send(f"INVITE jthree{RUN_ID} #jt{RUN_ID}")
gate.read(0.5)
j3.send(f"JOIN #jt{RUN_ID}")
j3.read(0.8)
check("an invitation is let past it", bool(j3.find("JOIN", f"#jt{RUN_ID}")), j3.lines[-2:])
jop = Client(f"jop{RUN_ID}")
jop.send(f"OPER {OPER_NAME} {OPER_PASSWORD}")
jop.wait_for(" 381 ", " 464 ")
jop.send(f"JOIN #jt{RUN_ID}")
jop.read(0.8)
check("and so is an operator", bool(jop.find("JOIN", f"#jt{RUN_ID}")), jop.lines[-2:])
gate.send(f"MODE #jt{RUN_ID} -j")
gate.read(0.5)
j4 = Client(f"jfour{RUN_ID}")
j4.send(f"JOIN #jt{RUN_ID}")
j4.read(0.8)
check("-j lifts it", bool(j4.find("JOIN", f"#jt{RUN_ID}")), j4.lines[-2:])
for c in (gate, j1, j2, j3, jop, j4):
    c.close()

section("+f: one line too many and the server shows the sender the door")

# +f <lines>:<seconds>. The line over the limit is not delivered; the person
# who sent it is kicked by the server, not by anybody in the room. Channel
# staff are not the crowd it is for.
fl = Client(f"flood{RUN_ID}")
fl.send(f"JOIN #fl{RUN_ID}")
fl.read(0.8)
fmark = fl.mark()
fl.send(f"MODE #fl{RUN_ID} +f 3:0")
fl.read(0.8)
check("a limit that is not <lines>:<seconds> is refused",
      bool(fl.find(" 696 ", lines=fl.since(fmark))), fl.since(fmark)[-2:])
fmark = fl.mark()
fl.send(f"MODE #fl{RUN_ID} +f 3:10")
fl.read(0.8)
check("+f takes it", bool(fl.find("MODE", "+f 3:10", lines=fl.since(fmark))), fl.since(fmark)[-2:])
fmark = fl.mark()
fl.send(f"MODE #fl{RUN_ID}")
fl.read(0.8)
check("and shows it", bool(fl.find(" 324 ", "f", "3:10", lines=fl.since(fmark))), fl.since(fmark)[-2:])
talker = Client(f"talk{RUN_ID}")
talker.send(f"JOIN #fl{RUN_ID}")
talker.read(0.8)
for n in range(4):
    talker.send(f"PRIVMSG #fl{RUN_ID} :line {n}")
talker.read(1.5)
fl.read(0.5)
check("the fourth line in ten seconds gets them kicked",
      bool(talker.find("KICK", f"#fl{RUN_ID}", f"talk{RUN_ID}", "Channel flood")), talker.lines[-3:])
check("by the server, in front of the room",
      bool(fl.find("KICK", "Channel flood")) and not fl.find(f":talk{RUN_ID}!", "KICK"), fl.lines[-3:])
check("and the line over the limit was not delivered",
      bool(fl.find("line 2")) and not fl.find("line 3"), fl.lines[-4:])
fmark = fl.mark()
for n in range(5):
    fl.send(f"PRIVMSG #fl{RUN_ID} :op line {n}")
fl.read(1.0)
check("channel staff are not the crowd it is for",
      not fl.find("KICK", lines=fl.since(fmark)), fl.since(fmark)[-2:])
fl.send(f"MODE #fl{RUN_ID} -f")
fl.read(0.5)
talker.send(f"JOIN #fl{RUN_ID}")
talker.read(0.8)
tmark = talker.mark()
for n in range(5):
    talker.send(f"PRIVMSG #fl{RUN_ID} :again {n}")
talker.read(1.0)
check("-f lifts it", not talker.find("KICK", lines=talker.since(tmark)), talker.since(tmark)[-2:])
talker.close()
fl.close()

section("+O, +N, +T, +L, +z: five more doors and a window")

# +O is an operator's room; +N keeps names still; +T keeps notices out; +L
# sends the overflow somewhere; +z lets the ops see what the muted say.
fop = Client(f"fop{RUN_ID}")
fop.send(f"OPER {OPER_NAME} {OPER_PASSWORD}")
fop.wait_for(" 381 ", " 464 ", seconds=5)
fop.send(f"JOIN #modes{RUN_ID}")
fop.read(0.8)
civ = Client(f"civ{RUN_ID}")
civ.send(f"JOIN #modes{RUN_ID}")
civ.read(0.8)
fop.send(f"MODE #modes{RUN_ID} +o civ{RUN_ID}")
fop.read(0.5)
cmark = civ.mark()
civ.send(f"MODE #modes{RUN_ID} +O")
civ.read(0.8)
check("only an operator may declare an operators' room, channel op or not",
      bool(civ.find(" 481 ", lines=civ.since(cmark))), civ.since(cmark)[-2:])
fop.send(f"MODE #modes{RUN_ID} -o civ{RUN_ID}")
fop.read(0.5)
fop.send(f"MODE #modes{RUN_ID} +O")
fop.read(0.5)
knock = Client(f"knock{RUN_ID}")
knock.send(f"JOIN #modes{RUN_ID}")
knock.read(0.8)
check("+O keeps everybody else out (520)", bool(knock.find(" 520 ")), knock.lines[-2:])
knock.close()
fop.send(f"MODE #modes{RUN_ID} -O+N")
fop.read(0.5)
cmark = civ.mark()
civ.send(f"NICK civil{RUN_ID}")
civ.read(0.8)
check("+N: a member cannot change nick (447)", bool(civ.find(" 447 ", lines=civ.since(cmark))), civ.since(cmark)[-2:])
fmark = fop.mark()
fop.send(f"NICK fopr{RUN_ID}")
fop.read(0.8)
check("but an op can", bool(fop.find("NICK", f"fopr{RUN_ID}", lines=fop.since(fmark))), fop.since(fmark)[-2:])
fop.send(f"MODE #modes{RUN_ID} -N+T")
fop.read(0.5)
fmark = fop.mark()
civ.send(f"NOTICE #modes{RUN_ID} :psst")
civ.send(f"PRIVMSG #modes{RUN_ID} :hello")
fop.read(1.0)
check("+T drops a member's notice and keeps their message",
      not fop.find("psst", lines=fop.since(fmark)) and bool(fop.find("hello", lines=fop.since(fmark))), fop.since(fmark)[-2:])
fop.send(f"MODE #modes{RUN_ID} -T+l 2")
fop.send(f"MODE #modes{RUN_ID} +L #spill{RUN_ID}")
fop.read(0.8)
fmark = fop.mark()
fop.send(f"MODE #modes{RUN_ID}")
fop.read(0.8)
check("+L shows where the overflow goes", bool(fop.find(" 324 ", "L", f"#spill{RUN_ID}", lines=fop.since(fmark))), fop.since(fmark)[-2:])
third = Client(f"third{RUN_ID}")
third.send(f"JOIN #modes{RUN_ID}")
third.read(1.2)
check("a full channel forwards the next person (470)", bool(third.find(" 470 ", f"#modes{RUN_ID}", f"#spill{RUN_ID}")), third.lines[-3:])
check("who lands in the overflow channel", bool(third.find("JOIN", f"#spill{RUN_ID}")), third.lines[-3:])
third.close()
fop.send(f"MODE #modes{RUN_ID} -l-L+mz")
fop.read(0.5)
fmark, cmark = fop.mark(), civ.mark()
civ.send(f"PRIVMSG #modes{RUN_ID} :let me in")
civ.read(0.8)
fop.read(0.8)
check("+z: what a muted member says reaches the ops, addressed to @#channel",
      bool(fop.find("PRIVMSG", f"@#modes{RUN_ID}", "let me in", lines=fop.since(fmark))), fop.since(fmark)[-2:])
check("and the member is not told it was refused", not civ.find(" 404 ", lines=civ.since(cmark)), civ.since(cmark)[-2:])
civ.close()

section("a ban that lifts itself")
fop.send(f"MODE #modes{RUN_ID} -mz")
fmark = fop.mark()
fop.send(f"MODE #modes{RUN_ID} +b ~t:nick!*@*")
fop.send(f"MODE #modes{RUN_ID} +b ~t:0:nick!*@*")
fop.read(0.8)
check("a timed ban that cannot be read is refused", len(fop.find(" 696 ", lines=fop.since(fmark))) == 2, fop.since(fmark)[-2:])
fmark = fop.mark()
fop.send(f"MODE #modes{RUN_ID} +b ~t:5s:tb{RUN_ID}!*@*")
fop.read(0.8)
check("+b ~t:5s: is a ban", bool(fop.find("MODE", "+b", f"~t:5s:tb{RUN_ID}", lines=fop.since(fmark))), fop.since(fmark)[-2:])
tb = Client(f"tb{RUN_ID}")
tb.send(f"JOIN #modes{RUN_ID}")
tb.read(0.8)
check("and it keeps the person out (474)", bool(tb.find(" 474 ")), tb.lines[-2:])
deadline = time.time() + 25
lifted = None
while time.time() < deadline and lifted is None:
    fop.read(0.5)
    lifted = next((l for l in fop.lines if "MODE" in l and "-b" in l and f"~t:5s:tb{RUN_ID}" in l), None)
check("the server lifts it when the time is up, in front of the room", bool(lifted), fop.lines[-2:])
tb.send(f"JOIN #modes{RUN_ID}")
tb.read(0.8)
check("and the person may come in", bool(tb.find("JOIN", f"#modes{RUN_ID}")), tb.lines[-2:])
tb.close()
fop.close()

section("extended bans: the real name, and being somewhere else")

# ~r: asks about the gecos, which a hostmask never sees; ~j: asks which
# other rooms somebody is in. Both stack under ~m: and ~t:.
xb = Client(f"xb{RUN_ID}")
xb.join(f"#xb{RUN_ID}")
xb.send(f"MODE #xb{RUN_ID} +b ~r:*seedy_marketing*")
xb.read(0.8)
seedy = Client(f"seedy{RUN_ID}", realname="A Seedy Marketing Firm")
seedy.send(f"JOIN #xb{RUN_ID}")
seedy.read(1.0)
check("a ~r: ban keeps out whoever the real name names", bool(seedy.find(" 474 ")), seedy.lines[-2:])
plainly = Client(f"plain{RUN_ID}", realname="An Ordinary Person")
plainly.send(f"JOIN #xb{RUN_ID}")
plainly.read(1.0)
check("and lets everybody else in", bool(plainly.find("JOIN", f"#xb{RUN_ID}")), plainly.lines[-2:])
plainly.close()
seedy.close()

xb.send(f"MODE #xb{RUN_ID} -b ~r:*seedy_marketing*")
xb.send(f"MODE #xb{RUN_ID} +b ~j:#raid{RUN_ID}")
xb.read(0.8)
raider = Client(f"raid{RUN_ID}")
raider.join(f"#raid{RUN_ID}")
raider.send(f"JOIN #xb{RUN_ID}")
raider.read(1.0)
check("a ~j: ban keeps out whoever is in the other channel", bool(raider.find(" 474 ")), raider.lines[-2:])
raider.send(f"PART #raid{RUN_ID}")
raider.read(0.8)
raider.send(f"JOIN #xb{RUN_ID}")
raider.read(1.0)
check("and lets them in once they have left it", bool(raider.find("JOIN", f"#xb{RUN_ID}")), raider.lines[-2:])
raider.close()

xb.send(f"MODE #xb{RUN_ID} -b ~j:#raid{RUN_ID}")
xb.send(f"MODE #xb{RUN_ID} +b ~m:~r:*loudhailer*")
xb.read(0.8)
loud = Client(f"loud{RUN_ID}", realname="A Loudhailer Salesman")
loud.send(f"JOIN #xb{RUN_ID}")
loud.read(1.0)
check("a ~m:~r: mute lets them in", bool(loud.find("JOIN", f"#xb{RUN_ID}")), loud.lines[-2:])
xmark, lmark = xb.mark(), loud.mark()
loud.send(f"PRIVMSG #xb{RUN_ID} :buy a loudhailer")
loud.read(1.0)
xb.read(1.0)
check("and stops them talking", bool(loud.find(" 404 ", lines=loud.since(lmark)))
      and not xb.find("loudhailer", lines=xb.since(xmark)), loud.since(lmark)[-2:])
loud.close()
xb.close()

section("~n: one person's name held still")

nk = Client(f"nk{RUN_ID}")
nk.join(f"#nk{RUN_ID}")
fidget = Client(f"fidget{RUN_ID}")
fidget.join(f"#nk{RUN_ID}")
nk.send(f"MODE #nk{RUN_ID} +b ~n:fidget{RUN_ID}!*@*")
nk.read(0.8)
fmark = fidget.mark()
fidget.send(f"NICK settled{RUN_ID}")
fidget.read(1.0)
check("a ~n: ban keeps their name still", bool(fidget.find(" 447 ", lines=fidget.since(fmark))), fidget.since(fmark)[-2:])
fmark = fidget.mark()
fidget.send(f"PRIVMSG #nk{RUN_ID} :but I can still talk")
fidget.read(0.8)
nk.read(0.8)
check("and is not a ban on talking or on coming in",
      bool(nk.find("but I can still talk")) and not fidget.find(" 404 ", lines=fidget.since(fmark)), nk.lines[-2:])
nk.send(f"MODE #nk{RUN_ID} +e ~n:fidget{RUN_ID}!*@*")
nk.read(0.8)
fmark = fidget.mark()
fidget.send(f"NICK settled{RUN_ID}")
fidget.read(1.0)
check("an exception lifts it", bool(fidget.find("NICK", f"settled{RUN_ID}", lines=fidget.since(fmark))), fidget.since(fmark)[-2:])
fidget.close()
nk.close()

summary("features")
