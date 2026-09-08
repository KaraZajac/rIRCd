#!/usr/bin/env python3
"""Server features beyond the core protocol: SCRAM, history cursors, bans,
cloaking, WEBIRC, auto-join, monitor patterns, read markers and REHASH."""

import base64
import hashlib
import hmac
import time

from harness import RUN_ID, Client, check, connect_negotiating, db, section, summary

PASSWORD = "hunter2secret"
ACCOUNT = f"scram{RUN_ID}"
HISTORY = f"#history{RUN_ID}"
BANS = f"#bans{RUN_ID}"
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
setup.read(2.5)
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

op.close()
joiner.close()
chanop.close()
cloaked.close()
summary("features")
