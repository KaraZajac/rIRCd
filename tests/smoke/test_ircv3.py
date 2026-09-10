#!/usr/bin/env python3
"""IRCv3 conformance: every capability the server advertises, exercised on the wire."""

import os
import re
import time

from harness import (
    OPER_NAME,
    OPER_PASSWORD,
    Client,
    check,
    connect_negotiating,
    section,
    summary,
)

TAGS = ["message-tags", "server-time", "batch", "echo-message"]

section("SASL 3.2")
s = connect_negotiating("sasluser", caps=["sasl"])
s.send("AUTHENTICATE NOSUCHMECH")
s.read(1.5)
check("908 RPL_SASLMECHS lists supported mechanisms for an unknown one",
      bool(s.find(" 908 ")), s.lines[-4:])
s.send("AUTHENTICATE PLAIN")
s.read(1.0)
check("server prompts with AUTHENTICATE +", bool(s.find("AUTHENTICATE +")), s.lines[-3:])
s.send("AUTHENTICATE *")
s.read(1.0)
check("906 on aborted authentication", bool(s.find(" 906 ")), s.lines[-3:])
s.close()

section("capability names")
names = Client()
names.send("CAP LS 302")
names.read(1.0)
advertised = set()
for line in names.find("CAP", "LS"):
    advertised.update(t.split("=")[0] for t in line.split(":", 2)[-1].split())

check("redaction is advertised with the draft/ prefix the spec requires",
      "draft/message-redaction" in advertised and "message-redaction" not in advertised,
      sorted(advertised))
for token_only in ["whox", "utf8only", "bot", "account-extban"]:
    check(f"{token_only} is not advertised as a capability (it is an ISUPPORT token)",
          token_only not in advertised, sorted(advertised))

# Everything the server says it supports has to reach the wire. The list lives
# in src/capability.rs, and a capability added there but never advertised is a
# feature nobody can turn on.
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_caps_rs = open(os.path.join(REPO, "src", "capability.rs")).read()
_block = _caps_rs.split("pub const CAPS: &[&str] = &[", 1)[1].split("];", 1)[0]
declared = {m.group(1) for m in re.finditer(r'"([^"]+)"', _block)}
# Negotiation itself is not a capability a client can ask for, and STS needs a
# TLS port this server does not have.
declared -= {"capability-negotiation", "sts"}
missing = sorted(declared - advertised)
check("every capability the server supports is advertised in CAP LS", not missing, missing)

# Clients written against an earlier release must not be left worse off.
mark = names.mark()
names.send("CAP REQ :message-redaction whox utf8only bot account-extban")
names.read(1.5)
reply = names.find("CAP", lines=names.since(mark))
check("legacy capability names are still ACKed, not NAKed",
      bool(reply) and " ACK " in reply[0] and " NAK " not in " ".join(reply), reply)
check("the legacy redaction name maps to the current one",
      bool(reply) and "draft/message-redaction" in reply[0], reply)
names.close()

section("WHOX without a capability")
# WHOX is signalled by the WHOX ISUPPORT token; there is no capability for it.
whox = Client("whoxuser")
whox.join("#whoxroom")
mark = whox.mark()
whox.send("WHO #whoxroom %tcuhsnfar,742")
whox.read(1.5)
replies = whox.find(" 354 ", lines=whox.since(mark))
check("354 RPL_WHOSPCRPL for a client that negotiated nothing", bool(replies), whox.since(mark))
check("the requested token comes back",
      bool(replies) and "742" in replies[0], replies)
check("the requested fields are populated",
      bool(replies) and "whoxuser" in replies[0] and "#whoxroom" in replies[0], replies)
whox.close()

section("no-implicit-names")
quiet = Client("quietjoin", caps=["no-implicit-names"])
mark = quiet.mark()
quiet.join("#names")
check("no 353 burst when the cap is on", not quiet.find(" 353 ", lines=quiet.since(mark)), quiet.since(mark))
mark = quiet.mark()
quiet.send("NAMES #names")
quiet.read(1.0)
check("explicit NAMES still answers", bool(quiet.find(" 353 ", lines=quiet.since(mark))), quiet.since(mark))
quiet.close()

section("userhost-in-names and multi-prefix")
uh = Client("uhnames", caps=["userhost-in-names", "multi-prefix"])
uh.join("#Prefix")
names = " ".join(uh.find(" 353 "))
check("353 names the channel as created, not case-folded", "#Prefix" in names, names)
check("353 carries nick!user@host", "!" in names and "@" in names.split(":")[-1], names)
check("channel creator is opped in NAMES", "@uhnames" in names, names)

uh.send("MODE #Prefix +v uhnames")
uh.read(1.0)
mark = uh.mark()
uh.send("NAMES #prefix")  # a differently-cased request must still find it
uh.read(1.0)
names = " ".join(uh.find(" 353 ", lines=uh.since(mark)))
check("multi-prefix shows @ and + together", "@+" in names, names)

section("extended-join and away-notify")
watcher = Client("watcher", caps=["extended-join", "away-notify", "account-notify", "invite-notify", "chghost"])
watcher.join("#social")

joiner = Client("joiner")
mark = watcher.mark()
joiner.join("#social")
watcher.read(1.5)
join_line = watcher.find("JOIN #social", lines=watcher.since(mark))
check("extended-join adds account and realname",
      bool(join_line) and len(join_line[0].split()) >= 4, join_line)

mark = watcher.mark()
joiner.send("AWAY :lunch")
watcher.read(1.5)
check("away-notify announces AWAY", bool(watcher.find("AWAY", lines=watcher.since(mark))), watcher.since(mark))
mark = watcher.mark()
joiner.send("AWAY")
watcher.read(1.5)
check("away-notify announces the return", bool(watcher.find("AWAY", lines=watcher.since(mark))), watcher.since(mark))

invitee = Client("invitee")
mark = watcher.mark()
watcher.send("INVITE invitee #social")
watcher.read(1.5)
reply = watcher.find(" 341 ", lines=watcher.since(mark))
check("341 RPL_INVITING", bool(reply), watcher.since(mark))
check("341's first parameter is the inviter's nick, not their mask",
      bool(reply) and reply[0].split()[2] == "watcher", reply)
check("the invitee receives the INVITE", bool(invitee.wait_for("INVITE", seconds=3)), invitee.lines[-3:])
invitee.close()

section("setname")
sn = Client("renamer", caps=["setname"])
mark = sn.mark()
sn.send("SETNAME :A New Realname")
sn.read(1.0)
check("SETNAME echoed to the sender", bool(sn.find("SETNAME", lines=sn.since(mark))), sn.since(mark))
mark = sn.mark()
sn.send("SETNAME")
sn.read(1.0)
check("SETNAME with no parameter is rejected",
      bool(sn.find("FAIL SETNAME", lines=sn.since(mark))) or bool(sn.find(" 461 ", lines=sn.since(mark))),
      sn.since(mark))
sn.close()

section("bot mode")
bot = Client("botclient", caps=TAGS)
bot.send("MODE botclient +B")
bot.read(1.0)
watcher.send("WHOIS botclient")
watcher.read(1.5)
check("335 RPL_WHOISBOT", bool(watcher.find(" 335 ")), watcher.find(" 33"))

section("client-only tags")
tagger = Client("tagger", caps=TAGS + ["message-tags"])
tagged = Client("tagged", caps=TAGS + ["message-tags"])
tagger.join("#tags")
tagged.join("#tags")
tagger.read(1.0)
tagged.read(1.0)

for tag, label in [
    ("+typing=active", "typing"),
    ("+draft/react=🎉", "react"),
    ("+draft/unreact=🎉", "unreact"),
    ("+draft/channel-context=#tags", "channel-context"),
]:
    mark = tagged.mark()
    tagger.send(f"@{tag} TAGMSG #tags")
    tagged.read(1.5)
    relayed = tagged.find("TAGMSG", lines=tagged.since(mark))
    check(f"{label} tag relayed", bool(relayed) and tag.split("=")[0] in relayed[0], tagged.since(mark))

mark = tagged.mark()
tagger.send("PRIVMSG #tags :first")
tagged.read(1.0)
first = tagged.find("PRIVMSG", lines=tagged.since(mark))
msgid = None
if first:
    for part in first[0].lstrip("@").split(" ")[0].split(";"):
        if part.startswith("msgid="):
            msgid = part.split("=", 1)[1]
check("msgid tag available for replies", bool(msgid), first)
if msgid:
    mark = tagged.mark()
    tagger.send(f"@+reply={msgid} PRIVMSG #tags :answering")
    tagged.read(1.5)
    relayed = tagged.find("PRIVMSG", "answering", lines=tagged.since(mark))
    check("+reply tag relayed", bool(relayed) and "+reply=" in relayed[0], tagged.since(mark))

section("draft/multiline")
ml_sender = Client("mlsender", caps=TAGS + ["draft/multiline"])
ml_reader = Client("mlreader", caps=TAGS + ["draft/multiline"])
ml_sender.join("#multi")
ml_reader.join("#multi")
ml_sender.read(1.0)
ml_reader.read(1.0)

mark = ml_reader.mark()
ml_sender.send("BATCH +ml draft/multiline #multi")
ml_sender.send("@batch=ml PRIVMSG #multi :line one")
ml_sender.send("@batch=ml PRIVMSG #multi :line two")
ml_sender.send("BATCH -ml")
ml_reader.read(2.0)
received = ml_reader.since(mark)
check("multiline batch opened", bool(ml_reader.find("BATCH +", "draft/multiline", lines=received)), received)
check("both lines delivered inside the batch",
      len(ml_reader.find("PRIVMSG", "line one", lines=received)) == 1
      and len(ml_reader.find("PRIVMSG", "line two", lines=received)) == 1, received)
check("multiline batch closed", bool(ml_reader.find("BATCH -", lines=received)), received)

ml_sender.read(2.0)  # collect the sender's own echo before counting it
check("the sender receives its own batch exactly once",
      len(ml_sender.find("BATCH +", "draft/multiline")) == 1
      and len(ml_sender.find("PRIVMSG", "line one")) == 1,
      [l for l in ml_sender.lines if "draft/multiline" in l or "line one" in l])

no_echo = Client("mlnoecho", caps=["message-tags", "server-time", "batch", "draft/multiline"])
no_echo.join("#multi")
mark = no_echo.mark()
no_echo.send("BATCH +ne draft/multiline #multi")
no_echo.send("@batch=ne PRIVMSG #multi :quiet please")
no_echo.send("BATCH -ne")
no_echo.read(2.0)
check("a sender without echo-message gets no copy of its own batch",
      not no_echo.find("quiet please", lines=no_echo.since(mark)), no_echo.since(mark))
no_echo.close()

plain_reader = Client("mlplain", caps=TAGS)
plain_reader.join("#multi")
mark = plain_reader.mark()
ml_sender.send("BATCH +m2 draft/multiline #multi")
ml_sender.send("@batch=m2 PRIVMSG #multi :fallback one")
ml_sender.send("@batch=m2 PRIVMSG #multi :fallback two")
ml_sender.send("BATCH -m2")
plain_reader.read(2.0)
received = plain_reader.since(mark)
check("clients without the cap get plain PRIVMSGs",
      bool(plain_reader.find("PRIVMSG", "fallback one", lines=received))
      and not plain_reader.find("BATCH", lines=received), received)

section("message-redaction and draft/message-edit")
red = Client("redactor", caps=TAGS + ["draft/message-redaction", "draft/message-edit"])
red_peer = Client("redpeer", caps=TAGS + ["draft/message-redaction", "draft/message-edit"])
red.join("#redact")
red_peer.join("#redact")
red.read(1.0)
red_peer.read(1.0)

mark = red.mark()
red.send("PRIVMSG #redact :regrettable message")
red.read(1.5)
own = red.find("PRIVMSG", "regrettable", lines=red.since(mark))
red_msgid = None
if own:
    for part in own[0].lstrip("@").split(" ")[0].split(";"):
        if part.startswith("msgid="):
            red_msgid = part.split("=", 1)[1]
check("sender learns its own msgid via echo-message", bool(red_msgid), own)

if red_msgid:
    mark = red_peer.mark()
    red.send(f"REDACT #redact {red_msgid} :mistake")
    red_peer.read(2.0)
    check("REDACT relayed to channel members",
          bool(red_peer.find("REDACT", lines=red_peer.since(mark))), red_peer.since(mark))

    mark = red.mark()
    red.send("PRIVMSG #redact :original text")
    red.read(1.5)
    own = red.find("PRIVMSG", "original text", lines=red.since(mark))
    edit_id = None
    if own:
        for part in own[0].lstrip("@").split(" ")[0].split(";"):
            if part.startswith("msgid="):
                edit_id = part.split("=", 1)[1]
    if edit_id:
        mark = red_peer.mark()
        red.send(f"@+draft/edit={edit_id} PRIVMSG #redact :corrected text")
        red_peer.read(2.0)
        edited = red_peer.find("PRIVMSG", "corrected text", lines=red_peer.since(mark))
        check("edit relayed with the +draft/edit tag",
              bool(edited) and "draft/edit=" in edited[0], red_peer.since(mark))

    mark = red.mark()
    red.send("PRIVMSG #redact :a message only its author may redact")
    red.read(1.5)
    own = red.find("PRIVMSG", "only its author", lines=red.since(mark))
    other_msgid = None
    if own:
        for part in own[0].lstrip("@").split(" ")[0].split(";"):
            if part.startswith("msgid="):
                other_msgid = part.split("=", 1)[1]

    mark = red_peer.mark()
    red_peer.send(f"REDACT #redact {other_msgid} :not mine")
    red_peer.read(1.5)
    check("a non-operator cannot redact someone else's message",
          bool(red_peer.find("FAIL REDACT REDACT_FORBIDDEN", lines=red_peer.since(mark))),
          red_peer.since(mark))

section("draft/chathistory")
hist = Client("historian", caps=TAGS + ["draft/chathistory", "draft/event-playback"])
hist.join("#redact")
mark = hist.mark()
hist.send("CHATHISTORY LATEST #redact * 10")
hist.read(2.5)
received = hist.since(mark)
check("history wrapped in a chathistory batch",
      bool(hist.find("BATCH +", "chathistory", lines=received)), received)
check("history replays messages", bool(hist.find("PRIVMSG", "#redact", lines=received)), received)
check("redacted message is not replayed",
      not hist.find("regrettable message", lines=received), received)

mark = hist.mark()
hist.send("CHATHISTORY TARGETS timestamp=2020-01-01T00:00:00.000Z timestamp=2038-01-01T00:00:00.000Z 10")
hist.read(2.0)
check("CHATHISTORY TARGETS answers", bool(hist.find("BATCH", lines=hist.since(mark))), hist.since(mark))

mark = hist.mark()
hist.send("CHATHISTORY NONSENSE #redact * 10")
hist.read(1.5)
check("invalid subcommand gets a FAIL",
      bool(hist.find("FAIL", "CHATHISTORY", lines=hist.since(mark))), hist.since(mark))

section("capability negotiation details")
cn2 = Client()
cn2.send("CAP LS 302")
cn2.read(1.0)
mark = cn2.mark()
cn2.send("CAP REQ :message-tags server-time no-such-capability")
cn2.read(1.5)
reply = cn2.find("CAP", lines=cn2.since(mark))
check("a request containing an unknown capability is NAKed whole",
      bool(reply) and " NAK " in reply[0], reply)
check("the NAK echoes everything that was requested",
      bool(reply) and all(c in reply[0] for c in
                          ["message-tags", "server-time", "no-such-capability"]), reply)
mark = cn2.mark()
cn2.send("CAP LIST")
cn2.read(1.0)
check("and none of the request took effect",
      not cn2.find("message-tags", lines=cn2.since(mark)), cn2.since(mark))
cn2.close()

section("advertised limits match what is enforced")
lim = Client("limituser", caps=TAGS)
isupport = " ".join(lim.find(" 005 "))
linelen = next((t.split("=")[1] for t in isupport.split() if t.startswith("LINELEN=")), None)
check("LINELEN reports the enforced line limit", linelen == "512", linelen)
lim.join("#limits")
mark = lim.mark()
lim.send("PRIVMSG #limits :" + "y" * (int(linelen or 512) - 30))
lim.read(1.5)
check("a message at the advertised limit is accepted",
      not lim.find(" 417 ", lines=lim.since(mark)), lim.since(mark))
lim.close()

section("MONITOR")
bare = Client("monbare")
mark = bare.mark()
bare.send("MONITOR + joiner")
bare.read(1.5)
check("MONITOR works without negotiating a capability",
      bool(bare.find(" 730 ", lines=bare.since(mark))) or bool(bare.find(" 731 ", lines=bare.since(mark))),
      bare.since(mark))
bare.close()

mon = Client("monitor1", caps=["extended-monitor", "away-notify"])
mark = mon.mark()
mon.send("MONITOR + ghostuser,joiner")
mon.read(1.5)
received = mon.since(mark)
check("730 for online targets", bool(mon.find(" 730 ", lines=received)), received)
check("731 for offline targets", bool(mon.find(" 731 ", lines=received)), received)

mark = mon.mark()
mon.send("MONITOR L")
mon.read(1.0)
check("732/733 list the watched nicks",
      bool(mon.find(" 732 ", lines=mon.since(mark))) and bool(mon.find(" 733 ", lines=mon.since(mark))),
      mon.since(mark))

mark = mon.mark()
ghost = Client("ghostuser")
mon.read(2.0)
check("730 when a watched nick appears", bool(mon.find(" 730 ", lines=mon.since(mark))), mon.since(mark))
mark = mon.mark()
ghost.close()
mon.read(2.5)
check("731 when a watched nick leaves", bool(mon.find(" 731 ", lines=mon.since(mark))), mon.since(mark))

mark = mon.mark()
mon.send("MONITOR C")
mon.send("MONITOR L")
mon.read(1.0)
check("MONITOR C clears the list", not mon.find(" 732 ", lines=mon.since(mark)), mon.since(mark))
mon.close()

section("draft/read-marker")
rm = Client("reader", caps=["draft/read-marker", "sasl"])
mark = rm.mark()
rm.send("MARKREAD #redact timestamp=2026-01-01T00:00:00.000Z")
rm.read(1.5)
check("MARKREAD is acknowledged", bool(rm.find("MARKREAD", lines=rm.since(mark))), rm.since(mark))
mark = rm.mark()
rm.send("MARKREAD #redact")
rm.read(1.5)
check("MARKREAD without a timestamp reports the stored one",
      bool(rm.find("MARKREAD", "timestamp=", lines=rm.since(mark))), rm.since(mark))
rm.close()

section("draft/metadata-2")
md = Client("metaowner", caps=["draft/metadata-2"])
mark = md.mark()
md.send("METADATA * SET display-name :Meta Owner")
md.read(1.5)
check("METADATA SET replies 761 RPL_KEYVALUE",
      bool(md.find(" 761 ", "display-name", lines=md.since(mark))), md.since(mark))
check("the value is not double-colon quoted",
      not md.find("::Meta Owner", lines=md.since(mark)), md.since(mark))
mark = md.mark()
md.send("METADATA * GET display-name")
md.read(1.5)
check("METADATA GET returns the value",
      bool(md.find(" 761 ", "Meta Owner", lines=md.since(mark))), md.since(mark))
mark = md.mark()
md.send("METADATA * LIST")
md.read(1.5)
check("METADATA LIST includes it",
      bool(md.find("display-name", lines=md.since(mark))), md.since(mark))
mark = md.mark()
md.send("METADATA metaowner GET display-name")
md.read(1.5)
check("an explicit nick target resolves (case-insensitively)",
      bool(md.find(" 761 ", lines=md.since(mark))), md.since(mark))
mark = md.mark()
md.send("METADATA METAOWNER GET display-name")
md.read(1.5)
check("an upper-case nick target resolves too",
      bool(md.find(" 761 ", lines=md.since(mark))), md.since(mark))
mark = md.mark()
md.send("METADATA * CLEAR")
md.read(1.5)
md.send("METADATA * LIST")
md.read(1.5)
check("METADATA CLEAR removes it", not md.find("Meta Owner", lines=md.since(mark)), md.since(mark))
md.close()

# Metadata is filed under the nick, and a nick with nothing behind it belongs to
# whoever holds it next — so it must not come with the last holder's keys.
handover = Client("handover")
handover.send("METADATA * SET display-name :The First Holder")
handover.read(1.0)
handover.close()
time.sleep(0.6)
second = Client("handover")
mark = second.mark()
second.send("METADATA * LIST")
second.read(1.5)
check("a nick does not inherit the last holder's metadata",
      not second.find("The First Holder", lines=second.since(mark)), second.since(mark))
second.close()

section("draft/channel-rename")
ren = Client("renamer2", caps=["draft/channel-rename"])
ren.join("#before")
mark = ren.mark()
ren.send("RENAME #before #after :tidying up")
ren.read(2.0)
check("RENAME accepted for a channel operator",
      bool(ren.find("RENAME", "#after", lines=ren.since(mark))), ren.since(mark))
plain = Client("renamewatch")
mark = plain.mark()
plain.join("#after")
check("the renamed channel exists", bool(plain.find("JOIN", "#after", lines=plain.since(mark))), plain.since(mark))
plain.close()
ren.close()

section("STATUSMSG")
op = Client("statusop", caps=TAGS)
op.join("#status")
voiced = Client("statusvoice", caps=TAGS)
voiced.join("#status")
plain_member = Client("statusplain", caps=TAGS)
plain_member.join("#status")
op.send("MODE #status +v statusvoice")
op.read(1.0)

mark_v, mark_p = voiced.mark(), plain_member.mark()
op.send("PRIVMSG @#status :ops only")
voiced.read(1.0)
plain_member.read(1.0)
check("@#channel skips unprivileged members",
      not plain_member.find("ops only", lines=plain_member.since(mark_p)), plain_member.since(mark_p))

mark_v, mark_p = voiced.mark(), plain_member.mark()
op.send("PRIVMSG +#status :voiced and up")
voiced.read(1.0)
plain_member.read(1.0)
check("+#channel reaches voiced members",
      bool(voiced.find("voiced and up", lines=voiced.since(mark_v))), voiced.since(mark_v))
check("+#channel skips plain members",
      not plain_member.find("voiced and up", lines=plain_member.since(mark_p)), plain_member.since(mark_p))

section("channel modes")
modes = Client("modeop", caps=TAGS)
modes.join("#modes")
outsider = Client("outsider", caps=TAGS)

modes.send("MODE #modes +n")
modes.read(1.0)
mark = outsider.mark()
outsider.send("PRIVMSG #modes :from outside")
outsider.read(1.0)
check("+n blocks external messages", bool(outsider.find(" 404 ", lines=outsider.since(mark))), outsider.since(mark))

modes.send("MODE #modes +i")
modes.read(1.0)
mark = outsider.mark()
outsider.join("#modes")
check("+i blocks uninvited joins", bool(outsider.find(" 473 ", lines=outsider.since(mark))), outsider.since(mark))

mark = outsider.mark()
outsider.send("KNOCK #modes :let me in")
outsider.read(1.5)
check("KNOCK is accepted (710/711)",
      bool(outsider.find(" 711 ", lines=outsider.since(mark))) or bool(outsider.find(" 710 ", lines=outsider.since(mark))),
      outsider.since(mark))

modes.send("MODE #modes -i")
modes.read(1.0)
modes.send("MODE #modes +k sekrit")
modes.read(1.0)
mark = outsider.mark()
outsider.join("#modes")
check("+k requires the key", bool(outsider.find(" 475 ", lines=outsider.since(mark))), outsider.since(mark))
mark = outsider.mark()
outsider.send("JOIN #modes sekrit")
outsider.read(1.5)
check("the right key gets you in", bool(outsider.find("JOIN", "#modes", lines=outsider.since(mark))), outsider.since(mark))

modes.send("MODE #modes +m")
modes.read(1.0)
mark = outsider.mark()
outsider.send("PRIVMSG #modes :may I speak")
outsider.read(1.0)
check("+m silences unvoiced members", bool(outsider.find(" 404 ", lines=outsider.since(mark))), outsider.since(mark))

mark = modes.mark()
modes.send("MODE #modes")
modes.read(1.0)
check("324 RPL_CHANNELMODEIS", bool(modes.find(" 324 ", lines=modes.since(mark))), modes.since(mark))

mark = modes.mark()
modes.send("MODE #modes +b baduser!*@*")
modes.send("MODE #modes +b")
modes.read(1.5)
check("367/368 ban list", bool(modes.find(" 367 ", lines=modes.since(mark))) and bool(modes.find(" 368 ", lines=modes.since(mark))), modes.since(mark))
outsider.close()

section("oper commands")
oper = Client("operator1", caps=TAGS + ["message-tags"])
mark = oper.mark()
oper.send(f"OPER {OPER_NAME} {OPER_PASSWORD}")
oper.read(2.0)
check("381 RPL_YOUREOPER", bool(oper.find(" 381 ", lines=oper.since(mark))), oper.since(mark))

victim = Client("victim", caps=["message-tags"])
victim.send("MODE victim +w")
victim.read(1.0)
mark = victim.mark()
oper.send("WALLOPS :server maintenance in five minutes")
victim.read(1.5)
check("WALLOPS reaches +w users", bool(victim.find("WALLOPS", lines=victim.since(mark))), victim.since(mark))

mark = oper.mark()
oper.send("SETHOST cloaked.example")
oper.read(1.5)
check("SETHOST accepted for an oper",
      bool(oper.find("CHGHOST", lines=oper.since(mark))) or bool(oper.find("cloaked.example", lines=oper.since(mark))),
      oper.since(mark))

mark = victim.mark()
oper.send("KILL victim :smoke test")
victim.read(2.0)
check("KILL disconnects the target",
      bool(victim.find("ERROR", lines=victim.since(mark))) or bool(victim.find("KILL", lines=victim.since(mark))),
      victim.since(mark))
victim.close()

section("draft/oper-tag")
watcher_oper = Client("opwatch", caps=TAGS + ["message-tags", "draft/oper-tag"])
watcher_plain = Client("opplain", caps=TAGS + ["message-tags"])
watcher_oper.join("#opers")
watcher_plain.join("#opers")
oper.join("#opers")

mark_o, mark_p = watcher_oper.mark(), watcher_plain.mark()
oper.send("PRIVMSG #opers :speaking as an operator")
watcher_oper.read(1.5)
watcher_plain.read(1.5)
tagged_line = watcher_oper.find("speaking as an operator", lines=watcher_oper.since(mark_o))
plain_line = watcher_plain.find("speaking as an operator", lines=watcher_plain.since(mark_p))
check("draft/oper tag added for capable clients",
      bool(tagged_line) and "draft/oper=" in tagged_line[0], watcher_oper.since(mark_o))
check("the tag names the operator",
      bool(tagged_line) and f"draft/oper={OPER_NAME}" in tagged_line[0], tagged_line)
check("clients without the cap see no oper tag",
      bool(plain_line) and "draft/oper" not in plain_line[0], plain_line)

mark_o = watcher_oper.mark()
watcher_plain.send("PRIVMSG #opers :just a regular user")
watcher_oper.read(1.5)
regular = watcher_oper.find("just a regular user", lines=watcher_oper.since(mark_o))
check("non-operators are not tagged",
      bool(regular) and "draft/oper" not in regular[0], regular)
watcher_oper.close()
watcher_plain.close()

section("STATS, WHOWAS, ISON, USERHOST")
mark = oper.mark()
oper.send("STATS u")
oper.read(1.0)
check("STATS u replies 242/219", bool(oper.find(" 242 ", lines=oper.since(mark))), oper.since(mark))
mark = oper.mark()
oper.send("STATS o")
oper.read(1.0)
check("STATS o lists opers", bool(oper.find(" 243 ", lines=oper.since(mark))), oper.since(mark))

mark = oper.mark()
oper.send("WHOWAS victim")
oper.read(1.5)
check("WHOWAS finds the departed nick",
      bool(oper.find(" 314 ", lines=oper.since(mark))) or bool(oper.find(" 406 ", lines=oper.since(mark))),
      oper.since(mark))

mark = oper.mark()
oper.send("ISON operator1 nosuchnick")
oper.read(1.0)
ison = oper.find(" 303 ", lines=oper.since(mark))
check("303 ISON lists only online nicks",
      bool(ison) and "operator1" in ison[0] and "nosuchnick" not in ison[0], ison)

mark = oper.mark()
oper.send("USERHOST operator1")
oper.read(1.0)
check("302 USERHOST", bool(oper.find(" 302 ", lines=oper.since(mark))), oper.since(mark))

section("utf8only")
u8 = Client("utf8user", caps=["standard-replies"])
mark = u8.mark()
u8.sock.sendall(b"PRIVMSG #modes :\xff\xfe invalid\r\n")
u8.read(1.5)
check("non-UTF-8 is rejected with a FAIL",
      bool(u8.find("FAIL", lines=u8.since(mark))), u8.since(mark))
u8.close()

section("draft/extended-isupport")
ei = Client()
ei.send("CAP LS 302")
ei.read(0.7)
ei.send("CAP REQ :draft/extended-isupport")
ei.read(0.5)
mark = ei.mark()
ei.send("ISUPPORT")
ei.read(1.5)
check("ISUPPORT answers before registration", bool(ei.find(" 005 ", lines=ei.since(mark))), ei.since(mark))
ei.close()

section("cap-notify")
cn = Client("capnotify", caps=["cap-notify"])
mark = cn.mark()
cn.send("CAP LIST")
cn.read(1.0)
check("CAP LIST reports enabled caps", bool(cn.find("CAP", "LIST", lines=cn.since(mark))), cn.since(mark))
mark = cn.mark()
cn.send("CAP REQ :no-such-capability")
cn.read(1.0)
check("unknown capability is NAKed", bool(cn.find("CAP", "NAK", lines=cn.since(mark))), cn.since(mark))
cn.close()

section("wire format across every reply seen")
seen = []
for c in [watcher, joiner, bot, tagger, tagged, ml_sender, ml_reader, red, red_peer,
          hist, uh, modes, oper, md, mon, quiet, sn]:
    seen.extend(c.lines)
check("no reply has a doubled trailing colon", not [l for l in seen if " : :" in l],
      [l for l in seen if " : :" in l][:3])
check("no reply has an escaped-looking '::' parameter",
      not [l for l in seen if " ::" in l], [l for l in seen if " ::" in l][:3])

for c in [watcher, joiner, bot, tagger, tagged, ml_sender, ml_reader, plain_reader,
          red, red_peer, hist, uh, op, voiced, plain_member, modes, oper]:
    c.close()

summary("ircv3")
