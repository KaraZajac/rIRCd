#!/usr/bin/env python3
"""Core protocol: capability negotiation, ISUPPORT, channels, messaging."""

from harness import Client, check, connect_negotiating, section, summary

section("capability negotiation")
c = Client()
c.send("CAP LS 302")
c.read(1.0)
cap_ls = " ".join(c.find("CAP", "LS"))

for cap in [
    "sasl=PLAIN,SCRAM-SHA-256",
    "message-tags",
    "server-time",
    "batch",
    "echo-message",
    "multi-prefix",
    "extended-join",
    "account-notify",
    "chghost",
    "setname",
    "away-notify",
    "invite-notify",
    "labeled-response",
    "standard-replies",
    "draft/chathistory",
    "draft/account-registration=",
    "draft/webpush",
    "draft/oper-tag",
]:
    check(f"advertises {cap.rstrip('=')}", cap in cap_ls, cap_ls[:300])

check("CAP LS 302 is split across continuation lines", len(c.find("CAP", "LS", " * :")) >= 1)
c.close()

section("registration and ISUPPORT")
alice = Client("alice", caps=["message-tags", "server-time", "echo-message", "draft/webpush"])
check("001 welcome", bool(alice.find(" 001 ")))
check("002/003/004 sent", all(alice.find(f" 00{n} ") for n in (2, 3, 4)))
check("005 ISUPPORT sent", bool(alice.find(" 005 ")))
check("MOTD delivered (375/372/376)", bool(alice.find(" 376 ")) or bool(alice.find(" 422 ")))

isupport = " ".join(alice.find(" 005 "))
# A feature the server implements but does not advertise is one no client will
# offer, so the tokens are worth pinning alongside the behaviour.
for token in ["CHANTYPES=#", "PREFIX=(ohv)@%+", "NETWORK=", "CASEMAPPING=", "CHATHISTORY=",
              "STATUSMSG=@+", "KNOCK", "EXCEPTS", "INVEX", "SAFELIST", "ELIST=CMNTU",
              "EXTBAN=~,am", "MONITOR=", "TARGMAX=", "METADATA=", "UTF8ONLY", "WHOX"]:
    check(f"ISUPPORT has {token}", token in isupport, isupport[:300])
check("VAPID advertised to a draft/webpush client", "VAPID=" in isupport, isupport[:300])

section("channels")
alice.join("#smoke")
check("JOIN echoed to the joiner", bool(alice.find("JOIN", "#smoke")))
check("353/366 NAMES burst", bool(alice.find(" 353 ")) and bool(alice.find(" 366 ")))
check("first joiner is opped", bool(alice.find("MODE #smoke", "+o", "alice")) or "@alice" in " ".join(alice.find(" 353 ")))

alice.send("TOPIC #smoke :smoke testing in progress")
alice.read(1.0)
check("TOPIC accepted", bool(alice.find("TOPIC", "#smoke")))

bob = Client("bob", caps=["message-tags", "server-time", "account-tag", "extended-join"])
mark = alice.mark()
bob.join("#smoke")
alice.read(1.0)
check("peers see the JOIN", bool(alice.find("JOIN", "#smoke", lines=alice.since(mark))), alice.since(mark))
check("332 topic on join", bool(bob.find(" 332 ", "#smoke")), bob.lines[-6:])
check("333 topic setter/time", bool(bob.find(" 333 ", "#smoke")))
# 324 and 329 answer `MODE #channel`; sending them on JOIN too puts unasked-for
# numerics between the JOINs of a multi-channel join, which clients read by
# position.
check("no 329 in the JOIN burst", not bob.find(" 329 ", "#smoke"), bob.lines[-8:])
mark = bob.mark()
bob.send("MODE #smoke")
bob.read(1.0)
check("324 channel modes on MODE", bool(bob.find(" 324 ", "#smoke", lines=bob.since(mark))))
check("329 creation time on MODE", bool(bob.find(" 329 ", "#smoke", lines=bob.since(mark))))

section("messaging")
mark = bob.mark()
alice.send("PRIVMSG #smoke :hello channel")
bob.read(1.0)
delivered = bob.find("PRIVMSG", "#smoke", "hello channel", lines=bob.since(mark))
check("channel PRIVMSG delivered", bool(delivered), bob.since(mark))
check("server-time tag present", bool(delivered) and delivered[0].startswith("@") and "time=" in delivered[0], delivered)
check("msgid tag present", bool(delivered) and "msgid=" in delivered[0], delivered)

mark = alice.mark()
alice.send("PRIVMSG #smoke :echo check")
alice.read(1.0)
check("echo-message returns the sender's own line", bool(alice.find("PRIVMSG", "echo check", lines=alice.since(mark))), alice.since(mark))

mark = bob.mark()
alice.send("PRIVMSG bob :direct hello")
bob.read(1.0)
check("direct PRIVMSG delivered", bool(bob.find("PRIVMSG bob", "direct hello", lines=bob.since(mark))), bob.since(mark))

mark = bob.mark()
alice.send("NOTICE #smoke :a notice")
bob.read(1.0)
check("channel NOTICE delivered", bool(bob.find("NOTICE", "#smoke", "a notice", lines=bob.since(mark))))

section("queries")
alice.send("WHOIS bob")
alice.read(1.5)
check("311 WHOIS user", bool(alice.find(" 311 ", "bob")))
check("318 end of WHOIS", bool(alice.find(" 318 ")))

alice.send("WHO #smoke")
alice.read(1.5)
check("352 WHO reply", bool(alice.find(" 352 ")))
check("315 end of WHO", bool(alice.find(" 315 ")))

# "The <name> passed to WHO is matched against users' host, server, real name
# and nickname" — RFC 1459, and the modern spec after it. Matching the nick
# alone makes the searches a person actually types find nobody.
searcher = Client("whofind", user="wfinduser", realname="A Findable Person")


def who_hits(mask, nick="whofind"):
    mark = searcher.mark()
    searcher.send(f"WHO {mask}")
    searcher.wait_for(" 315 ", seconds=5)
    return [l for l in searcher.find(" 352 ", lines=searcher.since(mark)) if nick in l]


check("WHO finds a user by their nick", bool(who_hits("whofin*")))
check("WHO finds a user by their username", bool(who_hits("*finduser")))
check("WHO finds a user by their real name", bool(who_hits("*Findable*")))
check("WHO finds a user by a real name with a space in it",
      bool(who_hits(":*A Findable*")))
check("WHO finds a user by their host", bool(who_hits("*.IP")))
check("WHO finds a user by the server they are on", bool(who_hits("*.test")))
# No wildcard in it, and still nobody's nick: a plain hostname is a search.
host_line = [l for l in searcher.find(" 352 ", lines=searcher.lines) if "whofind" in l]
if host_line:
    host = host_line[0].split()[4]
    check("WHO finds a user by a host with no wildcard in it",
          bool(who_hits(host)), host)
else:
    check("a 352 for the searcher was seen", False)
check("WHO on a mask that matches nobody answers with only 315",
      not who_hits("*nobodyhasthisname*"))
mark = searcher.mark()
searcher.send("WHO *Findable*")
searcher.wait_for(" 315 ", seconds=5)
check("the 315 echoes the mask as it was sent",
      any("*Findable*" in l for l in searcher.find(" 315 ", lines=searcher.since(mark))),
      searcher.since(mark)[-2:])
searcher.close()

alice.send("LIST")
alice.read(1.5)
check("322 LIST entry for #smoke", bool(alice.find(" 322 ", "#smoke")))
check("323 end of LIST", bool(alice.find(" 323 ")))

for command, numeric in [("LUSERS", " 251 "), ("VERSION", " 351 "), ("TIME", " 391 "), ("INFO", " 371 "), ("MOTD", " 372 ")]:
    mark = alice.mark()
    alice.send(command)
    alice.read(1.0)
    check(f"{command} replies {numeric.strip()}", bool(alice.find(numeric, lines=alice.since(mark))), alice.since(mark))

section("labeled-response")
labeled = Client("carol_l", caps=["labeled-response", "message-tags", "batch"])
mark = labeled.mark()
labeled.send("@label=abc123 PING smoke")
labeled.read(1.0)
check("reply carries the label", any("label=abc123" in l for l in labeled.since(mark)), labeled.since(mark))
labeled.close()

section("error handling")
mark = alice.mark()
alice.send("PRIVMSG nosuchuser :hello?")
alice.read(1.0)
check("401 for unknown nick", bool(alice.find(" 401 ", lines=alice.since(mark))), alice.since(mark))

mark = alice.mark()
alice.send("FROBNICATE now")
alice.read(1.0)
check("421 for unknown command", bool(alice.find(" 421 ", lines=alice.since(mark))), alice.since(mark))

mark = alice.mark()
alice.send("JOIN")
alice.read(1.0)
check("461 for missing parameters", bool(alice.find(" 461 ", lines=alice.since(mark))), alice.since(mark))

section("wire format")
all_lines = alice.lines + bob.lines
check("no doubled trailing colon", not [l for l in all_lines if " : :" in l],
      [l for l in all_lines if " : :" in l][:3])
check("every line has a source or is a client command",
      all(l.startswith((":", "@", "PING", "ERROR")) for l in all_lines),
      [l for l in all_lines if not l.startswith((":", "@", "PING", "ERROR"))][:3])

section("draft/pre-away and away-notify")
away = connect_negotiating("dana", caps=["away-notify"])
away.send("AWAY :back later")
away.send("CAP END")
away.wait_for(" 376 ", " 422 ", seconds=5)
mark = alice.mark()
alice.send("PRIVMSG dana :you there?")
alice.read(1.0)
check("301 RPL_AWAY from a pre-away client", bool(alice.find(" 301 ", lines=alice.since(mark))), alice.since(mark))
away.close()

alice.close()
bob.close()
summary("core")
