#!/usr/bin/env python3
"""What a channel keeps when the last person walks out.

A channel only lived while somebody was in it: when it emptied it was dropped,
and the next JOIN built a blank one. Everything that made it *someone's* — the
founder, the operator list, the bans, the modes, the topic — was in the
database, and the database was only read at startup. So a registered channel
that went quiet came back unowned and unguarded, and the next person to log in
and join took it, was written into its operator list for good, and destroyed
its stored modes with their first MODE.

A channel nobody claimed is still forgotten. That is the line these check.
"""

import os
import re
import time

from harness import (
    Client, check, section, summary, wait_for_mail, clear_mail, db,
    connect_negotiating,
)

PW = "ownership-password-123"
RUN = format(int(time.time()) % 100000, "05d")


def make_account(name):
    clear_mail()
    c = Client(name)
    c.send(f"REGISTER * {name}@example.org {PW}")
    c.read(2.5)
    mail = wait_for_mail(1, seconds=15)
    found = re.search(rf"VERIFY {name} ([A-Z0-9]{{8}})", mail[0])
    if not found:
        raise RuntimeError(f"no verification code mailed for {name}")
    c.send(f"VERIFY {name} {found.group(1)}")
    c.read(2.0)
    c.close()


def logged_in(nick, account):
    """A registered connection. The nick differs from the account because the
    account's own nick is reserved, and NICK comes before AUTHENTICATE."""
    s = connect_negotiating(nick, caps=["sasl"])
    s.sasl_plain(account, PW)
    s.send("CAP END")
    s.wait_for(" 001 ", seconds=6)
    return s


def channel_row(channel, column):
    return db(f"SELECT {column} FROM channels WHERE name='{channel}'")


def persisted_operators(channel):
    return db(
        "SELECT GROUP_CONCAT(nick_or_account) FROM channel_operators o "
        f"JOIN channels c ON o.channel_id = c.id WHERE c.name='{channel}'"
    ) or ""


owner, stranger = f"own{RUN}", f"str{RUN}"
make_account(owner)
make_account(stranger)

CH = f"#owned{RUN}"
OPEN = f"#open{RUN}"

# ── a channel somebody made into something ───────────────────────────────────

section("a channel with a founder")

a = logged_in(f"{owner}_c", owner)
a.join(CH)
check("whoever made it is opped", bool(a.find(f"@{owner}_c") or a.find(f"+o {owner}_c")), a.lines[-6:])
check("and is recorded as the founder", channel_row(CH, "founder") == owner, channel_row(CH, "founder"))

a.send(f"MODE {CH} +i")
a.send(f"MODE {CH} +b nobody!*@*")
a.send(f"TOPIC {CH} :this channel belongs to {owner}")
a.read(1.5)
time.sleep(0.8)
check("the topic is written down, not just held", channel_row(CH, "topic").endswith(owner),
      channel_row(CH, "topic"))

section("everybody leaves")

a.send(f"PART {CH}")
a.read(1.0)
a.close()
time.sleep(0.6)

section("a stranger tries to walk in")

b = logged_in(f"{stranger}_c", stranger)
mark = b.mark()
b.join(CH)
b.read(1.5)
new = b.since(mark)
check("the invite-only mode is still on", bool(b.find(" 473 ", lines=new)), new[-4:])
check("and they are not in it", not b.find(f"JOIN {CH}", lines=new), new[-4:])
check("nor did joining make them an operator", stranger not in persisted_operators(CH),
      persisted_operators(CH))
check("the founder is unchanged", channel_row(CH, "founder") == owner, channel_row(CH, "founder"))
b.close()

section("the founder comes back")

a = logged_in(f"{owner}_r", owner)
mark = a.mark()
a.join(CH)
a.send(f"MODE {CH}")
a.send(f"MODE {CH} b")
a.read(1.5)
back = a.since(mark)
check("they are opped again", bool(a.find(f"@{owner}_r", lines=back) or a.find(f"+o {owner}_r", lines=back)), back[-6:])
check("the ban list survived", bool(a.find("nobody!*@*", lines=back)), back[-6:])
check("the topic survived", bool(a.find(f"belongs to {owner}", lines=back)), back[-6:])

mark = a.mark()
a.send(f"MODE {CH} +m")
a.read(1.2)
time.sleep(0.8)
flags = channel_row(CH, "mode_flags")
check("a new mode is added to the stored ones, not swapped for them",
      "i" in flags and "m" in flags, f"mode_flags={flags!r}")
a.close()

# ── and a channel nobody claimed ─────────────────────────────────────────────

section("a channel nobody made anything of")

c = Client(f"pass{RUN}")
c.join(OPEN)
c.send(f"PART {OPEN}")
c.read(1.0)
c.close()
time.sleep(0.6)

d = Client(f"next{RUN}")
mark = d.mark()
d.join(OPEN)
d.send(f"MODE {OPEN}")
d.read(1.5)
fresh = d.since(mark)
check("is forgotten, so the next person in creates it fresh",
      bool(d.find(" 329 ", lines=fresh)), fresh[-4:])
check("and is opped, the way creating a channel works",
      bool(d.find(f"@next{RUN}", lines=fresh) or d.find(f"+o next{RUN}", lines=fresh)), fresh[-6:])
d.close()

section("a channel with modes but no owner")

# Nobody logged in made this one, so nobody can ever lift what is set on it.
# Keeping it would not be preserving a channel, it would be sealing one.
SEALED = f"#sealed{RUN}"
e = Client(f"seal{RUN}")
e.join(SEALED)
e.send(f"MODE {SEALED} +k secretkey")
e.send(f"MODE {SEALED} +i")
e.read(1.2)
e.send(f"PART {SEALED}")
e.read(1.0)
e.close()
time.sleep(0.6)

f = Client(f"after{RUN}")
mark = f.mark()
f.join(SEALED)
f.send(f"MODE {SEALED}")
f.read(1.5)
opened = f.since(mark)
check("is let go, so its key does not outlive the person who set it",
      not f.find(" 475 ", lines=opened) and not f.find(" 473 ", lines=opened), opened[-4:])
check("and whoever comes next gets it fresh",
      bool(f.find(f"@after{RUN}", lines=opened) or f.find(f"+o after{RUN}", lines=opened)), opened[-6:])
f.close()

# ── the founder cannot be evicted from their own room ────────────────────────

section("an operator the founder appointed turns on them")

a = logged_in(f"{owner}_p", owner)
a.join(CH)
a.read(1.0)
b = logged_in(f"{stranger}_p", stranger)
a.send(f"INVITE {stranger}_p {CH}")
a.read(0.8)
b.join(CH)
b.read(1.0)
mark = b.mark()
a.send(f"MODE {CH} +o {stranger}_p")
a.read(1.2)
b.read(1.0)
check("the founder can appoint an operator",
      bool(b.find(f"+o {stranger}_p", lines=b.since(mark))), b.since(mark)[-4:])

mark = b.mark()
b.send(f"KICK {CH} {owner}_p :this is my channel now")
b.read(1.2)
check("who cannot then kick the founder out",
      bool(b.find(" 482 ", lines=b.since(mark))), b.since(mark)[-4:])
mark = b.mark()
b.send(f"NAMES {CH}")
b.read(1.2)
check("and the founder is still in their channel",
      bool(b.find(" 353 ", f"{owner}_p", lines=b.since(mark))), b.since(mark)[-3:])

mark = b.mark()
b.send(f"MODE {CH} -o {owner}_p")
b.read(1.2)
check("nor quietly take their operator status away",
      bool(b.find(" 482 ", lines=b.since(mark))), b.since(mark)[-4:])

# ── handing a channel on ─────────────────────────────────────────────────────

section("CHANOWN says who a channel belongs to")

mark = a.mark()
a.send(f"CHANOWN {CH}")
a.read(1.2)
check("the founder is named", bool(a.find("NOTE CHANOWN FOUNDER", owner, lines=a.since(mark))),
      a.since(mark)[-3:])

section("only the founder or an operator may hand it on")

mark = b.mark()
b.send(f"CHANOWN {CH} {stranger}")
b.read(1.2)
check("a channel operator cannot take it",
      bool(b.find("FAIL CHANOWN NOT_FOUNDER", lines=b.since(mark))), b.since(mark)[-3:])
check("and it is still the founder's",
      channel_row(CH, "founder") == owner, channel_row(CH, "founder"))

mark = a.mark()
a.send(f"CHANOWN {CH} nobody{RUN}")
a.read(1.2)
check("handing it to an account that does not exist is refused",
      bool(a.find("FAIL CHANOWN NO_SUCH_ACCOUNT", lines=a.since(mark))), a.since(mark)[-3:])

section("the founder hands it on")

mark, bmark = a.mark(), b.mark()
a.send(f"CHANOWN {CH} {stranger}")
a.read(1.5)
b.read(0.5)
check("the transfer is confirmed",
      bool(a.find("NOTE CHANOWN TRANSFERRED", lines=a.since(mark))), a.since(mark)[-3:])
check("the channel is told, so it is not a quiet handover",
      bool(b.find("now belongs to", stranger, lines=b.since(bmark))), b.since(bmark)[-4:])
time.sleep(0.8)
check("the database agrees", channel_row(CH, "founder") == stranger, channel_row(CH, "founder"))
check("the outgoing founder keeps operator status, not thrown out",
      owner in persisted_operators(CH), persisted_operators(CH))

mark = b.mark()
b.send(f"KICK {CH} {owner}_p :off you go")
b.read(1.2)
check("and the new founder can now remove the old one",
      not b.find(" 482 ", lines=b.since(mark)), b.since(mark)[-3:])

mark = a.mark()
a.send(f"CHANOWN {CH} {owner}")
a.read(1.2)
check("who can no longer hand the channel back to themselves",
      bool(a.find("FAIL CHANOWN NOT_FOUNDER", lines=a.since(mark))), a.since(mark)[-3:])
a.close()
b.close()

section("an operator can move a channel, and cannot do it quietly")

# The permissive half: an operator does not have to own a channel to act on one,
# because a channel whose founder has vanished otherwise has no way back. The
# loud half: everybody in the room is told, and told that it was an operator.
watcher = logged_in(f"{stranger}_w", stranger)
watcher.join(CH)
watcher.read(1.0)

oper = Client(f"op{RUN}")
oper.send(f"OPER {os.environ.get('SMOKE_OPER_NAME', 'smokeoper')} "
          f"{os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
oper.wait_for(" 381 ", " 464 ", seconds=5)
check("the operator logged in", bool(oper.find(" 381 ")), oper.lines[-3:])

mark, wmark = oper.mark(), watcher.mark()
oper.send(f"CHANOWN {CH} {owner}")
oper.read(1.5)
watcher.read(1.0)
check("an operator can hand on a channel that is not theirs",
      bool(oper.find("NOTE CHANOWN TRANSFERRED", lines=oper.since(mark))), oper.since(mark)[-3:])
check("the room is told it was an operator who did it",
      bool(watcher.find("network operator", lines=watcher.since(wmark))),
      watcher.since(wmark)[-4:])
time.sleep(0.8)
check("and the channel really moved", channel_row(CH, "founder") == owner, channel_row(CH, "founder"))
oper.close()
watcher.close()

summary("ownership")
