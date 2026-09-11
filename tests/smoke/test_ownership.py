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

summary("ownership")
