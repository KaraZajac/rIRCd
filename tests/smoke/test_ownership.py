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

# They gave the channel away and were then removed from it, and it is invite
# only, so it is not theirs and not visible to them. Both answers refuse; the
# one they get is the one that says nothing about the channel still being there.
mark = a.mark()
a.send(f"CHANOWN {CH} {owner}")
a.read(1.2)
check("who can no longer hand the channel back to themselves",
      bool(a.find("FAIL CHANOWN", lines=a.since(mark)))
      and not a.find("NOTE CHANOWN TRANSFERRED", lines=a.since(mark)), a.since(mark)[-3:])
check("and a channel they cannot see does not confirm itself to them",
      bool(a.find("NO_SUCH_CHANNEL", lines=a.since(mark))), a.since(mark)[-3:])
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

# Deciding who owns a room is its own privilege. An operator trusted to keep
# the network orderly is not automatically trusted to take channels off people.
limited = Client(f"lim{RUN}")
limited.send(f"OPER smokehelper "
             f"{os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
limited.wait_for(" 381 ", " 464 ", seconds=5)
check("a limited operator still logs in", bool(limited.find(" 381 ")), limited.lines[-3:])
mark = limited.mark()
limited.send(f"CHANOWN {CH} {stranger}")
limited.read(1.5)
check("but one without the channels privilege cannot move a channel",
      bool(limited.find("FAIL CHANOWN", lines=limited.since(mark)))
      and not limited.find("NOTE CHANOWN TRANSFERRED", lines=limited.since(mark)),
      limited.since(mark)[-3:])
time.sleep(0.6)
check("and the channel did not move", channel_row(CH, "founder") == owner,
      channel_row(CH, "founder"))
limited.close()
watcher.close()

section("a rename takes the channel's record with it")

# RENAME moved the channel in memory and left its row under the old name, so
# after a restart the old name came back owned and the new one was a stranger.
BEFORE = f"#before{RUN}"
AFTER = f"#after{RUN}"
r = logged_in(f"{owner}_n", owner)
r.join(BEFORE)
r.send(f"MODE {BEFORE} +m")
r.send(f"TOPIC {BEFORE} :moving house")
r.read(1.2)
time.sleep(0.8)
check("the channel starts out recorded under its own name",
      channel_row(BEFORE, "founder") == owner, channel_row(BEFORE, "founder"))

mark = r.mark()
r.send(f"RENAME {BEFORE} {AFTER} :moving")
r.read(1.5)
time.sleep(0.8)
check("the rename is accepted",
      not r.find("FAIL RENAME", lines=r.since(mark)), r.since(mark)[-3:])
check("the record moved to the new name",
      channel_row(AFTER, "founder") == owner, channel_row(AFTER, "founder"))
check("and nothing is left behind under the old one",
      channel_row(BEFORE, "founder") == "", repr(channel_row(BEFORE, "founder")))
check("the modes came too", "m" in (channel_row(AFTER, "mode_flags") or ""),
      channel_row(AFTER, "mode_flags"))
r.close()

section("who may bring a channel into being")

# channel_creation gates making a channel, never walking into one that exists.
# The setting is changed under the running server with REHASH and put back
# afterwards, so the suites that follow see the server they expect.
CONFIG = os.environ.get("SMOKE_CONFIG", "")
original = open(CONFIG).read() if CONFIG else ""


def rehash_with(setting):
    """Rewrite the server's configuration and make it read it again."""
    text = original
    if setting:
        text = text.replace("[server]", f"[server]\n{setting}", 1)
    open(CONFIG, "w").write(text)
    op = Client(f"cfg{RUN}{abs(hash(setting)) % 100}")
    op.send(f"OPER {os.environ.get('SMOKE_OPER_NAME', 'smokeoper')} "
            f"{os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
    op.wait_for(" 381 ", " 464 ", seconds=5)
    op.send("REHASH")
    op.wait_for(" 382 ", seconds=5)
    op.close()
    time.sleep(0.5)


if CONFIG:
    try:
        rehash_with('channel_creation = "accounts"')

        anon = Client(f"anon{RUN}")
        mark = anon.mark()
        anon.send(f"JOIN #fresh{RUN}")
        anon.read(1.5)
        check("somebody not logged in cannot make a channel",
              bool(anon.find(" 477 ", lines=anon.since(mark))), anon.since(mark)[-3:])

        holder = logged_in(f"{owner}_cc", owner)
        mark = holder.mark()
        holder.join(f"#fresh{RUN}")
        holder.read(1.5)
        check("somebody logged in can",
              bool(holder.find(f"JOIN", f"#fresh{RUN}", lines=holder.since(mark))),
              holder.since(mark)[-3:])
        check("and the channel it makes has a founder from the start",
              channel_row(f"#fresh{RUN}", "founder") == owner,
              channel_row(f"#fresh{RUN}", "founder"))

        mark = anon.mark()
        anon.send(f"JOIN #fresh{RUN}")
        anon.read(1.5)
        check("joining one that already exists is not gated",
              bool(anon.find("JOIN", f"#fresh{RUN}", lines=anon.since(mark))),
              anon.since(mark)[-3:])
        anon.close()
        holder.close()

        rehash_with('channel_creation = "opers"')
        member = logged_in(f"{owner}_op", owner)
        mark = member.mark()
        member.join(f"#opersonly{RUN}")
        member.read(1.5)
        check("with opers-only even an account is refused",
              bool(member.find(" 481 ", lines=member.since(mark))), member.since(mark)[-3:])
        member.close()
    finally:
        rehash_with(None)
        anyone = Client(f"any{RUN}")
        mark = anyone.mark()
        anyone.join(f"#default{RUN}")
        anyone.read(1.5)
        check("and by default anybody may still make one",
              bool(anyone.find("JOIN", f"#default{RUN}", lines=anyone.since(mark))),
              anyone.since(mark)[-3:])
        anyone.close()

# ── whose profile is it ──────────────────────────────────────────────────────

section("a profile belongs to the person, not to the name they are using")

# What happened on a live server: a restart left a ghost holding the usual nick,
# the client reconnected as <nick>_ and republished its whole profile, and those
# rows stayed under <nick>_ for ever. Anyone taking that name afterwards wore
# the avatar, display name and pronouns of somebody they had never met.

PROFILE = f"prof{RUN}"
make_account(PROFILE)

# Logged in, but using a fallback name, exactly as a client does after a restart.
p1 = logged_in(f"{PROFILE}_", PROFILE)
p1.send("METADATA * SET display-name :The Real Person")
p1.send("METADATA * SET avatar :https://example.invalid/me.png")
p1.read(1.5)
mark = p1.mark()
p1.send("METADATA * LIST")
p1.read(1.5)
check("the profile is set", bool(p1.find("The Real Person", lines=p1.since(mark))),
      p1.since(mark)[-4:])
time.sleep(0.8)
check("and written down under the account, not the nick",
      db(f"SELECT COUNT(*) FROM metadata WHERE target='a:{PROFILE}'") != "0",
      db("SELECT GROUP_CONCAT(DISTINCT target) FROM metadata"))
check("nothing is filed under the fallback name",
      db(f"SELECT COUNT(*) FROM metadata WHERE target LIKE '%{PROFILE}\\_%'") == "0",
      db("SELECT GROUP_CONCAT(DISTINCT target) FROM metadata"))
p1.close()
time.sleep(0.6)

stranger_nick = Client(f"{PROFILE}_")
mark = stranger_nick.mark()
stranger_nick.send("METADATA * LIST")
stranger_nick.read(1.5)
check("whoever takes the name next inherits nothing",
      not stranger_nick.find("The Real Person", lines=stranger_nick.since(mark)),
      stranger_nick.since(mark)[-4:])
mark = stranger_nick.mark()
stranger_nick.send(f"METADATA {PROFILE}_ GET display-name")
stranger_nick.read(1.5)
check("and cannot be handed it by asking for the name",
      not stranger_nick.find("The Real Person", lines=stranger_nick.since(mark)),
      stranger_nick.since(mark)[-4:])
stranger_nick.close()

section("but the person keeps it, under whatever name")

p2 = logged_in(f"{PROFILE}_again", PROFILE)
mark = p2.mark()
p2.send("METADATA * LIST")
p2.read(1.5)
check("the same account comes back to its own profile",
      bool(p2.find("The Real Person", lines=p2.since(mark))), p2.since(mark)[-4:])

mark = p2.mark()
p2.send(f"NICK {PROFILE}_moved")
p2.read(1.0)
p2.send("METADATA * LIST")
p2.read(1.5)
check("and a nick change does not move it anywhere",
      bool(p2.find("The Real Person", lines=p2.since(mark))), p2.since(mark)[-4:])
time.sleep(0.8)
check("still written down under the account alone",
      db("SELECT COUNT(*) FROM metadata WHERE target LIKE 'n:%'") == "0",
      db("SELECT GROUP_CONCAT(DISTINCT target) FROM metadata"))
p2.close()

section("somebody with no account keeps nothing")

anon2 = Client(f"anonmeta{RUN}")
anon2.send("METADATA * SET display-name :Just Passing Through")
anon2.read(1.2)
time.sleep(0.8)
check("a borrowed name is never written down",
      db("SELECT COUNT(*) FROM metadata WHERE value='Just Passing Through'") == "0",
      db("SELECT GROUP_CONCAT(target) FROM metadata WHERE value='Just Passing Through'"))
anon2.close()
time.sleep(0.6)

after_anon = Client(f"anonmeta{RUN}")
mark = after_anon.mark()
after_anon.send("METADATA * LIST")
after_anon.read(1.5)
check("and the next holder of it inherits nothing either",
      not after_anon.find("Just Passing Through", lines=after_anon.since(mark)),
      after_anon.since(mark)[-4:])
after_anon.close()

section("a channel that hides itself hides itself from CHANOWN too")

# Answering "only the founder may do that" to somebody who cannot see the
# channel tells them it exists, which is the one thing +s is for.
SECRET = f"#secret{RUN}"
keeper = logged_in(f"{owner}_s", owner)
keeper.join(SECRET)
keeper.send(f"MODE {SECRET} +s")
keeper.read(1.2)

outsider = Client(f"out{RUN}")
mark = outsider.mark()
outsider.send(f"CHANOWN {SECRET}")
outsider.read(1.5)
check("a stranger is told there is no such channel",
      bool(outsider.find("FAIL CHANOWN NO_SUCH_CHANNEL", lines=outsider.since(mark))),
      outsider.since(mark)[-3:])
check("and is not told who owns it",
      not outsider.find(owner, lines=outsider.since(mark)), outsider.since(mark)[-3:])
mark = outsider.mark()
outsider.send(f"CHANOWN {SECRET} {stranger}")
outsider.read(1.5)
check("nor can they tell it apart from one that does not exist by trying",
      bool(outsider.find("FAIL CHANOWN NO_SUCH_CHANNEL", lines=outsider.since(mark))),
      outsider.since(mark)[-3:])
outsider.close()

mark = keeper.mark()
keeper.send(f"CHANOWN {SECRET}")
keeper.read(1.5)
check("while whoever owns it still gets an answer",
      bool(keeper.find("NOTE CHANOWN FOUNDER", owner, lines=keeper.since(mark))),
      keeper.since(mark)[-3:])
keeper.close()

section("standing in a channel belongs to an account, not to a name")

# Operator status that outlives a visit used to be stored as whatever the
# person was called, and matched against a nick as well as an account. Either
# half hands somebody's status to whoever takes their name — and the thing that
# would normally stop a name being taken, nick reservation, deliberately fails
# open when the database is unreachable, which is exactly when it matters.

NAMED = f"#named{RUN}"
holder = logged_in(f"{owner}_a", owner)
holder.join(NAMED)
holder.read(1.0)

# An account is given standing here.
helper = logged_in(f"{stranger}_a", stranger)
helper.join(NAMED)
helper.read(1.0)
holder.send(f"MODE {NAMED} +o {stranger}_a")
holder.read(1.2)
time.sleep(0.8)
check("an account's standing is remembered", stranger in persisted_operators(NAMED),
      persisted_operators(NAMED))
helper.close()
holder.close()
time.sleep(0.6)

# Somebody arrives using that account's name, without being it.
impostor = Client(stranger)
mark = impostor.mark()
impostor.send(f"JOIN {NAMED}")
impostor.read(1.5)
took_the_name = bool(impostor.find(f"JOIN {NAMED}", lines=impostor.since(mark))) or \
    bool(impostor.find(" 353 ", lines=impostor.since(mark)))
if took_the_name:
    check("wearing the name does not inherit what the account was given",
          not impostor.find(f"@{stranger}", lines=impostor.since(mark)),
          impostor.since(mark)[-5:])
else:
    # Nick reservation turned them away before they could even register, which
    # is the other defence and is fine — but it is the one that fails open when
    # the database is unreachable, so it is not the one being tested here.
    check("the name is reserved, so the other defence answered first",
          bool(impostor.find(" 433 ")), impostor.lines[-4:])
impostor.close()

# And somebody not logged in is an operator while they are here, no longer.
passing = Client(f"pass{RUN}b")
passing.join(NAMED)
passing.read(1.0)
back = logged_in(f"{owner}_b", owner)
back.join(NAMED)
back.read(1.0)
# They may already hold it from being first into a room that was standing
# empty, so this asks for the status rather than assuming the change is visible.
back.send(f"MODE {NAMED} +o pass{RUN}b")
back.read(1.2)
mark = back.mark()
back.send(f"NAMES {NAMED}")
back.read(1.2)
check("somebody with no account can still be made an operator",
      bool(back.find(" 353 ", f"@pass{RUN}b", lines=back.since(mark))),
      back.since(mark)[-3:])
time.sleep(0.8)
check("but it is not written down for the next holder of the name",
      f"pass{RUN}b" not in persisted_operators(NAMED), persisted_operators(NAMED))
passing.close()
back.close()

section("an owned channel that is standing open")

# The case the earlier checks missed, because they set +i and the stranger was
# turned away at the door before there was any question of ops. A real channel
# is usually just open — and then being first through the door is something
# that happens to everybody eventually, at every restart and every quiet hour.
OPEN_OWNED = f"#openowned{RUN}"
holder2 = logged_in(f"{owner}_o", owner)
holder2.join(OPEN_OWNED)
holder2.send(f"TOPIC {OPEN_OWNED} :an ordinary channel with an owner")
holder2.read(1.2)
time.sleep(0.8)
check("it has an owner and no door on it",
      channel_row(OPEN_OWNED, "founder") == owner
      and "i" not in (channel_row(OPEN_OWNED, "mode_flags") or ""),
      (channel_row(OPEN_OWNED, "founder"), channel_row(OPEN_OWNED, "mode_flags")))
holder2.send(f"PART {OPEN_OWNED}")
holder2.read(1.0)
holder2.close()
time.sleep(0.6)

# Everybody has gone. The next person in is first, and first is not the same
# as the owner.
passerby = Client(f"first{RUN}")
mark = passerby.mark()
passerby.join(OPEN_OWNED)
passerby.read(1.5)
arrived = passerby.since(mark)
check("the next person in does get in", bool(passerby.find("JOIN", OPEN_OWNED, lines=arrived)),
      arrived[-3:])
check("but being first does not make them an operator of somebody else's channel",
      not passerby.find(f"@first{RUN}", lines=arrived), arrived[-4:])
check("and the topic is still the owner's",
      bool(passerby.find("an ordinary channel with an owner", lines=arrived)), arrived[-4:])

# The owner comes back and is an operator again, with somebody already there.
back2 = logged_in(f"{owner}_o2", owner)
mark = back2.mark()
back2.join(OPEN_OWNED)
back2.read(1.5)
check("while the owner is an operator whenever they return",
      bool(back2.find(f"@{owner}_o2", lines=back2.since(mark))
           or back2.find(f"+o {owner}_o2", lines=back2.since(mark))),
      back2.since(mark)[-5:])
passerby.close()
back2.close()

summary("ownership")
