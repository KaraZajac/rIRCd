#!/usr/bin/env python3
"""Looking after an account and a channel without a NickServ or a ChanServ.

Registering is the easy half. This is the other half: a password that leaked,
a password that was forgotten, a person who wants to leave, a founder who wants
to see who they have given the run of their channel to, and one who wants to
give it up. Every one of these proves something before it acts, and every
proof is charged like a failed login.
"""

import os
import re
import time

from harness import (
    Client, check, section, summary, wait_for_mail, clear_mail, db,
    connect_negotiating,
)

PW = "management-password-1"
NEW = "a-different-password-2"
RUN = format(int(time.time()) % 100000, "05d")
OPER_PW = os.environ.get("SMOKE_OPER_PASSWORD", "smoke-oper-password")


def make_account(name, password=PW):
    clear_mail()
    c = Client(name)
    c.send(f"REGISTER * {name}@example.org {password}")
    c.read(2.5)
    mail = wait_for_mail(1, seconds=15)
    found = re.search(rf"VERIFY {name} ([A-Z0-9]{{8}})", mail[0])
    if not found:
        raise RuntimeError(f"no verification code mailed for {name}")
    c.send(f"VERIFY {name} {found.group(1)}")
    c.read(2.0)
    c.close()


def logged_in(nick, account, password=PW):
    s = connect_negotiating(nick, caps=["sasl"])
    s.sasl_plain(account, password)
    s.send("CAP END")
    s.wait_for(" 001 ", " 904 ", seconds=6)
    return s


def can_log_in(account, password):
    s = connect_negotiating(f"try{RUN}{int(time.time() * 1000) % 1000}", caps=["sasl"])
    s.sasl_plain(account, password)
    ok = bool(s.find(" 903 "))
    s.close()
    return ok


def persisted_operators(channel):
    return db(
        "SELECT GROUP_CONCAT(nick_or_account) FROM channel_operators o "
        f"JOIN channels c ON o.channel_id = c.id WHERE c.name='{channel}'"
    ) or ""


alice, bob = f"al{RUN}", f"bo{RUN}"
make_account(alice)
make_account(bob)

# ── PASSWD ───────────────────────────────────────────────────────────────────

section("PASSWD: changing a password you know")

nobody = Client(f"nobody{RUN}")
mark = nobody.mark()
nobody.send(f"PASSWD {PW} {NEW}")
nobody.read(1.2)
check("somebody not logged in has no password to change",
      bool(nobody.find("FAIL PASSWD NOT_LOGGED_IN", lines=nobody.since(mark))), nobody.since(mark)[-2:])
nobody.close()

a = logged_in(f"{alice}_1", alice)
other = logged_in(f"{alice}_2", alice)
check("the account is logged in twice", bool(a.find(" 903 ")) and bool(other.find(" 903 ")),
      (a.lines[-2:], other.lines[-2:]))

mark = a.mark()
a.send(f"PASSWD not-the-password {NEW}")
a.wait_for("PASSWD", seconds=20)
check("the current password is asked for, and a wrong one is refused",
      bool(a.find("FAIL PASSWD INCORRECT_PASSWORD", lines=a.since(mark))), a.since(mark)[-2:])

mark = a.mark()
a.send(f"PASSWD {PW} x")
a.wait_for("PASSWD", seconds=20)
check("a new password that is too short is refused",
      bool(a.find("FAIL PASSWD WEAK_PASSWORD", lines=a.since(mark))), a.since(mark)[-2:])

mark, omark = a.mark(), other.mark()
a.send(f"PASSWD {PW} {NEW}")
a.wait_for("PASSWD", seconds=20)
other.read(2.0)
check("the right one changes it", bool(a.find("NOTE PASSWD CHANGED", lines=a.since(mark))),
      a.since(mark)[-2:])
check("the other login to the account is closed",
      bool(other.find("Closing link", lines=other.since(omark))), other.since(omark)[-2:])
check("this one is not", not a.find("Closing link", lines=a.since(mark)), a.since(mark)[-2:])
check("the old password no longer works", not can_log_in(alice, PW))
check("the new one does", can_log_in(alice, NEW))
a.close()
other.close()

# ── RESETPASS ────────────────────────────────────────────────────────────────

section("RESETPASS: a password you have forgotten")

early = connect_negotiating(f"early{RUN}")
mark = early.mark()
early.send(f"RESETPASS nosuch{RUN}")
early.read(1.5)
check("a reset can be asked for before registering, since that is when it is needed",
      bool(early.find("NOTE RESETPASS SENT", lines=early.since(mark))), early.since(mark)[-2:])
early.close()

asker = Client(f"ask{RUN}")
clear_mail()
mark = asker.mark()
asker.send(f"RESETPASS nosuch{RUN}")
asker.read(1.5)
check("asking about a name that is not an account gets the same answer as one that is",
      bool(asker.find("NOTE RESETPASS SENT", lines=asker.since(mark))), asker.since(mark)[-2:])
check("and sends nothing", not wait_for_mail(1, seconds=3))

mark = asker.mark()
asker.send(f"RESETPASS {bob}")
asker.read(1.5)
check("asking about an account is answered the same way",
      bool(asker.find("NOTE RESETPASS SENT", lines=asker.since(mark))), asker.since(mark)[-2:])
mail = wait_for_mail(1, seconds=15)
code = None
if mail:
    found = re.search(rf"RESETPASS {bob} ([A-Z0-9]{{8}}) <new password>", mail[0])
    code = found.group(1) if found else None
check("but this time a code was mailed, with the command to type", bool(code),
      (mail[0][:200] if mail else "no mail"))
check("the mail never contains a password", bool(mail) and PW not in mail[0] and NEW not in mail[0])

clear_mail()
asker.send(f"RESETPASS {bob}")
asker.read(1.5)
check("asking again straight away sends nothing more: one code at a time",
      not wait_for_mail(1, seconds=3))

victim = logged_in(f"{bob}_v", bob)
mark = asker.mark()
asker.send(f"RESETPASS {bob} WRONGCODE {NEW}")
asker.wait_for("RESETPASS", seconds=20)
check("a wrong code is refused", bool(asker.find("FAIL RESETPASS INVALID_CODE", lines=asker.since(mark))),
      asker.since(mark)[-2:])
check("and the account is untouched", can_log_in(bob, PW))

if code:
    mark = asker.mark()
    asker.send(f"RESETPASS {bob} {code} x")
    asker.wait_for("RESETPASS", seconds=20)
    check("the right code with a password too short is refused",
          bool(asker.find("FAIL RESETPASS WEAK_PASSWORD", lines=asker.since(mark))), asker.since(mark)[-2:])

    mark, vmark = asker.mark(), victim.mark()
    asker.send(f"RESETPASS {bob} {code} {NEW}")
    asker.wait_for("RESETPASS", seconds=20)
    victim.read(2.0)
    check("and the code is still good afterwards, so a typo does not cost a fresh mail",
          bool(asker.find("NOTE RESETPASS CHANGED", lines=asker.since(mark))), asker.since(mark)[-2:])
    check("every login to the account is closed: whoever is in it is not the person resetting",
          bool(victim.find("Closing link", lines=victim.since(vmark))), victim.since(vmark)[-2:])
    check("the new password works", can_log_in(bob, NEW))
    check("the old one does not", not can_log_in(bob, PW))

    mark = asker.mark()
    asker.send(f"RESETPASS {bob} {code} {NEW}")
    asker.wait_for("RESETPASS", seconds=20)
    check("a used code is a dead code", bool(asker.find("FAIL RESETPASS INVALID_CODE", lines=asker.since(mark))),
          asker.since(mark)[-2:])
victim.close()
asker.close()

# ── CHANACCESS / CHANDROP ────────────────────────────────────────────────────

section("CHANACCESS: who has the run of a channel")

CH = f"#managed{RUN}"
owner = logged_in(f"{alice}_o", alice, NEW)
owner.join(CH)
helper = logged_in(f"{bob}_h", bob, NEW)
helper.join(CH)
owner.send(f"MODE {CH} +o {bob}_h")
owner.read(1.2)
time.sleep(0.8)

mark = owner.mark()
owner.send(f"CHANACCESS {CH}")
owner.read(1.5)
seen = owner.since(mark)
check("the founder is listed", bool(owner.find("NOTE CHANACCESS FOUNDER", alice, lines=seen)), seen[-4:])
check("and so is the operator they made", bool(owner.find("NOTE CHANACCESS OPERATOR", bob, lines=seen)), seen[-4:])
check("and the list ends", bool(owner.find("NOTE CHANACCESS END", lines=seen)), seen[-2:])

owner.send(f"MODE {CH} +s")
owner.read(1.0)
stranger = Client(f"str{RUN}")
mark = stranger.mark()
stranger.send(f"CHANACCESS {CH}")
stranger.read(1.5)
check("a stranger cannot see the list of a secret channel, nor that it exists",
      bool(stranger.find("FAIL CHANACCESS NO_SUCH_CHANNEL", lines=stranger.since(mark))),
      stranger.since(mark)[-2:])

section("CHANDROP: giving a channel up")

mark = stranger.mark()
stranger.send(f"CHANDROP {CH}")
stranger.read(1.5)
check("a stranger cannot drop it", bool(stranger.find("FAIL CHANDROP", lines=stranger.since(mark)))
      and not stranger.find("NOTE CHANDROP DROPPED", lines=stranger.since(mark)), stranger.since(mark)[-2:])
stranger.close()

mark = helper.mark()
helper.send(f"CHANDROP {CH}")
helper.read(1.5)
check("nor can an operator of it who is not its founder",
      bool(helper.find("FAIL CHANDROP NOT_FOUNDER", lines=helper.since(mark))), helper.since(mark)[-2:])

limited = Client(f"lim{RUN}")
limited.send(f"OPER smokehelper {OPER_PW}")
limited.wait_for(" 381 ", " 464 ", seconds=5)
mark = limited.mark()
limited.send(f"CHANDROP {CH}")
limited.read(1.5)
check("nor a network operator without the channels privilege",
      bool(limited.find("FAIL CHANDROP", lines=limited.since(mark)))
      and not limited.find("NOTE CHANDROP DROPPED", lines=limited.since(mark)), limited.since(mark)[-2:])
limited.close()

mark, hmark = owner.mark(), helper.mark()
owner.send(f"CHANDROP {CH}")
owner.read(1.5)
helper.read(1.0)
check("the founder can", bool(owner.find("NOTE CHANDROP DROPPED", lines=owner.since(mark))), owner.since(mark)[-2:])
check("and the channel is told", bool(helper.find("no longer has a founder", lines=helper.since(hmark))),
      helper.since(hmark)[-2:])
time.sleep(0.8)
check("the record agrees", db(f"SELECT founder FROM channels WHERE name='{CH}'") == "",
      repr(db(f"SELECT founder FROM channels WHERE name='{CH}'")))
check("the operators keep their standing", alice in persisted_operators(CH) and bob in persisted_operators(CH),
      persisted_operators(CH))

mark = owner.mark()
owner.send(f"CHANDROP {CH}")
owner.read(1.5)
check("there is nothing to drop twice", bool(owner.find("FAIL CHANDROP NO_FOUNDER", lines=owner.since(mark))),
      owner.since(mark)[-2:])
owner.close()
helper.close()

# ── DROPACCOUNT ──────────────────────────────────────────────────────────────

section("DROPACCOUNT: leaving, and leaving nothing behind")

OWNED = f"#kept{RUN}"
leaver = logged_in(f"{bob}_l", bob, NEW)
leaver.join(OWNED)
leaver.send("METADATA * SET display-name :Somebody Leaving")
stayer = logged_in(f"{alice}_s", alice, NEW)
stayer.join(OWNED)
leaver.send(f"MODE {OWNED} +o {alice}_s")
leaver.read(1.2)
time.sleep(0.8)
check("the account owns a channel and has a profile",
      db(f"SELECT founder FROM channels WHERE name='{OWNED}'") == bob
      and db(f"SELECT COUNT(*) FROM metadata WHERE target='a:{bob}'") != "0",
      (db(f"SELECT founder FROM channels WHERE name='{OWNED}'"), db(f"SELECT COUNT(*) FROM metadata WHERE target='a:{bob}'")))

mark = leaver.mark()
leaver.send("DROPACCOUNT not-the-password")
leaver.wait_for("DROPACCOUNT", seconds=20)
check("the password is asked for", bool(leaver.find("FAIL DROPACCOUNT INCORRECT_PASSWORD", lines=leaver.since(mark))),
      leaver.since(mark)[-2:])

mark, smark = leaver.mark(), stayer.mark()
leaver.send(f"DROPACCOUNT {NEW}")
leaver.wait_for("DROPACCOUNT", seconds=20)
leaver.read(1.0)
stayer.read(2.0)
check("the right one drops the account", bool(leaver.find("NOTE DROPACCOUNT DROPPED", lines=leaver.since(mark))),
      leaver.since(mark)[-3:])
check("and ends the session, since there is no account to be in",
      bool(leaver.find("Closing link", lines=leaver.since(mark))), leaver.since(mark)[-2:])
check("the channel is told it lost its founder",
      bool(stayer.find("no longer has a founder", lines=stayer.since(smark))), stayer.since(smark)[-2:])
time.sleep(0.8)
check("the account is gone", db(f"SELECT COUNT(*) FROM users WHERE nick_lower='{bob}'") == "0")
check("the channel has no founder", db(f"SELECT founder FROM channels WHERE name='{OWNED}'") == "")
check("its profile is gone", db(f"SELECT COUNT(*) FROM metadata WHERE target='a:{bob}'") == "0")
check("it is on no operator list", bob not in persisted_operators(CH) and bob not in persisted_operators(OWNED),
      (persisted_operators(CH), persisted_operators(OWNED)))
check("the operator it made keeps their standing", alice in persisted_operators(OWNED), persisted_operators(OWNED))

mark = stayer.mark()
stayer.send(f"CHANACCESS {OWNED}")
stayer.read(1.5)
check("and the running server agrees with the record",
      bool(stayer.find("NOTE CHANACCESS NO_FOUNDER", lines=stayer.since(mark)))
      and not stayer.find(bob, lines=stayer.since(mark)), stayer.since(mark)[-4:])
stayer.close()

fresh = Client(bob)
mark = fresh.mark()
fresh.send(f"REGISTER * {bob}@example.org {PW}")
fresh.read(2.5)
check("the name is free to register again", bool(fresh.find("REGISTER", lines=fresh.since(mark)))
      and not fresh.find("ACCOUNT_EXISTS", lines=fresh.since(mark)), fresh.since(mark)[-2:])
fresh.close()

section("SANICK: moving somebody off a name rather than off the network")

# The milder cousin of KILL. The person is told who did it; the room sees an
# ordinary nick change; the checks a NICK gets, a SANICK gets too — a nick in
# use, a bad nick, and a nick registered to somebody else are all refused.
squatter = Client(f"squat{RUN}")
squatter.send(f"JOIN #san{RUN}")
squatter.read(0.8)
witness = Client(f"wit{RUN}")
witness.send(f"JOIN #san{RUN}")
witness.read(0.8)
plain = Client(f"pl{RUN}")
pmark = plain.mark()
plain.send(f"SANICK squat{RUN} moved{RUN}")
plain.read(1.0)
check("a user cannot rename anybody", bool(plain.find(" 481 ", lines=plain.since(pmark))), plain.since(pmark)[-2:])
plain.close()
sop = Client(f"sop{RUN}")
sop.send(f"OPER smokeoper {OPER_PW}")
sop.wait_for(" 381 ", " 464 ", seconds=5)
omark = sop.mark()
sop.send(f"SANICK nosuch{RUN} moved{RUN}")
sop.read(1.0)
check("renaming nobody is 401", bool(sop.find(" 401 ", lines=sop.since(omark))), sop.since(omark)[-2:])
omark = sop.mark()
sop.send(f"SANICK squat{RUN} wit{RUN}")
sop.read(1.0)
check("onto a nick in use is 433", bool(sop.find(" 433 ", lines=sop.since(omark))), sop.since(omark)[-2:])
omark = sop.mark()
sop.send(f"SANICK squat{RUN} #bad")
sop.read(1.0)
check("onto a bad nick is 432", bool(sop.find(" 432 ", lines=sop.since(omark))), sop.since(omark)[-2:])
make_account(f"held{RUN}")
omark = sop.mark()
sop.send(f"SANICK squat{RUN} held{RUN}")
sop.read(1.0)
check("onto somebody else's registered nick is refused",
      bool(sop.find(" 433 ", "registered", lines=sop.since(omark))), sop.since(omark)[-2:])
smark, wmark, omark = squatter.mark(), witness.mark(), sop.mark()
sop.send(f"SANICK squat{RUN} moved{RUN}")
sop.read(1.0)
squatter.read(0.8)
witness.read(0.5)
check("the operator is told it happened",
      bool(sop.find("Changed", f"squat{RUN}", f"moved{RUN}", lines=sop.since(omark))), sop.since(omark)[-2:])
check("the person sees the nick change, and who did it",
      bool(squatter.find("NICK", f"moved{RUN}", lines=squatter.since(smark)))
      and bool(squatter.find("NOTICE", "changed", f"sop{RUN}", lines=squatter.since(smark))),
      squatter.since(smark)[-3:])
check("and so does the room", bool(witness.find("NICK", f"moved{RUN}", lines=witness.since(wmark))), witness.since(wmark)[-2:])
omark = sop.mark()
sop.send(f"WHOIS moved{RUN}")
sop.wait_for(" 318 ", " 401 ", seconds=5)
check("and the new name is theirs", bool(sop.find(" 311 ", f"moved{RUN}", lines=sop.since(omark))), sop.since(omark)[-3:])
squatter.close()
witness.close()
sop.close()

summary("management")
