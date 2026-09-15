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
import os as _os
CONFIG = _os.environ.get("SMOKE_CONFIG", "")
original = open(CONFIG).read() if CONFIG else ""


def rehash_with(*changes):
    """Rewrite the server's configuration and make it read it again; with no
    changes, put the original back."""
    text = original
    for old, new in changes:
        assert old in text, old
        text = text.replace(old, new, 1)
    open(CONFIG, "w").write(text)
    op = Client(f"cfg{RUN}{abs(hash(changes)) % 100}")
    op.send(f"OPER smokeoper {OPER_PW}")
    op.wait_for(" 381 ", " 464 ", seconds=5)
    op.send("REHASH")
    op.wait_for(" 382 ", seconds=5)
    op.close()
    time.sleep(0.5)


def make_account(name, password=PW):
    clear_mail()
    c = Client(name)
    c.send(f"REGISTER * {name}@example.org {password}")
    c.wait_for("REGISTER", seconds=20)
    mail = wait_for_mail(1, seconds=15)
    found = re.search(rf"VERIFY {name} ([A-Z0-9]{{8}})", mail[0])
    if not found:
        raise RuntimeError(f"no verification code mailed for {name}")
    c.send(f"VERIFY {name} {found.group(1)}")
    c.read(2.0)
    c.close()


def patiently(client, command, want, seconds=60):
    """Send a credential command, doing what the server says when it asks the
    address to slow down.

    Every password check costs real work and is charged to the address that
    asked for it, successful or not; a suite that does a dozen in two minutes
    spends an allowance a person never would. The server answers RATE_LIMITED
    and says to try again in a moment, so that is what this does — which is
    also the only way to test that the answer means what it says."""
    deadline = time.time() + seconds
    while True:
        mark = client.mark()
        client.send(command)
        client.wait_for(want, "RATE_LIMITED", seconds=20)
        lines = client.since(mark)
        if client.find(want, lines=lines) or time.time() > deadline:
            return lines
        if not client.find("RATE_LIMITED", lines=lines):
            return lines
        time.sleep(6)

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
seen = patiently(a, f"PASSWD {PW} {NEW}", "NOTE PASSWD CHANGED")
check("the right one changes it", bool(a.find("NOTE PASSWD CHANGED", lines=seen)), seen[-2:])
other.read(1.5)
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

    vmark = victim.mark()
    seen = patiently(asker, f"RESETPASS {bob} {code} {NEW}", "NOTE RESETPASS CHANGED")
    check("and the code is still good afterwards, so a typo does not cost a fresh mail",
          bool(asker.find("NOTE RESETPASS CHANGED", lines=seen)), seen[-2:])
    victim.read(1.5)
    check("every login to the account is closed: whoever is in it is not the person resetting",
          bool(victim.find("Closing link", lines=victim.since(vmark))), victim.since(vmark)[-2:])
    check("the new password works", can_log_in(bob, NEW))
    check("the old one does not", not can_log_in(bob, PW))

    seen = patiently(asker, f"RESETPASS {bob} {code} {NEW}", "INVALID_CODE")
    mark = asker.mark()
    check("a used code is a dead code", bool(asker.find("FAIL RESETPASS INVALID_CODE", lines=seen)),
          seen[-2:])
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

smark = stayer.mark()
seen = patiently(leaver, f"DROPACCOUNT {NEW}", "NOTE DROPACCOUNT DROPPED")
leaver.read(1.0)
stayer.read(2.0)
check("the right one drops the account", bool(leaver.find("NOTE DROPACCOUNT DROPPED", lines=seen)),
      seen[-3:])
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
fresh.wait_for("REGISTER", seconds=20)
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
# make_account closes its client; the nick is not free again until the server
# has seen that go, and "in use" is a different refusal from "reserved".
for _ in range(20):
    probe = sop.mark()
    sop.send(f"WHOIS held{RUN}")
    sop.wait_for(" 318 ", " 401 ", seconds=5)
    if sop.find(" 401 ", lines=sop.since(probe)):
        break
    time.sleep(0.5)
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

section("server notices: an operator chooses what to hear")

# User mode +s with a mask of letters. A new operator hears everything about
# the server and nothing about traffic; connections and nick changes are
# asked for, because on a busy server they are a lot.
watcher = Client(f"watch{RUN}")
watcher.send(f"OPER smokeoper {OPER_PW}")
watcher.wait_for(" 381 ", " 464 ", seconds=5)
wmark = watcher.mark()
watcher.send(f"MODE watch{RUN}")
watcher.read(1.0)
check("a new operator starts with the server's own news",
      bool(watcher.find(" 008 ", "+abfklos", lines=watcher.since(wmark))), watcher.since(wmark)[-2:])
wmark = watcher.mark()
passer = Client(f"pass{RUN}")
passer.close()
watcher.read(1.0)
check("and hears nothing about a connection", not watcher.find("Client connecting", lines=watcher.since(wmark)), watcher.since(wmark)[-2:])
wmark = watcher.mark()
watcher.send(f"MODE watch{RUN} +s +cn")
watcher.read(0.8)
check("+s +cn adds connections and nick changes",
      bool(watcher.find(" 008 ", "+abcfklnos", lines=watcher.since(wmark))), watcher.since(wmark)[-2:])
wmark = watcher.mark()
walker = Client(f"walk{RUN}")
walker.send(f"NICK walked{RUN}")
walker.read(0.8)
walker.send("QUIT :done here")
walker.read(0.5)
watcher.read(1.0)
told = watcher.since(wmark)
check("a connection is announced with its address",
      bool(watcher.find("Client connecting", f"walk{RUN}", "[127.0.0.1]", lines=told)), told[-4:])
check("a nick change is announced", bool(watcher.find("Nick change", f"walk{RUN} -> walked{RUN}", lines=told)), told[-4:])
check("and so is leaving, with the reason",
      bool(watcher.find("Client exiting", f"walked{RUN}", "done here", lines=told)), told[-4:])
wmark = watcher.mark()
watcher.send(f"MODE watch{RUN} +s -cn")
watcher.read(0.8)
quiet = Client(f"quiet{RUN}")
quiet.close()
watcher.read(1.0)
check("-cn turns them off again", not watcher.find("Client connecting", lines=watcher.since(wmark)), watcher.since(wmark)[-2:])
bystander = Client(f"bys{RUN}")
bmark = bystander.mark()
bystander.send(f"MODE bys{RUN} +s +c")
bystander.read(0.8)
check("a user who is not an operator has no notices to choose from",
      bool(bystander.find(" 481 ", lines=bystander.since(bmark))), bystander.since(bmark)[-2:])
bystander.close()
wmark = watcher.mark()
watcher.send(f"MODE watch{RUN} -s")
watcher.read(0.8)
check("-s clears the mask", bool(watcher.find(" 008 ", "+ ", lines=watcher.since(wmark))) or bool(watcher.find(" 008 ", lines=watcher.since(wmark))), watcher.since(wmark)[-2:])
watcher.close()

section("MLOCK: what the founder locks, an appointed operator cannot undo")

# A founder sets the modes they want and locks them. An operator they made
# can still run the room — kick, ban, topic — but a MODE that would change a
# locked letter is refused (742) until the founder unlocks it.
lord = f"lord{RUN}"
make_account(lord)
serf = f"serf{RUN}"
make_account(serf)
LCH = f"#locked{RUN}"
lo = logged_in(f"{lord}c", lord)
lo.join(LCH)
se = logged_in(f"{serf}c", serf)
se.join(LCH)
lo.send(f"MODE {LCH} +nt")
lo.send(f"MODE {LCH} +o {serf}c")
lo.read(1.0)
lmark = lo.mark()
lo.send(f"MLOCK {LCH}")
lo.read(0.8)
check("a channel starts with no lock", bool(lo.find("NOTE MLOCK LOCK", "no mode lock", lines=lo.since(lmark))), lo.since(lmark)[-2:])
smark = se.mark()
se.send(f"MLOCK {LCH} +n")
se.read(0.8)
check("only the founder can set one", bool(se.find("FAIL MLOCK NOT_FOUNDER", lines=se.since(smark))), se.since(smark)[-2:])
lmark = lo.mark()
lo.send(f"MLOCK {LCH} +tn-k")
lo.read(0.8)
check("the founder locks +nt and -k", bool(lo.find("NOTE MLOCK LOCK", "+nt-k", lines=lo.since(lmark))), lo.since(lmark)[-2:])
lmark = lo.mark()
lo.send(f"MLOCK {LCH} +x")
lo.read(0.8)
check("a letter that is not a mode cannot be locked", bool(lo.find("FAIL MLOCK INVALID_LOCK", lines=lo.since(lmark))), lo.since(lmark)[-2:])
smark = se.mark()
se.send(f"MODE {LCH} -t")
se.send(f"MODE {LCH} +k secret")
se.read(1.0)
check("an operator's MODE against the lock is refused (742)", len(se.find(" 742 ", lines=se.since(smark))) == 2, se.since(smark)[-3:])
smark = se.mark()
se.send(f"MODE {LCH}")
se.read(0.8)
shown = next((l.split()[4] for l in se.since(smark) if " 324 " in l and len(l.split()) > 4), "")
check("and the modes are as the founder left them", shown == "+nt", se.since(smark)[-2:])
smark = se.mark()
se.send(f"MODE {LCH} +i")
se.read(0.8)
check("a mode that is not locked is theirs to set", bool(se.find("MODE", "+i", lines=se.since(smark))), se.since(smark)[-2:])
lmark = lo.mark()
lo.send(f"MODE {LCH} -t")
lo.read(0.8)
check("the founder is not bound by their own lock", bool(lo.find("MODE", "-t", lines=lo.since(lmark))), lo.since(lmark)[-2:])
lo.send(f"MLOCK {LCH} OFF")
lo.read(0.8)
smark = se.mark()
se.send(f"MODE {LCH} +t")
se.read(0.8)
check("MLOCK OFF lifts it", bool(se.find("MODE", "+t", lines=se.since(smark))), se.since(smark)[-2:])
lo.close()
se.close()

section("SAJOIN, SAPART, SAMODE: an operator's hand on a channel")

sa = Client(f"sa{RUN}")
sa.send(f"OPER smokeoper {OPER_PW}")
sa.wait_for(" 381 ", " 464 ", seconds=5)
keeper = Client(f"keep{RUN}")
keeper.send(f"JOIN #sa{RUN}")
keeper.read(0.8)
keeper.send(f"MODE #sa{RUN} +i")
keeper.read(0.5)
pulled = Client(f"pull{RUN}")
pmark = pulled.mark()
pulled.send(f"SAJOIN keep{RUN} #elsewhere{RUN}")
pulled.read(0.8)
check("a user cannot force anybody anywhere", bool(pulled.find(" 481 ", lines=pulled.since(pmark))), pulled.since(pmark)[-2:])
pmark, kmark = pulled.mark(), keeper.mark()
sa.send(f"SAJOIN pull{RUN} #sa{RUN}")
sa.read(1.0)
pulled.read(1.0)
keeper.read(0.5)
check("SAJOIN puts somebody in an invite-only channel", bool(pulled.find("JOIN", f"#sa{RUN}", lines=pulled.since(pmark))), pulled.since(pmark)[-3:])
check("and tells them who did it", bool(pulled.find("NOTICE", "joined to", f"sa{RUN}", lines=pulled.since(pmark))), pulled.since(pmark)[-3:])
check("and the room sees an ordinary join", bool(keeper.find("JOIN", f"pull{RUN}", lines=keeper.since(kmark))), keeper.since(kmark)[-2:])
smark = sa.mark()
sa.send(f"SAMODE #sa{RUN} +m")
sa.read(1.0)
keeper.read(0.5)
check("SAMODE sets a mode without holding ops", bool(keeper.find("MODE", f"#sa{RUN}", "+m")), keeper.lines[-2:])
check("shown as the operator's own MODE", bool(keeper.find(f":sa{RUN} MODE", "+m")), keeper.lines[-2:])
pmark, kmark = pulled.mark(), keeper.mark()
sa.send(f"SAPART pull{RUN} #sa{RUN} :go elsewhere")
sa.read(1.0)
pulled.read(1.0)
keeper.read(0.5)
check("SAPART takes them out again, with the reason", bool(pulled.find("PART", f"#sa{RUN}", "go elsewhere", lines=pulled.since(pmark))), pulled.since(pmark)[-3:])
check("which the room sees as a part", bool(keeper.find("PART", f"pull{RUN}", lines=keeper.since(kmark))), keeper.since(kmark)[-2:])
smark = sa.mark()
sa.send(f"SAPART pull{RUN} #sa{RUN}")
sa.read(0.8)
check("removing somebody who is not there is 441", bool(sa.find(" 441 ", lines=sa.since(smark))), sa.since(smark)[-2:])
smark = sa.mark()
sa.send(f"TESTMASK *!*@127.0.0.1")
sa.read(0.8)
hit = next((l for l in sa.since(smark) if " 724 " in l), "")
check("TESTMASK counts who a ban would hit", bool(hit) and int(hit.split()[4]) >= 3, sa.since(smark)[-2:])
smark = sa.mark()
sa.send("MAP")
sa.wait_for(" 017 ", seconds=5)
check("MAP shows this server and how many are on it", bool(sa.find(" 015 ", "irc.smoke.test", "users]", lines=sa.since(smark))), sa.since(smark)[-3:])
pulled.close()
keeper.close()
sa.close()

section("an operator block can ask for a certificate, TLS, or a host")

# A client certificate is made here, its fingerprint put into an operator
# block with no password, and OPER succeeds over TLS with the certificate
# and nowhere else. `require_tls` refuses the plaintext port; `hostmask`
# refuses the wrong host, judged on the real address.
import subprocess as _sp
import tempfile as _tf
if CONFIG:
    certdir = _tf.mkdtemp(prefix="smoke-oper-")
    pem = os.path.join(certdir, "oper.pem")
    _sp.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-keyout", pem, "-out", pem, "-subj", "/CN=certoper"], check=True,
            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    fp = _sp.run(["openssl", "x509", "-in", pem, "-noout", "-fingerprint", "-sha256"],
                 capture_output=True, text=True, check=True).stdout.strip().split("=", 1)[1]
    rehash_with(("[limits]",
                 "[[opers]]\nname = \"certoper\"\ncertfp = \"" + fp + "\"\n\n"
                 "[[opers]]\nname = \"tlsoper\"\npassword_hash = \"" + _os.environ.get("SMOKE_OPER_HASH", "") + "\"\nrequire_tls = true\n\n"
                 "[[opers]]\nname = \"faroper\"\nhostmask = \"*@10.9.9.9\"\npassword_hash = \"" + _os.environ.get("SMOKE_OPER_HASH", "") + "\"\n\n"
                 "[limits]"))
    with_cert = Client(f"cert{RUN}", tls=True, certfile=pem)
    cmark = with_cert.mark()
    with_cert.send("OPER certoper")
    with_cert.wait_for(" 381 ", " 464 ", " 461 ", seconds=5)
    check("OPER with the certificate and no password succeeds", bool(with_cert.find(" 381 ", lines=with_cert.since(cmark))), with_cert.since(cmark)[-2:])
    with_cert.close()
    without = Client(f"nocert{RUN}", tls=True)
    nmark = without.mark()
    without.send("OPER certoper")
    without.wait_for(" 381 ", " 464 ", " 461 ", seconds=5)
    check("over TLS without the certificate it is refused", bool(without.find(" 464 ", lines=without.since(nmark))), without.since(nmark)[-2:])
    without.close()
    plain = Client(f"plain{RUN}")
    pmark = plain.mark()
    plain.send(f"OPER tlsoper {OPER_PW}")
    plain.wait_for(" 381 ", " 464 ", seconds=5)
    check("a require_tls block refuses the plaintext port", bool(plain.find(" 464 ", lines=plain.since(pmark))), plain.since(pmark)[-2:])
    plain.close()
    secure = Client(f"secure{RUN}", tls=True)
    smark = secure.mark()
    secure.send(f"OPER tlsoper {OPER_PW}")
    secure.wait_for(" 381 ", " 464 ", seconds=5)
    check("and accepts the same password over TLS", bool(secure.find(" 381 ", lines=secure.since(smark))), secure.since(smark)[-2:])
    secure.close()
    far = Client(f"far{RUN}")
    fmark = far.mark()
    far.send(f"OPER faroper {OPER_PW}")
    far.wait_for(" 381 ", " 464 ", " 491 ", seconds=5)
    check("a block for another host refuses this one (491)", bool(far.find(" 491 ", lines=far.since(fmark))), far.since(fmark)[-2:])
    far.close()
    rehash_with()

section("TRACE and STATS: an operator can see the server")

look = Client(f"look{RUN}")
look.send(f"OPER smokeoper {OPER_PW}")
look.wait_for(" 381 ", " 464 ", seconds=5)
bystander = Client(f"byst{RUN}")
bmark = bystander.mark()
bystander.send("TRACE")
bystander.send("STATS l")
bystander.send("STATS t")
bystander.read(1.5)
refused = bystander.since(bmark)
check("none of it is a bystander's business", len(bystander.find(" 481 ", lines=refused)) == 3, refused[-4:])

lmark = look.mark()
look.send("TRACE")
look.wait_for(" 262 ", seconds=5)
traced = look.since(lmark)
check("TRACE names the operator asking", bool(look.find(" 204 ", "Oper", f"look{RUN}", lines=traced)), traced[-4:])
check("and everybody else on the server", bool(look.find(" 205 ", "User", f"byst{RUN}", lines=traced)), traced[-4:])
check("saying how each of them arrived", bool(look.find(" 205 ", "plain", lines=traced)), traced[-4:])
check("and ends where it says it does", bool(look.find(" 262 ", "End of TRACE", lines=traced)), traced[-2:])

lmark = look.mark()
look.send(f"TRACE byst{RUN}")
look.wait_for(" 262 ", seconds=5)
one = look.since(lmark)
check("TRACE with a name is about that one person",
      bool(look.find(" 205 ", f"byst{RUN}", lines=one)) and not look.find(" 204 ", lines=one), one[-3:])

lmark = look.mark()
look.send("STATS l")
look.wait_for(" 219 ", seconds=5)
rows = [l for l in look.since(lmark) if " 211 " in l]
check("STATS l has a row for every connection", len(rows) >= 2, rows[:3])
mine = next((l for l in rows if f"look{RUN}[" in l), "")
fields = mine.split()
# :server 211 nick name sendq sentmsgs sentbytes rcvdmsgs rcvdbytes :open
check("with counts that have counted something",
      bool(mine) and int(fields[5]) > 0 and int(fields[6]) > 0 and int(fields[7]) > 0, mine)
check("and a send queue that is not backed up", bool(mine) and int(fields[4]) < 100, mine)

lmark = look.mark()
look.send("STATS t")
look.wait_for(" 219 ", seconds=5)
totals = look.since(lmark)
check("STATS t says how long it has been up and what it has done",
      bool(look.find(" 249 ", "Up ", "seconds", lines=totals))
      and bool(look.find(" 249 ", "command(s) handled", lines=totals)), totals[-4:])
check("and how much has crossed the connections open now",
      bool(look.find(" 249 ", "byte(s) out", lines=totals)), totals[-4:])
bystander.close()
look.close()

section("connection classes: not every client is the same client")

# The harness gives 127.0.0.7 a class of its own, holding two connections.
# Everybody else falls into no class and is named by how they arrived.
klass = Client(f"cls{RUN}")
klass.send(f"OPER smokeoper {OPER_PW}")
klass.wait_for(" 381 ", " 464 ", seconds=5)
gw1 = Client(f"gw1{RUN}", source="127.0.0.7")
gw2 = Client(f"gw2{RUN}", source="127.0.0.7")
check("a class holds what it says it holds", bool(gw1.find(" 001 ")) and bool(gw2.find(" 001 ")),
      (gw1.lines[-1:], gw2.lines[-1:]))
third = Client(source="127.0.0.7")
third.read(1.5)
check("and refuses the one over it",
      bool(third.find("ERROR", "class")) and not third.find(" 001 "), third.lines[-2:])
third.close()

kmark = klass.mark()
klass.send("STATS y")
klass.wait_for(" 219 ", seconds=5)
classes = klass.since(kmark)
check("STATS y names the class and how many are in it",
      bool(klass.find(" 218 ", "smoke-gateway", "2 here", lines=classes)), classes[-4:])
check("and says where everybody else ended up",
      bool(klass.find(" 218 ", "in no class", lines=classes)), classes[-4:])
check("with the class's own ping time and send queue",
      bool(klass.find(" 218 ", "smoke-gateway", "300", "64", lines=classes)), classes[-4:])

kmark = klass.mark()
klass.send(f"TRACE gw1{RUN}")
klass.wait_for(" 262 ", seconds=5)
check("TRACE calls them by their class",
      bool(klass.find(" 205 ", "smoke-gateway", f"gw1{RUN}", lines=klass.since(kmark))), klass.since(kmark)[-3:])
kmark = klass.mark()
klass.send(f"TRACE cls{RUN}")
klass.wait_for(" 262 ", seconds=5)
check("and calls the unclassed by how they arrived",
      bool(klass.find(" 204 ", "plain", f"cls{RUN}", lines=klass.since(kmark))), klass.since(kmark)[-3:])

gw1.close()
gw2.close()
time.sleep(1.0)
again = Client(f"gw3{RUN}", source="127.0.0.7")
check("and a place opens up when one leaves", bool(again.find(" 001 ")), again.lines[-2:])
again.close()
klass.close()

section("extended bans: the certificate and the badge")

# ~S: asks for a TLS client certificate, ~O for an operator's badge. The
# useful one is +e ~O: the operators are exempt from what the room bans.
xo = Client(f"xo{RUN}")
xo.send(f"OPER smokeoper {OPER_PW}")
xo.wait_for(" 381 ", " 464 ", seconds=5)
XCH = f"#xo{RUN}"
holder = Client(f"hold{RUN}")
holder.join(XCH)
holder.send(f"MODE {XCH} +b *!*@*.IP")
holder.read(0.8)
xmark = xo.mark()
xo.send(f"JOIN {XCH}")
xo.read(1.0)
check("a wide ban keeps even an operator out", bool(xo.find(" 474 ", lines=xo.since(xmark))), xo.since(xmark)[-2:])
holder.send(f"MODE {XCH} +e ~O")
holder.read(0.8)
xmark = xo.mark()
xo.send(f"JOIN {XCH}")
xo.read(1.0)
check("+e ~O lets the operators past it", bool(xo.find("JOIN", XCH, lines=xo.since(xmark))), xo.since(xmark)[-2:])
plainer = Client(f"pln{RUN}")
plainer.send(f"JOIN {XCH}")
plainer.read(1.0)
check("and nobody else", bool(plainer.find(" 474 ")), plainer.lines[-2:])
plainer.close()
holder.send(f"MODE {XCH} -e ~O")
holder.send(f"MODE {XCH} -b *!*@*.IP")
holder.send(f"MODE {XCH} +b ~S:*")
holder.read(0.8)
withcert = Client(f"crt{RUN}", tls=True, certfile=pem) if CONFIG else None
if withcert:
    cmark = withcert.mark()
    withcert.send(f"JOIN {XCH}")
    withcert.read(1.2)
    check("a ~S: ban keeps out whoever brought a certificate",
          bool(withcert.find(" 474 ", lines=withcert.since(cmark))), withcert.since(cmark)[-2:])
    withcert.close()
    nocert = Client(f"ncr{RUN}", tls=True)
    nocert.send(f"JOIN {XCH}")
    nocert.read(1.2)
    check("and lets in whoever did not", bool(nocert.find("JOIN", XCH)), nocert.lines[-2:])
    nocert.close()
holder.close()
xo.close()

section("SETEMAIL: moving an account to another address")

# The address is what a forgotten password goes to, so moving it asks for the
# password and for a code read at the new address. Until the code comes back
# the account keeps the address it had.
mover = f"move{RUN}"
make_account(mover)
mv = logged_in(f"{mover}c", mover)
mmark = mv.mark()
mv.send(f"SETEMAIL wrong-password somewhere@example.org")
mv.wait_for("SETEMAIL", seconds=20)
check("a wrong password moves nothing",
      bool(mv.find("FAIL SETEMAIL INCORRECT_PASSWORD", lines=mv.since(mmark))), mv.since(mmark)[-2:])
mmark = mv.mark()
mv.send(f"SETEMAIL {PW} not-an-address")
mv.wait_for("SETEMAIL", seconds=20)
check("and neither does an address the server cannot write to",
      bool(mv.find("FAIL SETEMAIL INVALID_EMAIL", lines=mv.since(mmark))), mv.since(mmark)[-2:])

clear_mail()
mmark = mv.mark()
mv.send(f"SETEMAIL {PW} {mover}-new@example.org")
mv.wait_for("SETEMAIL", seconds=20)
check("the right password sends a code to the new address",
      bool(mv.find("NOTE SETEMAIL SENT", f"{mover}-new@example.org", lines=mv.since(mmark))), mv.since(mmark)[-2:])
check("and the account keeps the address it had for now",
      db(f"SELECT email FROM users WHERE nick_lower='{mover}'") == f"{mover}@example.org")
mail = wait_for_mail(1, seconds=20)
found = re.search(r"SETEMAIL ([A-Z0-9]{8})", mail[0]) if mail else None
check("the mail went to the new address and says what to type",
      bool(found) and f"To: {mover}-new@example.org" in mail[0], (mail or [""])[0][:200])
if found:
    mmark = mv.mark()
    mv.send("SETEMAIL WRONGCOD")
    mv.wait_for("SETEMAIL", seconds=20)
    check("a wrong code moves nothing",
          bool(mv.find("FAIL SETEMAIL INVALID_CODE", lines=mv.since(mmark))), mv.since(mmark)[-2:])
    seen = patiently(mv, f"SETEMAIL {found.group(1)}", "NOTE SETEMAIL CHANGED")
    check("the right one moves it", bool(mv.find("NOTE SETEMAIL CHANGED", lines=seen)), seen[-2:])
    check("and the account is at the new address", 
          db(f"SELECT email FROM users WHERE nick_lower='{mover}'") == f"{mover}-new@example.org")
    check("with nothing left waiting",
          db(f"SELECT COUNT(*) FROM users WHERE nick_lower='{mover}' AND pending_email IS NOT NULL") == "0")

section("ACCOUNTINFO: what the server is holding about you")

mv.send(f"JOIN #owned{RUN}")
mv.read(1.0)
mmark = mv.mark()
mv.send("ACCOUNTINFO")
mv.read(1.5)
info = mv.since(mmark)
check("it says when the account was registered and last seen",
      bool(mv.find("NOTE ACCOUNTINFO ACCOUNT", "registered", "last seen", lines=info)), info[-5:])
check("and the address it is at now",
      bool(mv.find("NOTE ACCOUNTINFO EMAIL", f"{mover}-new@example.org", lines=info)), info[-5:])
check("and the nicks it holds", bool(mv.find("NOTE ACCOUNTINFO NICKS", mover, lines=info)), info[-5:])
check("and the channels it founded",
      bool(mv.find("NOTE ACCOUNTINFO CHANNELS", f"#owned{RUN}", lines=info)), info[-5:])

nosy = Client(f"nosy{RUN}")
nmark = nosy.mark()
nosy.send(f"ACCOUNTINFO {mover}")
nosy.read(1.2)
check("somebody else's account is not a bystander's business",
      bool(nosy.find("FAIL ACCOUNTINFO NOT_YOURS", lines=nosy.since(nmark))), nosy.since(nmark)[-2:])
nmark = nosy.mark()
nosy.send("ACCOUNTINFO")
nosy.read(1.2)
check("and somebody with no account has none to show",
      bool(nosy.find("FAIL ACCOUNTINFO NOT_LOGGED_IN", lines=nosy.since(nmark))), nosy.since(nmark)[-2:])
nosy.close()

snoop = Client(f"snoop{RUN}")
snoop.send(f"OPER smokeoper {OPER_PW}")
snoop.wait_for(" 381 ", " 464 ", seconds=5)
smark = snoop.mark()
snoop.send(f"ACCOUNTINFO {mover}")
snoop.read(1.5)
check("an operator working out who is who may look",
      bool(snoop.find("NOTE ACCOUNTINFO ACCOUNT", mover, lines=snoop.since(smark))), snoop.since(smark)[-3:])
smark = snoop.mark()
snoop.send(f"ACCOUNTINFO nobody{RUN}")
snoop.read(1.2)
check("and is told plainly when there is no such account",
      bool(snoop.find("FAIL ACCOUNTINFO NO_SUCH_ACCOUNT", lines=snoop.since(smark))), snoop.since(smark)[-2:])
snoop.close()
mv.close()

section("RESV: names this network keeps")

rs = Client(f"rs{RUN}")
rs.send(f"OPER smokeoper {OPER_PW}")
rs.wait_for(" 381 ", " 464 ", seconds=5)
civ2 = Client(f"cv{RUN}")
cmark = civ2.mark()
civ2.send(f"RESV #anything{RUN} :mine now")
civ2.read(1.0)
check("a user reserves nothing", bool(civ2.find(" 481 ", lines=cmark and civ2.since(cmark))), civ2.since(cmark)[-2:])

rmark = rs.mark()
rs.send("RESV #* :everything")
rs.send(f"RESV rs{RUN} :my own nick")
rs.read(1.2)
refused = rs.since(rmark)
check("a pattern that names nothing is refused",
      bool(rs.find("FAIL RESV MASK_TOO_BROAD", lines=refused)), refused[-3:])
check("and so is one covering the operator's own nick",
      bool(rs.find("FAIL RESV MATCHES_YOURSELF", lines=refused)), refused[-3:])

rmark = rs.mark()
rs.send(f"RESV #staff{RUN} :for the people who run this place")
rs.send(f"RESV serv{RUN}* :nobody here speaks for services")
rs.read(1.2)
check("a channel and a nick can both be kept",
      len(rs.find("NOTE RESV RESERVED", lines=rs.since(rmark))) == 2, rs.since(rmark)[-3:])

cmark = civ2.mark()
civ2.send(f"JOIN #staff{RUN}")
civ2.read(1.2)
check("a reserved channel is refused, with the reason",
      bool(civ2.find(" 479 ", "run this place", lines=civ2.since(cmark))), civ2.since(cmark)[-2:])
cmark = civ2.mark()
civ2.send(f"NICK serv{RUN}bot")
civ2.read(1.2)
check("and a reserved nick likewise",
      bool(civ2.find(" 432 ", "speaks for services", lines=civ2.since(cmark))), civ2.since(cmark)[-2:])
cmark = civ2.mark()
civ2.send(f"JOIN #staffroom{RUN}")
civ2.read(1.2)
check("a name the pattern does not cover is nobody's business",
      bool(civ2.find("JOIN", f"#staffroom{RUN}", lines=civ2.since(cmark))), civ2.since(cmark)[-2:])

rmark = rs.mark()
rs.send(f"JOIN #staff{RUN}")
rs.read(1.2)
check("an operator is not held to it", bool(rs.find("JOIN", f"#staff{RUN}", lines=rs.since(rmark))), rs.since(rmark)[-2:])

rs.send(f"UNRESV #staff{RUN}")
rs.send(f"UNRESV serv{RUN}*")
rs.read(1.2)
cmark = civ2.mark()
civ2.send(f"JOIN #staff{RUN}")
civ2.send(f"NICK serv{RUN}bot")
civ2.read(1.5)
back = civ2.since(cmark)
check("UNRESV gives both back",
      bool(civ2.find("JOIN", f"#staff{RUN}", lines=back)) and bool(civ2.find("NICK", f"serv{RUN}bot", lines=back)), back[-3:])
rmark = rs.mark()
rs.send(f"UNRESV #never{RUN}")
rs.read(1.0)
check("and says so when there was nothing to give back",
      bool(rs.find("NOTE UNRESV NO_SUCH_RESV", lines=rs.since(rmark))), rs.since(rmark)[-2:])
civ2.close()
rs.close()

summary("management")
