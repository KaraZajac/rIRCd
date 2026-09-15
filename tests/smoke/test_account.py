#!/usr/bin/env python3
"""draft/account-registration: REGISTER, email verification, VERIFY, SASL gating."""

import re

import time

from harness import (
    Client,
    check,
    clear_mail,
    connect_negotiating,
    db,
    section,
    summary,
    wait_for_mail,
)

PASSWORD = "hunter2secret"

section("capability value")
c = Client()
c.send("CAP LS 302")
c.read(1.0)
cap_ls = " ".join(c.find("CAP", "LS"))
check("email-required advertised while [email] is configured", "email-required" in cap_ls, cap_ls[:300])
check("before-connect advertised", "before-connect" in cap_ls, cap_ls[:300])
check("custom-account-name not advertised (not implemented)", "custom-account-name" not in cap_ls)
check("min-password-length advertised", "min-password-length=6" in cap_ls, cap_ls[:300])
c.close()

section("REGISTER rejects unusable input")
clear_mail()
for label, command, expect in [
    ("no email", f"REGISTER * * {PASSWORD}", "FAIL REGISTER INVALID_EMAIL"),
    ("malformed email", f"REGISTER * nope {PASSWORD}", "FAIL REGISTER INVALID_EMAIL"),
    ("short password", "REGISTER * carol@example.org abc", "FAIL REGISTER"),
    ("wrong account name", f"REGISTER someoneelse carol@example.org {PASSWORD}", "FAIL REGISTER ACCOUNT_NAME_MUST_BE_NICK"),
]:
    client = Client(f"reg_{abs(hash(label)) % 1000}")
    mark = client.mark()
    client.send(command)
    client.read(2.0)
    check(f"rejected: {label}", bool(client.find(expect, lines=client.since(mark))), client.since(mark))
    client.close()

check("nothing was mailed for rejected attempts", not wait_for_mail(1, seconds=2))

section("REGISTER with a valid address")
carol = Client("carol")
mark = carol.mark()
carol.send(f"REGISTER * carol@example.org {PASSWORD}")
carol.wait_for("REGISTER", seconds=20)
new = carol.since(mark)
check("REGISTER VERIFICATION_REQUIRED", bool(carol.find("REGISTER VERIFICATION_REQUIRED carol", lines=new)), new)
check("client is not logged in yet", not carol.find(" 900 ", lines=new), new)
check("row stored unverified", db("SELECT verified FROM users WHERE nick_lower='carol'") == "0")

section("verification mail")
mail = wait_for_mail(1)
check("mail reached the sink", len(mail) == 1)
code = None
if mail:
    body = mail[0]
    check("addressed to the registrant", "To: carol@example.org" in body, body[:200])
    check("has a subject", "Subject:" in body)
    match = re.search(r"VERIFY carol ([A-Z0-9]{8})", body)
    check("body contains a ready-to-paste VERIFY command", bool(match), body)
    if match:
        code = match.group(1)
        check("code matches the stored one", code == db("SELECT verification_code FROM users WHERE nick_lower='carol'"))
        check("code avoids ambiguous characters", not set(code) & set("01OI"), code)

section("an unverified account cannot authenticate")
s = connect_negotiating("carol_sasl", caps=["sasl"])
s.sasl_plain("carol", PASSWORD)
check("SASL PLAIN refused with 904", bool(s.find(" 904 ")), s.lines[-4:])
check("no 900 RPL_LOGGEDIN", not s.find(" 900 "))
s.close()

section("VERIFY")
if code:
    v = Client("carol_v")
    mark = v.mark()
    v.send("VERIFY carol WRONGCOD")
    v.read(1.5)
    check("wrong code refused", bool(v.find("FAIL VERIFY INVALID_CODE", lines=v.since(mark))), v.since(mark))

    mark = v.mark()
    v.send(f"VERIFY carol {code.lower()}")
    v.read(2.0)
    new = v.since(mark)
    check("codes are case-insensitive: VERIFY SUCCESS", bool(v.find("VERIFY SUCCESS carol", lines=new)), new)
    check("900 RPL_LOGGEDIN follows", bool(v.find(" 900 ", lines=new)), new)
    check("row marked verified", db("SELECT verified FROM users WHERE nick_lower='carol'") == "1")
    check("code cleared", db("SELECT IFNULL(verification_code,'NULL') FROM users WHERE nick_lower='carol'") == "NULL")

    mark = v.mark()
    v.send(f"VERIFY carol {code}")
    v.read(1.5)
    check("re-verifying refused as already authenticated",
          bool(v.find("FAIL VERIFY ALREADY_AUTHENTICATED", lines=v.since(mark))), v.since(mark))
    v.close()

section("SASL after verification")
s = connect_negotiating("carol_ok", caps=["sasl", "account-notify"])
s.sasl_plain("carol", PASSWORD)
check("SASL PLAIN succeeds (903)", bool(s.find(" 903 ")), s.lines[-4:])
check("900 RPL_LOGGEDIN", bool(s.find(" 900 ")))
s.send("CAP END")
s.wait_for(" 376 ", " 422 ", seconds=5)
s.send("MODE carol_ok")
s.read(1.0)
check("umode +r once logged in", bool([l for l in s.find(" 221 ") if "r" in l.split()[-1]]), s.find(" 221 "))
s.close()

section("wrong password is still refused")
s = connect_negotiating("carol_bad", caps=["sasl"])
s.sasl_plain("carol", "not-the-password")
check("904 for a bad password", bool(s.find(" 904 ")), s.lines[-4:])
s.close()

section("expired codes free the account name")
db("DELETE FROM users WHERE nick_lower='stale'")
db(
    "INSERT INTO users (nick, nick_lower, password, email, verified, verification_code, verification_expires) "
    "VALUES ('stale','stale','x','s@example.org',0,'ABCD2345', UNIX_TIMESTAMP()-10)"
)
stale = Client("stale")
mark = stale.mark()
stale.send(f"REGISTER * fresh@example.org {PASSWORD}")
stale.wait_for("REGISTER", seconds=20)
check("re-registration allowed once the code expired",
      bool(stale.find("REGISTER VERIFICATION_REQUIRED stale", lines=stale.since(mark))), stale.since(mark))
check("exactly one row for the name", db("SELECT COUNT(*) FROM users WHERE nick_lower='stale'") == "1")
stale.close()

section("an unexpired pending registration holds the name")
held = Client("stale2")
mark = held.mark()
held.send(f"REGISTER * held@example.org {PASSWORD}")
held.wait_for("REGISTER", seconds=20)
held.close()
again = Client("stale2b")
mark = again.mark()
again.send(f"REGISTER stale2 other@example.org {PASSWORD}")
again.wait_for("REGISTER", seconds=20)
check("second registration is refused",
      bool(again.find("FAIL REGISTER", lines=again.since(mark))), again.since(mark))
again.close()

section("before-connect")
early = connect_negotiating("earlybird")
mark = early.mark()
early.send(f"REGISTER * early@example.org {PASSWORD}")
early.wait_for("REGISTER", seconds=20)
check("REGISTER works before CAP END",
      bool(early.find("REGISTER VERIFICATION_REQUIRED earlybird", lines=early.since(mark))), early.since(mark))
early.send("CAP END")
check("connection still completes afterwards", bool(early.wait_for(" 376 ", " 422 ", seconds=5)), early.lines[-3:])
early.close()

section("registering costs what a failed login costs")

# Each REGISTER is a hash, a database row and a message to an address the
# client chose. Unbounded, that is an open mail relay for anybody who can
# connect. It is charged to the address like a failed login, and never
# refunded; and no address is mailed twice in a quarter hour whoever asks.
STAMP = format(int(time.time()) % 100000, "05d")
import os as _os

CONFIG = _os.environ.get("SMOKE_CONFIG", "")
original = open(CONFIG).read() if CONFIG else ""


def rehash_with(*changes):
    """Rewrite the server's configuration and make it read it again. The
    registration window and the per-address mail gap are off for the suites,
    which register and reset dozens of accounts from one address within
    seconds; this is the one place either is turned on."""
    text = original
    for old, new in changes:
        assert old in text, old
        text = text.replace(old, new, 1)
    open(CONFIG, "w").write(text)
    op = Client(f"cfg{STAMP}{abs(hash(changes)) % 100}")
    op.send(f"OPER {_os.environ.get('SMOKE_OPER_NAME', 'smokeoper')} "
            f"{_os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
    op.wait_for(" 381 ", " 464 ", seconds=5)
    op.send("REHASH")
    op.wait_for(" 382 ", seconds=5)
    op.close()
    time.sleep(0.5)


if CONFIG:
    try:
        rehash_with(("max_registrations_per_ip = 0", "max_registrations_per_ip = 4"))
        clear_mail()
        answers = []
        for n in range(8):
            c = Client(f"burst{STAMP}{n}")
            mark = c.mark()
            c.send(f"REGISTER * burst{STAMP}{n}@example.org {PASSWORD}")
            # Either answer is an answer; waiting for one beats napping for
            # long enough that a busy machine usually manages it.
            c.wait_for("REGISTER", seconds=20)
            answers.append(" ".join(c.since(mark)))
            c.close()
        refused = [a for a in answers if "Too many registrations" in a]
        started = [a for a in answers if "VERIFICATION_REQUIRED" in a]
        check("a burst of registrations is cut off at the window",
              len(started) == 4 and len(refused) == 4 and "Too many registrations" in answers[-1],
              (len(started), len(refused), answers[-1][-90:]))
        time.sleep(1.0)
        check("and the mail that went out is no more than the allowance",
              len(wait_for_mail(1, seconds=5)) <= 4, len(wait_for_mail(1, seconds=2)))
    finally:
        rehash_with()

    # And the address's own say: one message per gap, whoever asks.
    try:
        rehash_with(("mail_gap_secs = 1", "mail_gap_secs = 900"))
        clear_mail()
        twice = Client(f"same{STAMP}")
        twice.send(f"REGISTER * shared{STAMP}@example.org {PASSWORD}")
        twice.wait_for("REGISTER", seconds=20)
        first_mail = len(wait_for_mail(1, seconds=8))
        again = Client(f"same{STAMP}b")
        mark = again.mark()
        again.send(f"REGISTER * shared{STAMP}@example.org {PASSWORD}")
        again.wait_for("REGISTER", seconds=20)
        check("a second registration to the same address within the gap is refused",
              bool(again.find("TEMPORARILY_UNAVAILABLE", lines=again.since(mark))) and first_mail == 1,
              (first_mail, again.since(mark)[-2:]))
        time.sleep(1.0)
        check("and that address got one message, not two", len(wait_for_mail(1, seconds=2)) == 1,
              len(wait_for_mail(1, seconds=1)))
        twice.close()
        again.close()
    finally:
        rehash_with()

section("expiry: a name and a room nobody has used in a long time are let go")

# [expiry] is off in the harness. It is turned on here with the clocks of two
# accounts and their channels wound back past the policy. One pair is idle and
# goes; the other is in use — a live login, a founder standing in the room —
# and stays, because a sweep looks at who is here before it looks at the clock.
if CONFIG:
    def verified_account(nick):
        c = Client(nick)
        c.send(f"REGISTER * {nick}@example.org {PASSWORD}")
        # The row has to exist before the next line marks it verified.
        c.wait_for("REGISTER", seconds=20)
        c.close()
        db(f"UPDATE users SET verified = 1 WHERE nick_lower = '{nick.lower()}'")

    def login(account):
        # A registered nick is reserved until its owner has logged in, and
        # NICK goes before AUTHENTICATE — so the connection uses another.
        s = connect_negotiating(f"{account}c", caps=["sasl"])
        s.sasl_plain(account, PASSWORD)
        s.send("CAP END")
        s.wait_for(" 001 ", seconds=5)
        return s

    idle, busy = f"idle{STAMP}", f"busy{STAMP}"
    idle_ch, busy_ch = f"#idle{STAMP}", f"#busy{STAMP}"
    verified_account(idle)
    time.sleep(1.2)  # the per-address mail gap
    verified_account(busy)
    i = login(idle)
    i.send(f"JOIN {idle_ch}")
    i.read(1.0)
    i.close()
    b = login(busy)
    b.send(f"JOIN {busy_ch}")
    b.read(1.0)
    founders = (db(f"SELECT founder FROM channels WHERE LOWER(name) = '{idle_ch}'"),
                db(f"SELECT founder FROM channels WHERE LOWER(name) = '{busy_ch}'"))
    check("each account founded a channel", founders == (idle, busy), founders)
    long_ago = "UNIX_TIMESTAMP() - 40 * 86400"
    db(f"UPDATE users SET last_seen = {long_ago} WHERE nick_lower IN ('{idle}', '{busy}')")
    db(f"UPDATE channels SET last_used = {long_ago} WHERE LOWER(name) IN ('{idle_ch}', '{busy_ch}')")
    bmark = b.mark()
    rehash_with(("[limits]", "[expiry]\naccounts_days = 30\nchannels_days = 30\n\n[limits]"))
    time.sleep(2.5)
    check("the idle account is erased",
          db(f"SELECT COUNT(*) FROM users WHERE nick_lower = '{idle}'") == "0")
    check("and its channel has no founder",
          db(f"SELECT founder FROM channels WHERE LOWER(name) = '{idle_ch}'") == "")
    check("the account somebody is logged in to stays",
          db(f"SELECT COUNT(*) FROM users WHERE nick_lower = '{busy}'") == "1")
    seen = db(f"SELECT last_seen FROM users WHERE nick_lower = '{busy}'")
    check("with its clock set to now", seen.isdigit() and int(time.time()) - int(seen) < 120, seen)
    check("and the channel its founder is standing in stays",
          db(f"SELECT founder FROM channels WHERE LOWER(name) = '{busy_ch}'") == busy)
    b.read(0.5)
    check("and that founder was not told anything", not b.find("no longer", lines=b.since(bmark)), b.since(bmark)[-2:])
    taker = Client(idle)
    taker.read(0.5)
    check("the freed nick can be taken", bool(taker.find(" 001 ")) and not taker.find(" 433 "), taker.lines[-2:])
    # An operator's NOEXPIRE keeps a name and a room whatever the clock says.
    kept, kept_ch = f"kept{STAMP}", f"#kept{STAMP}"
    verified_account(kept)
    k = login(kept)
    k.send(f"JOIN {kept_ch}")
    k.read(1.0)
    k.close()
    db(f"UPDATE users SET last_seen = {long_ago} WHERE nick_lower = '{kept}'")
    db(f"UPDATE channels SET last_used = {long_ago} WHERE LOWER(name) = '{kept_ch}'")
    noop = Client(f"noexp{STAMP}")
    noop.send(f"OPER {_os.environ.get('SMOKE_OPER_NAME', 'smokeoper')} {_os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
    noop.wait_for(" 381 ", " 464 ", seconds=5)
    nmark = noop.mark()
    noop.send(f"NOEXPIRE {kept} ON")
    noop.send(f"NOEXPIRE {kept_ch} ON")
    noop.send(f"NOEXPIRE nosuch{STAMP} ON")
    noop.read(1.2)
    check("NOEXPIRE marks an account and a channel",
          len(noop.find("NOTE NOEXPIRE STATUS", "kept whatever", lines=noop.since(nmark))) == 2
          and bool(noop.find("FAIL NOEXPIRE NO_SUCH_TARGET", lines=noop.since(nmark))), noop.since(nmark)[-3:])
    rehash_with(("[limits]", "[expiry]\naccounts_days = 30\nchannels_days = 30\n\n[limits]"))
    time.sleep(2.5)
    check("and the sweep leaves them alone",
          db(f"SELECT COUNT(*) FROM users WHERE nick_lower = '{kept}'") == "1"
          and db(f"SELECT founder FROM channels WHERE LOWER(name) = '{kept_ch}'") == kept)
    nmark = noop.mark()
    noop.send(f"NOEXPIRE {kept}")
    noop.read(0.8)
    check("and says so when asked", bool(noop.find("NOTE NOEXPIRE STATUS", "kept whatever", lines=noop.since(nmark))), noop.since(nmark)[-2:])
    noop.close()
    taker.close()
    newcomer = Client(f"newc{STAMP}")
    newcomer.send(f"JOIN {idle_ch}")
    newcomer.read(1.0)
    check("and the freed channel is anybody's again",
          bool(newcomer.find(" 353 ", f"@newc{STAMP}")), newcomer.lines[-3:])
    newcomer.close()
    b.close()
    rehash_with()

section("GROUP: the other names you go by")

# An account's own name is reserved for it. GROUP reserves the nick you are
# using as well; being logged in is then enough to use it, and nobody else
# can. It goes when the account goes.
if CONFIG:
    grp = f"grp{STAMP}"
    verified_account(grp)
    g = login(grp)
    # The login connects under another name, because a registered nick is
    # reserved until its owner has logged in; now that they have, it is theirs.
    g.send(f"NICK {grp}")
    g.read(0.8)
    gmark = g.mark()
    g.send("GROUP")
    g.read(0.8)
    check("an account's own name is already its own",
          bool(g.find("FAIL GROUP ALREADY_YOURS", lines=g.since(gmark))), g.since(gmark)[-2:])
    g.send(f"NICK alt{STAMP}")
    g.read(0.8)
    gmark = g.mark()
    g.send("GROUP")
    g.read(0.8)
    check("GROUP reserves the nick being used", bool(g.find("NOTE GROUP GROUPED", f"alt{STAMP}", lines=g.since(gmark))), g.since(gmark)[-2:])
    gmark = g.mark()
    g.send("GROUP *")
    g.read(0.8)
    check("and lists it beside the account", bool(g.find("NOTE GROUP NICKS", grp, f"alt{STAMP}", lines=g.since(gmark))), g.since(gmark)[-2:])
    stranger = Client(f"str{STAMP}")
    smark = stranger.mark()
    stranger.send(f"NICK alt{STAMP}")
    stranger.read(0.8)
    check("nobody else can take a grouped nick", bool(stranger.find(" 433 ", "registered", lines=stranger.since(smark))), stranger.since(smark)[-2:])
    smark = stranger.mark()
    stranger.send(f"REGISTER alt{STAMP} str@example.org {PASSWORD}")
    stranger.wait_for("REGISTER", seconds=20)
    check("nor register it as an account", bool(stranger.find("FAIL REGISTER", lines=stranger.since(smark))), stranger.since(smark)[-2:])
    stranger.close()
    # Away from the grouped nick and back again: it is still theirs to wear.
    g.send(f"NICK {grp}")
    g.read(0.8)
    gmark = g.mark()
    g.send(f"NICK alt{STAMP}")
    g.read(0.8)
    check("its owner can wear it again, being logged in to the account",
          bool(g.find("NICK", f"alt{STAMP}", lines=g.since(gmark))), g.since(gmark)[-2:])
    other = login(grp)
    other.send(f"NICK two{STAMP}")
    other.read(0.8)
    omark = other.mark()
    other.send("GROUP")
    other.read(0.8)
    check("and a second connection's nick can be grouped too",
          bool(other.find("NOTE GROUP GROUPED", f"two{STAMP}", lines=other.since(omark))), other.since(omark)[-2:])
    other.close()
    gmark = g.mark()
    g.send(f"GROUP -two{STAMP}")
    g.read(0.8)
    check("GROUP -<nick> gives one back", bool(g.find("NOTE GROUP RELEASED", f"two{STAMP}", lines=g.since(gmark))), g.since(gmark)[-2:])
    freed = Client(f"two{STAMP}")
    check("and it is anybody's again", bool(freed.find(" 001 ")) and not freed.find(" 433 "), freed.lines[-2:])
    freed.close()
    g.close()

summary("account")
