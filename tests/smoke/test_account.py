#!/usr/bin/env python3
"""draft/account-registration: REGISTER, email verification, VERIFY, SASL gating."""

import re

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
carol.read(2.5)
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
stale.read(2.5)
check("re-registration allowed once the code expired",
      bool(stale.find("REGISTER VERIFICATION_REQUIRED stale", lines=stale.since(mark))), stale.since(mark))
check("exactly one row for the name", db("SELECT COUNT(*) FROM users WHERE nick_lower='stale'") == "1")
stale.close()

section("an unexpired pending registration holds the name")
held = Client("stale2")
mark = held.mark()
held.send(f"REGISTER * held@example.org {PASSWORD}")
held.read(2.5)
held.close()
again = Client("stale2b")
mark = again.mark()
again.send(f"REGISTER stale2 other@example.org {PASSWORD}")
again.read(2.0)
check("second registration is refused",
      bool(again.find("FAIL REGISTER", lines=again.since(mark))), again.since(mark))
again.close()

section("before-connect")
early = connect_negotiating("earlybird")
mark = early.mark()
early.send(f"REGISTER * early@example.org {PASSWORD}")
early.read(2.5)
check("REGISTER works before CAP END",
      bool(early.find("REGISTER VERIFICATION_REQUIRED earlybird", lines=early.since(mark))), early.since(mark))
early.send("CAP END")
check("connection still completes afterwards", bool(early.wait_for(" 376 ", " 422 ", seconds=5)), early.lines[-3:])
early.close()

summary("account")
