#!/usr/bin/env python3
"""draft/webpush: subscription handling and which messages trigger a push.

There is no push service in the loop, so delivery ends in a connection error —
but only after the subscription was loaded and the payload encrypted, so the log
still tells us the trigger path ran end to end.
"""

import os
import time

from harness import (
    AUTH_SECRET,
    Client,
    P256DH,
    check,
    connect_negotiating,
    db,
    section,
    summary,
)

LOG = os.environ.get("SMOKE_SERVER_LOG", "")
ENDPOINT = "https://127.0.0.1:19443/push/erin"
PASSWORD = "hunter2secret"


def log_text():
    if LOG and os.path.exists(LOG):
        with open(LOG, errors="replace") as f:
            return f.read()
    return ""


def push_attempts():
    """Deliveries the server has attempted so far, successful or not."""
    text = log_text()
    return text.count("Web Push delivered") + text.count("Web Push delivery failed")


def encrypt_errors():
    return log_text().count("Web Push encrypt failed")


def wait_for_attempts(minimum, seconds=12.0):
    end = time.time() + seconds
    while time.time() < end:
        if push_attempts() >= minimum:
            return True
        time.sleep(0.3)
    return False


section("an account is required")
anon = Client("anon")
mark = anon.mark()
anon.send(f"WEBPUSH REGISTER {ENDPOINT} p256dh={P256DH};auth={AUTH_SECRET}")
anon.read(2.0)
check("refused without an account", bool(anon.find("FAIL WEBPUSH ACCOUNT_REQUIRED", lines=anon.since(mark))), anon.since(mark))
anon.close()

section("register an account to push to")
erin = Client("erin")
mark = erin.mark()
erin.send(f"REGISTER * erin@example.org {PASSWORD}")
erin.read(2.5)
registered = bool(erin.find("REGISTER SUCCESS", lines=erin.since(mark)))
if not registered:
    # Email verification is on in the full run: confirm the code from the sink.
    import re
    from harness import wait_for_mail

    body = "".join(wait_for_mail(1, seconds=15)[-1:])
    match = re.search(r"VERIFY erin ([A-Z0-9]{8})", body)
    check("verification code mailed", bool(match), body[:200])
    if match:
        erin.send(f"VERIFY erin {match.group(1)}")
        erin.read(2.0)
check("logged in", bool(erin.find(" 900 ")), erin.lines[-4:])

section("endpoint validation")
cases = [
    ("http://example.com/push/a", "must use https"),
    ("ftp://example.com/push/a", "must use https"),
    ("not-a-url", "not a valid URL"),
]
for endpoint, expected in cases:
    mark = erin.mark()
    erin.send(f"WEBPUSH REGISTER {endpoint} p256dh={P256DH};auth={AUTH_SECRET}")
    erin.read(2.0)
    new = erin.since(mark)
    check(f"rejected {endpoint}", bool(erin.find("FAIL WEBPUSH INVALID_PARAMS", lines=new)) and expected in " ".join(new), new)

for keys, label in [
    (f"p256dh=notakey;auth={AUTH_SECRET}", "bad p256dh"),
    (f"p256dh={P256DH};auth=c2hvcnQ", "short auth secret"),
    (f"auth={AUTH_SECRET}", "missing p256dh"),
    ("", "missing keys"),
]:
    mark = erin.mark()
    erin.send(f"WEBPUSH REGISTER https://example.com/push/x {keys}".rstrip())
    erin.read(2.0)
    check(f"rejected: {label}", bool(erin.find("FAIL WEBPUSH INVALID_PARAMS", lines=erin.since(mark))), erin.since(mark))

mark = erin.mark()
erin.send("WEBPUSH FROBNICATE https://example.com/push/x")
erin.read(1.5)
check("unknown subcommand rejected", bool(erin.find("FAIL WEBPUSH INVALID_PARAMS", lines=erin.since(mark))), erin.since(mark))

section("register and unregister")
mark = erin.mark()
erin.send(f"WEBPUSH REGISTER {ENDPOINT} p256dh={P256DH};auth={AUTH_SECRET}")
erin.read(2.5)
check("subscription accepted", bool(erin.find("WEBPUSH REGISTER", ENDPOINT, lines=erin.since(mark))), erin.since(mark))
check("stored against the account", db(f"SELECT account FROM webpush_subscriptions WHERE endpoint='{ENDPOINT}'") == "erin")

mark = erin.mark()
erin.send(f"WEBPUSH REGISTER {ENDPOINT} p256dh={P256DH};auth={AUTH_SECRET}")
erin.read(2.5)
check("re-registering the same endpoint replaces it",
      db(f"SELECT COUNT(*) FROM webpush_subscriptions WHERE endpoint='{ENDPOINT}'") == "1")

mark = erin.mark()
erin.send("WEBPUSH UNREGISTER https://127.0.0.1:19443/push/never-registered")
erin.read(1.5)
check("unregistering an unknown endpoint is not an error",
      bool(erin.find("WEBPUSH UNREGISTER", lines=erin.since(mark))) and not erin.find("FAIL", lines=erin.since(mark)),
      erin.since(mark))

section("what triggers a push")
erin.join("#push")
frank = Client("frank")
frank.join("#push")

before = push_attempts()
frank.send("PRIVMSG erin :are you awake?")
check("direct message pushes", wait_for_attempts(before + 1), f"attempts stayed at {push_attempts()}")

before = push_attempts()
frank.send("NOTICE erin :and a notice")
check("direct notice pushes", wait_for_attempts(before + 1), f"attempts stayed at {push_attempts()}")

before = push_attempts()
frank.send("PRIVMSG #push :erin: standup in five")
check("channel highlight pushes", wait_for_attempts(before + 1), f"attempts stayed at {push_attempts()}")

before = push_attempts()
frank.send("PRIVMSG #push :anyone been to the karaoke bar")
frank.send("PRIVMSG #push :just thinking out loud")
time.sleep(5)
check("ordinary channel chatter does not push", push_attempts() == before,
      f"attempts {before} -> {push_attempts()}")

before = push_attempts()
erin.send("PRIVMSG #push :erin talking about erin")
time.sleep(5)
check("a user is not pushed for their own message", push_attempts() == before,
      f"attempts {before} -> {push_attempts()}")

check("payloads encrypted without error", encrypt_errors() == 0)

section("failures are tracked")
failures = db(f"SELECT failures FROM webpush_subscriptions WHERE endpoint='{ENDPOINT}'")
check("failure counter advanced for the unreachable endpoint",
      failures.isdigit() and int(failures) >= 1, f"failures={failures}")

section("unregister")
mark = erin.mark()
erin.send(f"WEBPUSH UNREGISTER {ENDPOINT}")
erin.read(1.5)
check("UNREGISTER echoed", bool(erin.find("WEBPUSH UNREGISTER", ENDPOINT, lines=erin.since(mark))), erin.since(mark))
check("row removed", db(f"SELECT COUNT(*) FROM webpush_subscriptions WHERE endpoint='{ENDPOINT}'") == "0")

before = push_attempts()
frank.send("PRIVMSG erin :still there?")
time.sleep(5)
check("no push after unregistering", push_attempts() == before, f"attempts {before} -> {push_attempts()}")

erin.close()
frank.close()
summary("webpush")
