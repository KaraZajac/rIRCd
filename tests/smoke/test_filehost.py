#!/usr/bin/env python3
"""Sharing a file in chat.

There is no NickServ and there is no upload bot: the server hosts the file
itself. A client asks ISUPPORT where to put one, PUTs it over HTTPS with the
same account credentials it uses for SASL, and pastes back the URL it is
given. That is the whole of draft/filehost, and this is the suite that says
it works — including the parts that are about somebody trying it on.
"""
import base64
import http.client
import os
import re
import ssl
import time

from harness import Client, check, clear_mail, section, summary, wait_for_mail

RUN = format(int(time.time()) % 100000, "05d")
HOST = os.environ.get("SMOKE_IRC_HOST", "127.0.0.1")
FH_PORT = int(os.environ.get("SMOKE_FILEHOST_PORT", "16671"))
PASSWORD = "filehost-password-1"
# Guessing is charged to the address it comes from, and the address every
# other suite uses is 127.0.0.1. The wrong-password checks come from
# somewhere else so they spend their own allowance and nobody else's.
GUESSER = "127.0.0.9"


def request(method, path, body=None, auth=None, source=None, headers=None):
    ctx = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(
        HOST, FH_PORT, context=ctx, timeout=20,
        source_address=(source, 0) if source else None,
    )
    sending = dict(headers or {})
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        sending["Authorization"] = "Basic " + token
    try:
        conn.request(method, path, body=body, headers=sending)
        r = conn.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    finally:
        conn.close()


def make_account(name):
    clear_mail()
    c = Client(name)
    c.send(f"REGISTER * {name}@example.org {PASSWORD}")
    c.wait_for("REGISTER", seconds=20)
    mail = wait_for_mail(1, seconds=20)
    found = re.search(rf"VERIFY {name} ([A-Z0-9]{{8}})", mail[0]) if mail else None
    if not found:
        raise RuntimeError(f"no verification code mailed for {name}")
    c.send(f"VERIFY {name} {found.group(1)}")
    c.read(2.0)
    c.close()


section("the server says where to put a file")

asker = Client(f"fh{RUN}")
advertised = ""
for line in asker.find(" 005 "):
    for tok in line.split(" 005 ", 1)[1].split(" ", 1)[1].split(" :", 1)[0].split():
        name, _, value = tok.partition("=")
        if name == "FILEHOST":
            advertised = value
check("ISUPPORT carries a FILEHOST somebody can post to",
      advertised.startswith("https://") and advertised.endswith("/uploads"), advertised)
check("and draft/FILEHOST alongside it, for clients that know it by that name",
      any("draft/FILEHOST=" in l for l in asker.find(" 005 ")), advertised)
asker.close()

PREFIX = "/" + advertised.split("/", 3)[3] if advertised.count("/") >= 3 else "/uploads"

section("which door the client came in by")

# One file host, and on a network reachable both by name and as a hidden
# service, two ways to reach it. A client that arrived through the onion
# service and is handed the public name has been asked to leave Tor to fetch
# a file — or its client refuses and sharing a file does not work for it at
# all. The second plain listener stands in for that door here.
def filehost_token(port):
    c = Client(f"d{port % 1000}{RUN}", port=port)
    found = ""
    for line in c.find(" 005 "):
        for tok in line.split(" 005 ", 1)[1].split(" ", 1)[1].split(" :", 1)[0].split():
            name, _, value = tok.partition("=")
            if name == "FILEHOST":
                found = value
    c.close()
    return found

from harness import IRC_PORT, IRC_PORT2

by_name = filehost_token(IRC_PORT)
by_other_door = filehost_token(IRC_PORT2)
check("a client on the usual listener is told the usual address",
      by_name == advertised, (by_name, advertised))
check("and one that came in by the other door is told that door's address",
      by_other_door.startswith("https://onion.invalid"), by_other_door)
check("which is a different answer to the same question",
      by_name != by_other_door, (by_name, by_other_door))
check("and the path is the same, because the files are",
      by_name.rsplit("/", 1)[-1] == by_other_door.rsplit("/", 1)[-1],
      (by_name, by_other_door))

# And the link handed back has to be for that door too. Behind a proxy every
# door arrives on the same socket, so the file host cannot tell them apart the
# way the IRC side can — what tells them apart is the name the client dialled,
# which the proxy passes on in Host. A client that uploaded over Tor and was
# handed a clearnet link has had the whole arrangement undone at the last step.
ONION_HOST = "onion.invalid"

section("who may put one there")

owner = f"own{RUN}"
make_account(owner)

status, _, _ = request("POST", PREFIX, body=b"no credentials")
check("without credentials, nothing is stored (401)", status == 401, status)

status, _, _ = request("POST", PREFIX, body=b"wrong", auth=(owner, "not-the-password"),
                       source=GUESSER)
check("with the wrong password either (403)", status == 403, status)

status, _, _ = request("POST", PREFIX, body=b"nobody", auth=(f"ghost{RUN}", PASSWORD),
                       source=GUESSER)
check("and an account that does not exist is no different (403)", status == 403, status)

section("putting one there, and getting it back")

payload = b"\x89PNG\r\n\x1a\n" + b"a picture of a cat" * 10
status, headers, body = request(
    "POST", PREFIX, body=payload, auth=(owner, PASSWORD),
    headers={"Content-Disposition": 'attachment; filename="cat.png"'},
)
check("an account may upload (201)", status == 201, (status, body[:120]))
url = headers.get("location", "")
check("and is told where it went, in the Location header and the body",
      url.startswith(advertised) and url.encode() == body.strip(), (url, body[:120]))
check("the name it was given keeps the extension it had", url.endswith(".png"), url)

path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else ""
status, headers, got = request("GET", path)
check("anybody with the link can fetch it back", status == 200, status)
check("and gets back exactly what was put there", got == payload, (len(got), len(payload)))
check("served as the kind of file it is", headers.get("content-type", "").startswith("image/png"),
      headers.get("content-type"))

status, _, _ = request("HEAD", path)
check("HEAD says it is there without sending it", status == 200, status)

status, _, _ = request("GET", f"{PREFIX}/nothing{RUN}.png")
check("a link to nothing is a plain 404", status == 404, status)

section("what it will not do")

status, _, _ = request("POST", PREFIX, body=b"x" * 70000, auth=(owner, PASSWORD))
check("a file past the configured size is refused (413)", status == 413, status)

status, _, _ = request("POST", PREFIX, body=b"", auth=(owner, PASSWORD))
check("and so is an empty one (400)", status == 400, status)

for attempt in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"):
    status, _, _ = request("GET", f"{PREFIX}/{attempt}")
    check(f"a link that tries to leave the directory gets nothing ({attempt[:14]})",
          status in (301, 400, 404), status)

section("guessing at a password over HTTP costs what guessing over IRC costs")

# The IRC side spends a careful allowance on every credential check. These are
# the same passwords, so the same allowance is spent here — otherwise all that
# care is one HTTP request away from being beside the point.
seen = []
for i in range(12):
    status, headers, _ = request("POST", PREFIX, body=b"g", auth=(owner, f"guess{i}"),
                                 source=GUESSER)
    seen.append(status)
    if status == 429:
        break
check("a run of wrong passwords is eventually told to wait (429)", 429 in seen, seen)
check("and it says how long to wait for",
      "retry-after" in {k for k in headers}, sorted(headers))

section("how much one account may put there")

filler = f"fil{RUN}"
make_account(filler)
allowed, refused = 0, 0
for i in range(8):
    status, _, _ = request("POST", PREFIX, body=f"file {i}".encode(), auth=(filler, PASSWORD))
    if status == 201:
        allowed += 1
    elif status == 429:
        refused += 1
        break
check("an account may upload up to its allowance", allowed > 0, allowed)
check("and is asked to stop after it", refused == 1, (allowed, refused))

section("who a request is from, behind a proxy")

# A file host usually sits behind a reverse proxy, where the socket address is
# the proxy's and is the same for everybody who came through it. One address
# means one failed-login budget for the lot, so whoever is guessing spends the
# allowance of every real user sharing that door — and on this network that
# door is also the one Tor clients arrive by. X-Forwarded-For is how the proxy
# says whose request it is passing on. Anybody may send the header; only an
# address the operator named as a proxy is taken at its word.
BEHIND = "203.0.113.10"
ALSO_BEHIND = "203.0.113.11"
NOT_A_PROXY = "127.0.0.11"

# A failed check is charged to the address and to the account both, so telling
# the two apart takes an account per address. Guessing at one account from one
# address must not be what stops somebody else.
guessed_at = f"gsd{RUN}"
make_account(guessed_at)
bystander = f"byst{RUN}"
make_account(bystander)

spent = []
for i in range(14):
    status, _, _ = request("POST", PREFIX, body=b"g", auth=(guessed_at, f"forwarded{i}"),
                           headers={"X-Forwarded-For": BEHIND})
    spent.append(status)
    if status == 429:
        break
check("a forwarded address is told to wait once it has been guessing",
      429 in spent, spent)

status, _, _ = request("POST", PREFIX, body=b"g", auth=(bystander, "also-wrong"),
                       headers={"X-Forwarded-For": ALSO_BEHIND})
check("and another address behind the same proxy still has its own allowance",
      status == 403, status)

# The other half of the same idea: the account being guessed at is the same
# account wherever it is tried from. Behind a hidden service there is no
# address to tell anybody apart by, so this is the part that protects it.
status, _, _ = request("POST", PREFIX, body=b"g", auth=(guessed_at, "from-elsewhere"),
                       headers={"X-Forwarded-For": ALSO_BEHIND})
check("but the account being guessed at is slowed wherever it is tried from",
      status == 429, status)

# The header only counts from the proxy. From anybody else it is a way of
# spending somebody else's allowance, or of dodging your own.
status, _, _ = request("POST", PREFIX, body=b"g", auth=(bystander, "wrong-again"),
                       source=NOT_A_PROXY, headers={"X-Forwarded-For": BEHIND})
check("a forwarded address from somebody who is not a proxy counts for nothing",
      status == 403, status)

section("the link points at the door the file came in by")

doorman = f"door{RUN}"
make_account(doorman)
status, headers, _ = request("POST", PREFIX, body=b"through the front door",
                             auth=(doorman, PASSWORD))
front = headers.get("location", "")
check("an upload with no Host of its own gets the usual address",
      front.startswith("https://127.0.0.1"), front)

status, headers, _ = request("POST", PREFIX, body=b"through the other door",
                             auth=(doorman, PASSWORD),
                             headers={"Host": f"{ONION_HOST}:{FH_PORT}"})
other = headers.get("location", "")
check("one that came in by the other door gets that door's address",
      other.startswith(f"https://{ONION_HOST}"), other)
check("which is a different link to the same file host",
      front.rsplit("/", 1)[0] != other.rsplit("/", 1)[0], (front, other))

# The header chooses among the operator's doors; it does not invent one.
status, headers, _ = request("POST", PREFIX, body=b"through a door nobody built",
                             auth=(doorman, PASSWORD),
                             headers={"Host": "evil.example"})
forged = headers.get("location", "")
check("a Host nobody configured gets the usual address, not its own",
      forged.startswith("https://127.0.0.1"), forged)

section("how long a shared file is kept")

# Disk is the one thing here nothing else reclaims. [expiry] uploads_days
# says how long a link is good for, which is a thing people can be told in
# advance — unlike "until the disk fills", which is what no setting means.
CONFIG = os.environ.get("SMOKE_CONFIG", "")
UPLOAD_DIR = os.environ.get("SMOKE_UPLOAD_DIR", "")
# Said out loud rather than skipped past: a section that quietly disappears
# when the harness stops exporting something is a section nobody notices is
# gone.
check("the harness says where the config and the uploads are",
      bool(CONFIG and UPLOAD_DIR), (CONFIG, UPLOAD_DIR))
if CONFIG and UPLOAD_DIR:
    original = open(CONFIG).read()

    def rehash_to(text):
        open(CONFIG, "w").write(text)
        op = Client(f"cfg{RUN}")
        op.send(f"OPER {os.environ.get('SMOKE_OPER_NAME', 'smokeoper')} "
                f"{os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
        op.wait_for(" 381 ", " 464 ", seconds=5)
        op.send("REHASH")
        op.wait_for(" 382 ", seconds=5)
        op.close()
        time.sleep(1.5)

    _, headers, _ = request("POST", PREFIX, body=b"yesterday's news", auth=(owner, PASSWORD))
    stale_url = headers.get("location", "")
    stale_on_disk = os.path.join(UPLOAD_DIR, stale_url.rsplit("/", 1)[1])
    _, headers, _ = request("POST", PREFIX, body=b"today's news", auth=(owner, PASSWORD))
    fresh_url = headers.get("location", "")
    fresh_on_disk = os.path.join(UPLOAD_DIR, fresh_url.rsplit("/", 1)[1])
    check("both files are on disk to begin with",
          os.path.exists(stale_on_disk) and os.path.exists(fresh_on_disk),
          (stale_on_disk, fresh_on_disk))

    # Two days back, so a one-day setting is past it and the other is not.
    old_enough = time.time() - 2 * 86400
    os.utime(stale_on_disk, (old_enough, old_enough))

    try:
        assert "[limits]" in original
        rehash_to(original.replace("[limits]", "[expiry]\nuploads_days = 1\n\n[limits]", 1))
        check("a file older than the setting is let go", not os.path.exists(stale_on_disk),
              stale_on_disk)
        check("and the one that is not stays", os.path.exists(fresh_on_disk), fresh_on_disk)
        status, _, _ = request("GET", "/" + stale_url.split("/", 3)[3])
        check("the link to it is a plain 404 now", status == 404, status)
        status, _, _ = request("GET", "/" + fresh_url.split("/", 3)[3])
        check("and the other link still works", status == 200, status)
    finally:
        rehash_to(original)

summary("filehost")
