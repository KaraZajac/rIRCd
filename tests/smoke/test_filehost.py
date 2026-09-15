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

summary("filehost")
