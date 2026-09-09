#!/usr/bin/env python3
"""Two servers, linked: what each one knows about the other.

Run through tests/smoke/run-link.sh, which brings up both servers with their own
databases and links them.
"""

import os
import socket
import time

from harness import Client, check, section, summary

HOST = os.environ.get("SMOKE_IRC_HOST", "127.0.0.1")
A_PORT = int(os.environ.get("LINK_A_PORT", "16687"))
B_PORT = int(os.environ.get("LINK_B_PORT", "16697"))
A_NAME = os.environ.get("LINK_A_NAME", "a.link.test")
B_NAME = os.environ.get("LINK_B_NAME", "b.link.test")
LINK_DIR = os.environ.get("LINK_DIR", "")
RUN = format(int(time.time()) % 100000, "05d")


def log(side):
    path = os.path.join(LINK_DIR, f"{side}.log")
    try:
        return open(path).read()
    except OSError:
        return ""


section("the link came up")
a_log, b_log = log("a"), log("b")
check("server A reports a link", "Linked" in a_log, a_log[-400:])
check("server B reports a link", "Linked" in b_log, b_log[-400:])
check("neither refused the other", "Refusing link" not in a_log + b_log,
      [l for l in (a_log + b_log).splitlines() if "Refusing link" in l][:3])

section("each server names the other in LINKS")
a = Client(f"la{RUN}", port=A_PORT)
b = Client(f"lb{RUN}", port=B_PORT)

mark = a.mark()
a.send("LINKS")
a.wait_for(" 365 ", seconds=5)
a_links = " ".join(a.find(" 364 ", lines=a.since(mark)))
check(f"A lists itself ({A_NAME})", A_NAME in a_links, a_links)
check(f"A lists B ({B_NAME})", B_NAME in a_links, a_links)

mark = b.mark()
b.send("LINKS")
b.wait_for(" 365 ", seconds=5)
b_links = " ".join(b.find(" 364 ", lines=b.since(mark)))
check(f"B lists itself ({B_NAME})", B_NAME in b_links, b_links)
check(f"B lists A ({A_NAME})", A_NAME in b_links, b_links)

section("each server is its own")
check("A welcomed its client", bool(a.find(" 001 ")), a.lines[:3])
check("B welcomed its client", bool(b.find(" 001 ")), b.lines[:3])
check("the two servers have different names", A_NAME != B_NAME)

section("the link port is not a client port")
# A client that reaches the link port must get nothing out of it: the two speak
# different protocols and answer to different secrets.
link_port = int(os.environ.get("LINK_B_LINK_PORT", "17010"))
s = socket.create_connection((HOST, link_port), timeout=5)
s.sendall(b"NICK intruder\r\nUSER intruder 0 * :intruder\r\n")
s.settimeout(3)
got = b""
try:
    while b"\r\n" not in got:
        chunk = s.recv(4096)
        if not chunk:
            break
        got += chunk
except (socket.timeout, OSError):
    pass
s.close()
text = got.decode("utf-8", "replace")
check("a client on the link port is not registered", " 001 " not in text, text[:200])
check("it is told why, or simply dropped",
      text == "" or "ERROR" in text, text[:200])

section("a split is noticed")
# Stop B and watch A report the split rather than carrying on as if nothing
# happened.
pid_path = os.path.join(LINK_DIR, "b.pid")
if os.path.exists(pid_path):
    os.kill(int(open(pid_path).read().strip()), 15)
    deadline = time.time() + 15
    saw_split = False
    while time.time() < deadline:
        if "Netsplit" in log("a"):
            saw_split = True
            break
        time.sleep(0.5)
    check("A noticed B going away", saw_split, log("a")[-400:])

    mark = a.mark()
    a.send("LINKS")
    a.wait_for(" 365 ", seconds=5)
    after = " ".join(a.find(" 364 ", lines=a.since(mark)))
    check("A no longer lists B", B_NAME not in after, after)
    check("A still lists itself", A_NAME in after, after)
    check("A is still serving", bool(Client(f"after{RUN}", port=A_PORT).find(" 001 ")))
else:
    check("server B's pid file was written", False, pid_path)

a.close()
summary("link")
