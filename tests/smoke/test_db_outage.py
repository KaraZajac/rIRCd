#!/usr/bin/env python3
"""What the server does while the database is unavailable.

Not in the default run: it stops MariaDB, so it would disturb anything else
using the environment. Run it on its own:

    tests/smoke/run.sh test_db_outage.py
"""

import os
import subprocess
import time

from harness import DB_SOCKET, RUN_ID, Client, check, section, summary

TAGS = ["message-tags", "server-time", "batch", "echo-message", "draft/chathistory"]
CHANNEL = f"#outage{RUN_ID}"


def mariadb_running():
    return (
        subprocess.run(
            ["mariadb", f"--socket={DB_SOCKET}", "-e", "SELECT 1"],
            capture_output=True,
        ).returncode
        == 0
    )


section("before the outage")
talker = Client(f"out{RUN_ID}a", caps=TAGS)
listener = Client(f"out{RUN_ID}b", caps=TAGS)
talker.join(CHANNEL)
listener.join(CHANNEL)
mark = listener.mark()
talker.send(f"PRIVMSG {CHANNEL} :before the outage")
listener.read(1.5)
check("messages flow", bool(listener.find("before the outage", lines=listener.since(mark))))

section("with the database stopped")
subprocess.run(["mariadb", f"--socket={DB_SOCKET}", "-e", "SHUTDOWN"], capture_output=True)
time.sleep(3)
check("the database really is down", not mariadb_running())

mark = listener.mark()
talker.send(f"PRIVMSG {CHANNEL} :during the outage")
listener.read(2.0)
check("messages still flow", bool(listener.find("during the outage", lines=listener.since(mark))),
      listener.since(mark))

mark = talker.mark()
talker.send("PING stillthere")
talker.read(2.0)
check("the server still answers", bool(talker.find("PONG", lines=talker.since(mark))))

mark = talker.mark()
talker.send(f"CHATHISTORY LATEST {CHANNEL} * 10")
talker.read(8.0)  # the first failing query waits out the pool's acquire timeout
check("CHATHISTORY says so rather than going quiet",
      bool(talker.find("FAIL CHATHISTORY", lines=talker.since(mark))), talker.since(mark))

mark = talker.mark()
talker.send(f"REGISTER * out{RUN_ID}@example.org hunter2secret")
talker.read(8.0)
check("REGISTER says so too",
      bool(talker.find("FAIL REGISTER TEMPORARILY_UNAVAILABLE", lines=talker.since(mark))),
      talker.since(mark))

newcomer = Client(f"out{RUN_ID}c")
check("new clients can still connect", bool(newcomer.find(" 001 ")), newcomer.lines[-3:])
newcomer.close()

section("after the database comes back")
here = os.getcwd()
subprocess.Popen(
    [
        "mariadbd",
        f"--datadir={here}/target/smoke/db",
        f"--socket={DB_SOCKET}",
        "--port=" + os.environ.get("SMOKE_DB_PORT", "3399"),
        f"--pid-file={here}/target/smoke/run/mariadb.pid",
        f"--tmpdir={here}/target/smoke/run",
        "--bind-address=127.0.0.1",
        "--skip-grant-tables",
        "--skip-name-resolve",
        f"--log-error={here}/target/smoke/run/mariadb.log",
    ],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
for _ in range(30):
    if mariadb_running():
        break
    time.sleep(1)
check("the database is back", mariadb_running())
time.sleep(12)  # let the circuit breaker's backoff lapse

mark = listener.mark()
talker.send(f"PRIVMSG {CHANNEL} :after recovery")
listener.read(2.0)
check("messages still flow", bool(listener.find("after recovery", lines=listener.since(mark))))

time.sleep(2)
mark = talker.mark()
talker.send(f"CHATHISTORY LATEST {CHANNEL} * 20")
talker.read(3.0)
replay = talker.find("PRIVMSG", CHANNEL, lines=talker.since(mark))
check("history works again without a restart", bool(replay), talker.since(mark)[:3])
check("what was said after recovery is in it",
      any("after recovery" in l for l in replay), [l[-30:] for l in replay])

talker.close()
listener.close()
summary("db-outage")
