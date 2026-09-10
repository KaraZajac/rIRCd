#!/usr/bin/env python3
"""Hours of ordinary use against a linked pair, watching for drift.

    tests/smoke/run-link.sh --serve-only
    python3 tests/smoke/soak.py 3600          # seconds, default one hour

The short runs answer "does it survive this?". This answers a different
question: does anything grow that should not, over long enough for growth to be
visible? A leak of a few hundred bytes a connection is invisible in four minutes
and obvious in four hours, and so is a queue that never quite drains.

So the load is deliberately unremarkable — people talking in channels, people
coming and going, messages crossing the link, the occasional nonsense — and what
is actually measured is whether the server looks the same at the end as it did
once it had warmed up. Memory, open files, and how long it takes to answer.

A verdict is printed at the end, and the numbers behind it as it goes, so a run
that is going wrong can be stopped without waiting for it to finish.
"""

import asyncio
import os
import random
import socket
import statistics
import subprocess
import sys
import time

HOST = os.environ.get("SMOKE_IRC_HOST", "127.0.0.1")
A_PORT = int(os.environ.get("LINK_A_PORT", "16687"))
B_PORT = int(os.environ.get("LINK_B_PORT", "16697"))
LINK_DIR = os.environ.get("LINK_DIR", "target/smoke/link")

SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 3600
RESIDENTS = int(os.environ.get("SOAK_RESIDENTS", "24"))
CHANNELS = ["#soak1", "#soak2", "#soak3"]
SAMPLE_EVERY = 30

# Long enough for caches to fill and the allocator to settle. Growth before this
# is the server getting going; growth after it is the thing being looked for.
WARMUP = 300

rng = random.Random(20260910)


def server_pids():
    """The two linked servers, not every rircd on the machine.

    run-link.sh borrows the smoke harness for its database, and that starts a
    server of its own; measuring it as well would fold a third, idle process
    into numbers meant to describe these two.
    """
    pids = []
    for side in ("a", "b"):
        try:
            pids.append(int(open(os.path.join(LINK_DIR, f"{side}.pid")).read().strip()))
        except (OSError, ValueError):
            pass
    if len(pids) == 2:
        return pids
    out = subprocess.run(["pgrep", "-x", "rircd"], capture_output=True, text=True)
    return sorted(int(p) for p in out.stdout.split())


def rss_kb(pid):
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def open_files(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return 0


def panics():
    total = 0
    for side in ("a", "b"):
        try:
            with open(os.path.join(LINK_DIR, f"{side}.log"), errors="replace") as f:
                total += sum(1 for line in f if "panicked" in line)
        except OSError:
            pass
    return total


class Talker:
    """Somebody who stays, joins channels and says things at a human rate."""

    def __init__(self, nick, port):
        self.nick, self.port = nick, port
        self.reader = self.writer = None
        self.sent = self.received = 0

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(HOST, self.port)
        self.writer.write(
            f"CAP LS 302\r\nCAP REQ :server-time message-tags batch echo-message account-tag\r\n"
            f"NICK {self.nick}\r\nUSER {self.nick} 0 * :{self.nick}\r\nCAP END\r\n".encode()
        )
        await self.writer.drain()
        while True:
            line = await asyncio.wait_for(self.reader.readline(), timeout=30)
            if not line:
                raise ConnectionError("closed during registration")
            if b" 376 " in line or b" 422 " in line:
                break
        for channel in CHANNELS:
            self.writer.write(f"JOIN {channel}\r\n".encode())
        await self.writer.drain()

    async def drain(self):
        try:
            while True:
                line = await self.reader.readline()
                if not line:
                    return
                self.received += 1
                if line.startswith(b"PING"):
                    self.writer.write(b"PONG" + line[4:])
                    await self.writer.drain()
        except (ConnectionError, asyncio.CancelledError, OSError):
            return

    async def talk(self, until):
        """One command a second is inside the flood allowance with room spare."""
        while time.time() < until:
            try:
                what = rng.random()
                if what < 0.70:
                    channel = rng.choice(CHANNELS)
                    self.writer.write(
                        f"PRIVMSG {channel} :soak {self.sent} {'x' * rng.randrange(0, 200)}\r\n".encode()
                    )
                elif what < 0.80:
                    self.writer.write(f"WHOIS resident{rng.randrange(RESIDENTS)}\r\n".encode())
                elif what < 0.87:
                    # Back and forth, so the name other people look up keeps
                    # existing — a rename that never returns quietly stops the
                    # WHOIS traffic crossing the link.
                    self.renamed = not getattr(self, "renamed", False)
                    taken = f"{self.nick}_" if self.renamed else self.nick
                    self.writer.write(f"NICK {taken}\r\n".encode())
                elif what < 0.93:
                    channel = rng.choice(CHANNELS)
                    self.writer.write(f"PART {channel}\r\nJOIN {channel}\r\n".encode())
                elif what < 0.97:
                    self.writer.write(f"TOPIC {rng.choice(CHANNELS)} :soak {self.sent}\r\n".encode())
                else:
                    self.writer.write(f"AWAY :back in {self.sent}\r\n".encode())
                await self.writer.drain()
                self.sent += 1
            except (ConnectionError, OSError):
                return
            await asyncio.sleep(rng.uniform(0.8, 1.6))


async def churn(until, stats):
    """People arriving and leaving, which is what a server does most of."""
    nonsense = [
        "WHO 0", "LIST", "LUSERS", "MOTD", "VERSION", "TIME", "ADMIN",
        "MODE #soak1", "NAMES #soak1", "USERHOST nobody", "ISON nobody",
        "METADATA * LIST", "MONITOR L", "CHATHISTORY LATEST #soak1 * 10",
        "WHOIS nobody", "TOPIC #soak1", "STATS m", "HELP",
    ]
    n = 0
    while time.time() < until:
        n += 1
        port = A_PORT if n % 2 else B_PORT
        try:
            reader, writer = await asyncio.open_connection(HOST, port)
        except OSError:
            await asyncio.sleep(0.5)
            continue
        try:
            writer.write(
                f"NICK churn{n % 9000}\r\nUSER c 0 * :c\r\nJOIN {rng.choice(CHANNELS)}\r\n".encode()
            )
            for _ in range(rng.randrange(1, 6)):
                writer.write((rng.choice(nonsense) + "\r\n").encode())
            writer.write(f"PRIVMSG {rng.choice(CHANNELS)} :passing through\r\n".encode())
            await writer.drain()
            await asyncio.sleep(rng.uniform(0.2, 1.0))
            stats["churned"] = n
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except OSError:
                pass
        await asyncio.sleep(rng.uniform(0.05, 0.4))


async def latency(until, samples):
    """How long an ordinary client waits, all the way through."""
    while time.time() < until:
        try:
            reader, writer = await asyncio.open_connection(HOST, A_PORT)
            nick = f"beat{int(time.time()) % 100000}"
            writer.write(f"NICK {nick}\r\nUSER b 0 * :b\r\n".encode())
            await writer.drain()
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=30)
                if not line or b" 001 " in line:
                    break
            started = time.time()
            writer.write(b"PING soakbeat\r\n")
            await writer.drain()
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=30)
                if not line:
                    break
                if b"soakbeat" in line:
                    samples.append((time.time(), (time.time() - started) * 1000))
                    break
            writer.close()
        except (ConnectionError, OSError, asyncio.TimeoutError):
            samples.append((time.time(), 30_000.0))
        await asyncio.sleep(5)


async def main():
    pids = server_pids()
    if len(pids) < 2:
        print("Expected two rircd processes; run tests/smoke/run-link.sh --serve-only first.")
        return 1
    print(f"soaking two linked servers for {SECONDS}s ({SECONDS / 3600:.1f}h), pids {pids}")
    panics_before = panics()

    residents = []
    for i in range(RESIDENTS):
        residents.append(Talker(f"resident{i}", A_PORT if i % 2 else B_PORT))
    for who in residents:
        try:
            await who.connect()
        except (ConnectionError, OSError, asyncio.TimeoutError) as e:
            print(f"  {who.nick} could not connect: {e}")
    print(f"  {sum(1 for r in residents if r.writer)} residents in {len(CHANNELS)} channels")

    until = time.time() + SECONDS
    stats = {"churned": 0}
    samples = []
    tasks = [asyncio.create_task(who.drain()) for who in residents if who.writer]
    tasks += [asyncio.create_task(who.talk(until)) for who in residents if who.writer]
    tasks.append(asyncio.create_task(churn(until, stats)))
    tasks.append(asyncio.create_task(latency(until, samples)))

    history = []
    started = time.time()
    while time.time() < until:
        await asyncio.sleep(SAMPLE_EVERY)
        now = time.time()
        point = {
            "at": now - started,
            "rss": [rss_kb(p) for p in pids],
            "fds": [open_files(p) for p in pids],
        }
        history.append(point)
        recent = [ms for at, ms in samples if at > now - SAMPLE_EVERY * 2]
        print(
            f"  {point['at'] / 60:6.1f} min   "
            f"rss {point['rss'][0] / 1024:6.1f} + {point['rss'][1] / 1024:6.1f} MB   "
            f"fds {point['fds'][0]:4d} + {point['fds'][1]:4d}   "
            f"ping {statistics.median(recent) if recent else float('nan'):6.1f} ms   "
            f"sent {sum(r.sent for r in residents):7d}   churn {stats['churned']:6d}",
            flush=True,
        )

    for task in tasks:
        task.cancel()
    await asyncio.sleep(0.5)

    # ── the verdict ──────────────────────────────────────────────────────────
    print()
    after_warmup = [p for p in history if p["at"] >= WARMUP] or history[len(history) // 2 :]
    first, last = (after_warmup[0], after_warmup[-1]) if len(after_warmup) >= 2 else (None, None)
    span_min = (last["at"] - first["at"]) / 60 if first else 0

    # A megabyte either way over a minute is the allocator breathing, and
    # multiplying it up to an hour turns breathing into an alarm. Below this
    # there is nothing honest to say about drift, so nothing is said.
    JUDGE_AFTER_MIN = 20
    if span_min < JUDGE_AFTER_MIN:
        print(
            f"ran for {(history[-1]['at'] / 60) if history else 0:.0f} min, "
            f"{span_min:.0f} of them after warm-up: too short to tell drift from "
            f"noise, so no verdict on it. Give it an hour or more."
        )
        for i, pid in enumerate(pids):
            print(
                f"server {pid}: memory ended at {history[-1]['rss'][i] / 1024:.1f} MB, "
                f"{history[-1]['fds'][i]} open files"
            )
    ok = True

    for i, pid in enumerate(pids) if span_min >= JUDGE_AFTER_MIN else []:
        grew = (last["rss"][i] - first["rss"][i]) / 1024
        per_hour = grew / (span_min / 60) if span_min else 0
        settled = abs(per_hour) < 16
        ok &= settled
        print(
            f"server {pid}: memory {first['rss'][i] / 1024:.1f} -> {last['rss'][i] / 1024:.1f} MB "
            f"over {span_min:.0f} min after warm-up "
            f"({per_hour:+.1f} MB/h) {'settled' if settled else 'STILL GROWING'}"
        )
        fd_grew = last["fds"][i] - first["fds"][i]
        fds_ok = fd_grew < 64
        ok &= fds_ok
        print(
            f"           open files {first['fds'][i]} -> {last['fds'][i]} "
            f"({fd_grew:+d}) {'steady' if fds_ok else 'LEAKING'}"
        )

    late = [ms for at, ms in samples if at - started >= WARMUP]
    early = [ms for at, ms in samples if at - started < WARMUP]
    if late:
        late_sorted = sorted(late)
        p99 = late_sorted[min(int(len(late_sorted) * 0.99), len(late_sorted) - 1)]
        responsive = p99 < 1000
        ok &= responsive
        print(
            f"answering:  median {statistics.median(late):.1f} ms, p99 {p99:.1f} ms "
            f"after warm-up (was {statistics.median(early):.1f} ms early on) "
            f"{'steady' if responsive else 'DEGRADED'}"
        )

    new_panics = panics() - panics_before
    ok &= new_panics == 0
    print(f"panics:     {new_panics} {'' if new_panics == 0 else '<- IN THE LOGS'}")

    still_up = 0
    for n, port in enumerate((A_PORT, B_PORT)):
        try:
            s = socket.create_connection((HOST, port), timeout=10)
            s.sendall(f"NICK soakend{n}\r\nUSER s 0 * :s\r\n".encode())
            s.settimeout(10)
            buf = b""
            while b" 001 " not in buf and b" 433 " not in buf:
                d = s.recv(65536)
                if not d:
                    break
                buf += d
            still_up += 1 if b" 001 " in buf else 0
            s.close()
        except OSError:
            pass
    ok &= still_up == 2
    print(f"serving:    {still_up} of 2 servers still register a new client")

    print()
    print("VERDICT:", "nothing drifted" if ok else "SOMETHING DRIFTED — see above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
