#!/usr/bin/env python3
"""Load test: how many clients the server holds, and how fast it delivers.

Not part of the smoke run — it is a measurement, not a pass/fail check.

    tests/smoke/run.sh --serve-only
    SMOKE_SERVER_PID=$(pgrep -f 'rircd --config') python3 tests/smoke/loadtest.py 2000

Each client registers, joins one shared channel and reads continuously, so the
numbers include the fan-out every message causes.
"""

import asyncio
import os
import resource
import subprocess
import sys
import time

HOST = os.environ.get("SMOKE_IRC_HOST", "127.0.0.1")
PORT = int(os.environ.get("SMOKE_IRC_PORT", "16667"))
CHANNEL = "#load"


def server_pid():
    if os.environ.get("SMOKE_SERVER_PID"):
        return int(os.environ["SMOKE_SERVER_PID"])
    # -x matches the executable name, so the shell that launched it is excluded.
    out = subprocess.run(["pgrep", "-x", "rircd"], capture_output=True, text=True)
    pids = [int(p) for p in out.stdout.split()]
    return max(pids) if pids else None


def server_rss_mb(pid):
    if not pid:
        return 0.0
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except OSError:
        pass
    return 0.0


def server_cpu_seconds(pid):
    if not pid:
        return 0.0
    try:
        fields = open(f"/proc/{pid}/stat").read().split()
        ticks = int(fields[13]) + int(fields[14])
        return ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError):
        return 0.0


class Client:
    """One connection that registers, joins, and counts what it receives."""

    def __init__(self, index):
        self.nick = f"load{index}"
        self.received = 0
        self.registered = False
        self.reader = None
        self.writer = None
        self.pong = asyncio.Event()

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(HOST, PORT)
        self.writer.write(f"NICK {self.nick}\r\nUSER {self.nick} 0 * :load\r\n".encode())
        await self.writer.drain()
        while True:
            line = await asyncio.wait_for(self.reader.readline(), timeout=30)
            if not line:
                raise ConnectionError("closed during registration")
            text = line.decode("utf-8", "replace")
            if " 376 " in text or " 422 " in text:
                self.registered = True
                break
        self.writer.write(f"JOIN {CHANNEL}\r\n".encode())
        await self.writer.drain()

    async def drain_forever(self):
        try:
            while True:
                line = await self.reader.readline()
                if not line:
                    return
                text = line.decode("utf-8", "replace")
                if "PRIVMSG" in text and "burst" in text:
                    self.received += 1
                elif text.startswith("PING"):
                    self.writer.write(("PONG" + text[4:]).encode())
                    await self.writer.drain()
                elif " PONG " in text:
                    self.pong.set()
        except (ConnectionError, asyncio.CancelledError):
            return

    def close(self):
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass


async def main(target):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, target * 2 + 256), hard))

    pid = server_pid()
    base_rss = server_rss_mb(pid)
    print(f"server pid {pid}, baseline {base_rss:.0f} MB")

    clients, drains = [], []
    started = time.time()
    batch = 250
    for base in range(0, target, batch):
        group = [Client(base + i) for i in range(min(batch, target - base))]
        results = await asyncio.gather(*(c.connect() for c in group), return_exceptions=True)
        for client, result in zip(group, results):
            if isinstance(result, Exception):
                print(f"  connection {client.nick} failed: {result!r}")
            else:
                clients.append(client)
                drains.append(asyncio.create_task(client.drain_forever()))
        rss = server_rss_mb(pid)
        print(
            f"  {len(clients):>5} connected  "
            f"{time.time() - started:6.1f}s  "
            f"server {rss:6.0f} MB  "
            f"({(rss - base_rss) * 1024 / max(len(clients), 1):.0f} KB/client)"
        )

    connect_elapsed = time.time() - started
    print(
        f"\n{len(clients)} clients registered and joined {CHANNEL} in "
        f"{connect_elapsed:.1f}s ({len(clients) / connect_elapsed:.0f}/s)"
    )
    await asyncio.sleep(2)

    # Round-trip latency with everyone connected: send PING, wait for the PONG
    # the reader task hands back. Sleeping a fixed time instead would just
    # measure the sleep.
    probe = clients[0]
    latencies = []
    for _ in range(10):
        probe.pong.clear()
        sent = time.perf_counter()
        probe.writer.write(b"PING latency\r\n")
        await probe.writer.drain()
        try:
            await asyncio.wait_for(probe.pong.wait(), timeout=10)
        except asyncio.TimeoutError:
            print("idle round trip: no PONG within 10s")
            latencies = []
            break
        latencies.append((time.perf_counter() - sent) * 1000)
        await asyncio.sleep(0.1)
    if latencies:
        latencies.sort()
        print(
            f"idle round trip: {latencies[0]:.2f} ms best, "
            f"{latencies[len(latencies) // 2]:.2f} ms median, "
            f"{latencies[-1]:.2f} ms worst"
        )

    # One sender, everyone receives: this is the fan-out cost.
    sender = clients[0]
    messages = 50
    for c in clients:
        c.received = 0

    # Idle cost of holding these connections, so it can be subtracted from the
    # fan-out measurement below rather than being charged to the messages.
    idle_start = server_cpu_seconds(pid)
    await asyncio.sleep(5)
    idle_cpu_per_s = (server_cpu_seconds(pid) - idle_start) / 5

    cpu_before = server_cpu_seconds(pid)
    start = time.time()
    for i in range(messages):
        sender.writer.write(f"PRIVMSG {CHANNEL} :burst {i}\r\n".encode())
        await sender.writer.drain()
        await asyncio.sleep(1.05)  # flood control allows about one a second

    expected = messages * (len(clients) - 1)
    deadline = time.time() + 60
    while time.time() < deadline:
        delivered = sum(c.received for c in clients if c is not sender)
        if delivered >= expected * 0.99:
            break
        await asyncio.sleep(0.5)
    elapsed = time.time() - start
    delivered = sum(c.received for c in clients if c is not sender)
    cpu_used = server_cpu_seconds(pid) - cpu_before

    # The sender pauses about a second between messages to stay inside the flood
    # allowance, so the rate here is set by that pacing, not by the server. What
    # this measures is the CPU each delivery costs at this channel size.
    work_cpu = max(cpu_used - idle_cpu_per_s * elapsed, 0.0)
    print(
        f"fan-out: {delivered} of {expected} deliveries, sender-paced over {elapsed:.1f}s"
    )
    print(
        f"  {work_cpu:.1f}s CPU for the messages "
        f"({work_cpu / max(delivered, 1) * 1e6:.0f} µs/delivery), "
        f"{idle_cpu_per_s * 100:.1f}% of a core idle at {len(clients)} clients"
    )
    print(f"peak memory: {server_rss_mb(pid):.0f} MB for {len(clients)} clients")

    for task in drains:
        task.cancel()
    for c in clients:
        c.close()


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    asyncio.run(main(count))
