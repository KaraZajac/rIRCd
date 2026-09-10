#!/usr/bin/env python3
"""Throughput: how many messages, how many deliveries, and how long each took.

    python3 tests/smoke/throughput.py <receivers> <senders>

Every client sits in one channel, so each message a sender posts is delivered to
every receiver. Senders keep inside the flood allowance by pausing between
rounds, so the numbers measure the server, not its rate limiter.

Each message carries the clock reading it was sent at, so the time from posting
to arriving is measured per delivery rather than averaged over the batch. The
tail is the number that matters: a server can hold its rate up while one client
in a hundred waits a second, and the average will not say so.
"""

import asyncio
import os
import resource
import subprocess
import sys
import time

HOST = os.environ.get("SMOKE_IRC_HOST", "127.0.0.1")
PORT = int(os.environ.get("SMOKE_IRC_PORT", "16667"))
CHANNEL = "#throughput"

# What a current client actually negotiates. Capability sets are consulted once
# per recipient per message, so an empty set (NICK/USER only) measures a code
# path no real client takes.
CAPS = [
    "server-time", "message-tags", "account-tag", "batch", "labeled-response",
    "echo-message", "away-notify", "account-notify", "extended-join",
    "multi-prefix", "chghost", "invite-notify", "setname", "userhost-in-names",
    "cap-notify", "standard-replies", "draft/chathistory", "draft/read-marker",
]
NEGOTIATE = os.environ.get("SMOKE_CAPS", "1") != "0"


def server_pid():
    # -x matches the executable name, so the shell that launched it is excluded.
    out = subprocess.run(["pgrep", "-x", "rircd"], capture_output=True, text=True)
    pids = [int(p) for p in out.stdout.split()]
    return max(pids) if pids else None


def cpu_seconds(pid):
    fields = open(f"/proc/{pid}/stat").read().split()
    return (int(fields[13]) + int(fields[14])) / os.sysconf("SC_CLK_TCK")


class Client:
    def __init__(self, nick):
        self.nick = nick
        self.received = 0
        self.latencies = []

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(HOST, PORT)
        if NEGOTIATE:
            self.writer.write(
                f"CAP LS 302\r\nCAP REQ :{' '.join(CAPS)}\r\n"
                f"NICK {self.nick}\r\nUSER {self.nick} 0 * :t\r\nCAP END\r\n".encode()
            )
        else:
            self.writer.write(f"NICK {self.nick}\r\nUSER {self.nick} 0 * :t\r\n".encode())
        await self.writer.drain()
        while True:
            line = await asyncio.wait_for(self.reader.readline(), timeout=30)
            if not line:
                raise ConnectionError("closed")
            if b" 376 " in line or b" 422 " in line:
                break
        self.writer.write(f"JOIN {CHANNEL}\r\n".encode())
        await self.writer.drain()

    async def drain(self):
        try:
            while True:
                line = await self.reader.readline()
                if not line:
                    return
                if b"burst" in line:
                    self.received += 1
                    # The last field is the sender's clock reading, so the
                    # difference is the whole way round: in, through the one
                    # dispatch loop, fanned out, and back down this socket.
                    try:
                        sent_at = int(line.rsplit(b" ", 1)[1])
                        self.latencies.append((time.perf_counter_ns() - sent_at) / 1e6)
                    except (IndexError, ValueError):
                        pass
                elif line.startswith(b"PING"):
                    self.writer.write(b"PONG" + line[4:])
        except (ConnectionError, asyncio.CancelledError):
            return


async def main(receivers, senders):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, (receivers + senders) * 2 + 256), hard))
    pid = server_pid()

    clients = [Client(f"rx{i}") for i in range(receivers)] + [
        Client(f"tx{i}") for i in range(senders)
    ]
    for base in range(0, len(clients), 250):
        group = clients[base : base + 250]
        await asyncio.gather(*(c.connect() for c in group))
    tasks = [asyncio.create_task(c.drain()) for c in clients]
    await asyncio.sleep(2)
    print(f"{receivers} receivers and {senders} senders in {CHANNEL}")

    sending = clients[receivers:]
    # Each sender's flood budget is 10 messages, so one burst of 9 apiece keeps
    # the rate limiter out of the measurement entirely.
    per_sender = 9
    total_messages = per_sender * senders
    for c in clients:
        c.received = 0
        c.latencies.clear()
    expected = total_messages * (len(clients) - 1)

    cpu_before = cpu_seconds(pid)
    start = time.time()
    for i in range(per_sender):
        for s in sending:
            s.writer.write(
                f"PRIVMSG {CHANNEL} :burst {i} {time.perf_counter_ns()}\r\n".encode()
            )
    await asyncio.gather(*(s.writer.drain() for s in sending))

    deadline = time.time() + 180
    delivered = 0
    while time.time() < deadline:
        delivered = sum(c.received for c in clients)
        if delivered >= expected:
            break
        await asyncio.sleep(0.05)
    elapsed = time.time() - start
    cpu = cpu_seconds(pid) - cpu_before

    print(f"messages sent:      {total_messages}")
    print(f"deliveries:         {delivered} of {expected}")
    print(f"time to deliver:    {elapsed:.2f}s")
    print(f"message rate:       {total_messages / elapsed:,.0f}/s")
    print(f"delivery rate:      {delivered / elapsed:,.0f}/s")
    print(f"server CPU:         {cpu:.2f}s ({cpu / max(delivered, 1) * 1e6:.1f} µs per delivery)")

    def percentiles(samples, label):
        if not samples:
            return
        samples = sorted(samples)

        def at(fraction):
            return samples[min(int(len(samples) * fraction), len(samples) - 1)]

        print(
            f"{label:<22}p50 {at(0.50):.1f} ms   p95 {at(0.95):.1f} ms   "
            f"p99 {at(0.99):.1f} ms   worst {samples[-1]:.1f} ms"
        )

    # Under the burst, latency is how long the queue took to drain: every
    # message was posted before any of them had been delivered.
    percentiles([l for c in clients for l in c.latencies], "latency, saturated:")

    # And once more without saturating it: one message, waited for, before the
    # next is sent. That is the number that says whether the server is healthy —
    # how long one thing somebody said takes to reach everybody listening.
    for c in clients:
        c.latencies.clear()
        c.received = 0
    # The burst just spent every sender's flood allowance, which refills at a
    # token a second. Wait for it, then rotate the senders slowly enough that
    # each has one in hand by the time its turn comes round again — otherwise
    # this measures the rate limiter and calls it latency.
    await asyncio.sleep(2.0)
    rounds = 40
    per_round = 1.2 / max(len(sending), 1)
    missed = 0
    for i in range(rounds):
        sender = sending[i % len(sending)]
        started = time.time()
        sender.writer.write(
            f"PRIVMSG {CHANNEL} :burst one{i} {time.perf_counter_ns()}\r\n".encode()
        )
        await sender.writer.drain()
        want = (len(clients) - 1) * (i + 1 - missed)
        settle = time.time() + 2
        while sum(c.received for c in clients) < want and time.time() < settle:
            await asyncio.sleep(0.002)
        if sum(c.received for c in clients) < want:
            missed += 1
        remaining = per_round - (time.time() - started)
        if remaining > 0:
            await asyncio.sleep(remaining)
    if missed:
        print(f"({missed} of {rounds} single messages did not reach everybody)")
    percentiles([l for c in clients for l in c.latencies], "latency, one message:")

    for t in tasks:
        t.cancel()
    for c in clients:
        c.writer.close()


if __name__ == "__main__":
    rx = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    tx = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    asyncio.run(main(rx, tx))
