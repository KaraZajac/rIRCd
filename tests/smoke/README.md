# Smoke tests

End-to-end checks that talk raw IRC to a real `rircd` process, backed by a
throwaway MariaDB and a local SMTP sink. `cargo test` covers pure logic (message
formatting, RFC 8291 encryption vectors, capability gating); these cover the parts
that only show up when a server is actually running: registration flows, mail
delivery, push triggers, numerics on the wire.

## Running

```bash
tests/smoke/run.sh                  # bring everything up, run every suite, tear down
tests/smoke/run.sh --keep           # ... and leave the server running afterwards
tests/smoke/run.sh --serve-only     # just bring a server up, no tests
tests/smoke/run.sh --reuse          # run suites against an environment already up
tests/smoke/run.sh test_core.py     # one suite
tests/smoke/run.sh --stop           # stop a --keep/--serve-only environment
```

Suites use per-run names for accounts and channels, so `--reuse` can re-run them
against a live server without tripping over what an earlier run created.

Requires `mariadbd`, `mariadb`, `mariadb-install-db` and `python3` on PATH — no
Python packages, no running database service, no root. Everything lands in
`target/smoke/` and is wiped at the start of each non-`--reuse` run.

Override ports and paths with `SMOKE_IRC_PORT`, `SMOKE_WS_PORT`, `SMOKE_DB_PORT`,
`SMOKE_SMTP_PORT`, `SMOKE_BIND` and `SMOKE_DIR`. `SMOKE_BIND` defaults to
`127.0.0.1`; point it at `0.0.0.0` only if you want clients on other machines to
reach the test server.

## What's here

| File | |
|---|---|
| `run.sh` | Brings up MariaDB, the SMTP sink and `rircd`, then runs the suites |
| `harness.py` | `Client` (raw IRC socket), `check()`/`summary()`, database and mail helpers |
| `smtpsink.py` | Minimal SMTP server that writes each message to `target/smoke/mail/` |
| `wsclient.py` | Minimal WebSocket client (handshake and framing) for the transport suite |
| `test_core.py` | Capability negotiation, ISUPPORT, channels, messaging, queries, numerics |
| `test_ircv3.py` | Every advertised capability on the wire: SASL 3.2, client-only tags, multiline, redaction and edits, chathistory, MONITOR, metadata, channel-rename, STATUSMSG, oper-tag, channel modes, utf8only |
| `test_features.py` | SCRAM-SHA-256, cloaking, auto-join, WEBIRC, history cursors, event playback, client batches, bans/exceptions/quiets, monitor masks, read-marker persistence, REHASH |
| `test_websocket.py` | The IRCv3 WebSocket transport, including messaging between ws and tcp clients |
| `test_account.py` | `REGISTER`, email verification, `VERIFY`, SASL gating on unverified accounts |
| `test_webpush.py` | `WEBPUSH` subscription handling and which messages trigger a push |
| `test_db_outage.py` | What the server does while MariaDB is stopped — **not** in the default run, since it takes the database down |

## Notes

The generated config turns on every optional subsystem so the suites can reach
them: `[email]` points at the sink with `encryption = "none"`, and `[webpush]`
sets `allow_private_endpoints = true` so a subscription can name a closed local
port. Neither belongs in a real deployment.

There is no push service in the loop, so `test_webpush.py` reads the server log
and counts delivery *attempts*. A delivery that fails at connect still proves the
trigger fired, the subscription was loaded and the payload encrypted — the parts
this project owns. The encryption itself is checked against the RFC 8291 test
vector in `cargo test`.

## Measuring

Two tools that are measurements rather than pass/fail checks, so they are not
part of `run.sh`. Both want a **release** build: a debug one is several times
slower and the numbers mean nothing.

```
cargo build --release
tests/smoke/run.sh --serve-only          # database and a server
python3 tests/smoke/throughput.py 200 20 # 200 listening, 20 talking
python3 tests/smoke/loadtest.py 2000     # how many clients it holds
```

`throughput.py` reports two latencies and they answer different questions.
*Saturated* is every sender posting at once and is how long the queue takes to
drain. *One message* sends one and waits for it to reach everybody before
sending the next, which is what a person actually experiences.

Numbers from one run, so that a change which makes things worse is visible
rather than merely unmeasured. Release build, 16-core desktop, 10 September
2026, everything on loopback:

| | |
|---|---|
| Deliveries per second, saturated | ~100,000 |
| Server CPU per delivery | ~21 µs |
| Latency of one message to 219 recipients | 4.6 ms median, 12.0 ms p99 |
| 2,000 clients connected, registered and joined | 5.9 s (340/s) |
| Memory per client | ~22 KB (76 MB at 2,000) |
| Idle round trip at 2,000 clients | 0.61 ms median |

Loopback flatters latency and a desktop flatters CPU, so treat these as a
before-and-after for this machine rather than as a claim about anyone else's.
What they are for is noticing that a change cost 30% — every one of the
denial-of-service problems fixed in 1.4.0 showed up first as a latency that
went from under a millisecond to hundreds.

## Writing a new suite

```python
from harness import Client, check, section, summary

section("what this group covers")
c = Client("nick")                  # connects and completes registration
mark = c.mark()
c.send("SOMETHING")
c.read(1.0)
check("the server said something useful", bool(c.find(" 001 ", lines=c.since(mark))), c.since(mark))
c.close()
summary("my suite")                 # prints totals, exits non-zero on failure
```

Add the filename to the default list in `run.sh`.
