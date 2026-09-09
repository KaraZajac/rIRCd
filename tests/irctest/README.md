# irctest

[irctest](https://github.com/progval/irctest) is the conformance suite the
established IRC servers are measured with: RFC 1459, RFC 2812, the
[Modern](https://modern.ircdocs.horse/) specification, and the IRCv3
extensions. Ergo, Solanum, InspIRCd, UnrealIRCd and others are tested with it
daily and [the results are published](https://dashboard.irctest.limnoria.net/).

Running it against rIRCd is the difference between saying "we advertise 42
capabilities" — a number we chose ourselves — and being measured on the same
terms as everyone else.

```sh
tests/irctest/run.sh                 # the whole suite
tests/irctest/run.sh -k Lusers       # one area
tests/irctest/run.sh --no-parallel   # one at a time, easier to read a failure
```

Anything else is handed to pytest, so `-x`, `-v` and `--durations=10` all work.
The first run clones irctest into `target/irctest` and builds a virtualenv in
`target/irctest-venv`; both are throwaway.

## What it needs

A MariaDB it may create and empty databases in. The smoke harness already
starts a throwaway one:

```sh
tests/smoke/run.sh --serve-only
```

Point it somewhere else with `IRCTEST_RIRCD_DB_HOST`, `_DB_PORT`, `_DB_USER`
and `_DB_PASSWORD`.

## `rircd.py`

The controller: it tells irctest how to configure and start rIRCd, and what
rIRCd claims to support, so tests for features we do not have are skipped
rather than failed.

Two things in it are worth knowing about.

**One database per pytest worker, emptied between tests.** irctest expects a
server that has just started with nothing in it. Building rIRCd's schema takes
about six seconds — thirty DDL statements, each its own MariaDB transaction —
so a database per test would cost more than the tests do. The database is
created once per worker and truncated at each server start instead, which
takes server startup from ~6s to ~0.3s. Workers get their own databases, so
`-n` stays isolated.

**Deselected tests.** `not implementation-specific` drops tests for another
server's own extensions — irctest doubles as the integration suite for Ergo and
Sable, and those tests assert their behaviour, not the specification's.
`not deprecated` drops superseded specifications such as the old METADATA
draft, and `not strict` drops tests asserting a stricter reading than the
specification requires. Override with `IRCTEST_MARKERS` to see them.

## What is left

Two tests do not pass, and neither is a conformance defect:

- `testReadMarkerPropagatedToOtherSessions` needs two live connections sharing
  one nick and account. That is session multiplexing — one user, several
  sockets — which rIRCd does not have: a nick belongs to a connection.
  `persistent_sessions` gives the neighbouring behaviour (logging in resumes
  your session rather than joining it), which is not what this test asks for.
- `testLinksWithServices` expects services to appear in `LINKS` as a linked
  server named `My.Little.Services`. rIRCd's services are built into the
  server, so there is no second server; reporting one would put a false claim
  about the network's shape on the wire.

## Failures are findings

A failure here is a claim about rIRCd, not about the harness — but check which
it is before changing the server. The suite found that `QUIT` never closed the
connection: rIRCd removed the client from its own state and left the socket
open until it timed out.
