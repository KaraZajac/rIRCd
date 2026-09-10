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

One test does not pass, and it is not a conformance defect:

- `testLinksWithServices` expects services to appear in `LINKS` as a linked
  server named `My.Little.Services`. rIRCd's services are built into the
  server, so there is no second server; reporting one would put a false claim
  about the network's shape on the wire.

The controller turns on `multiclient` and `persistent_sessions`, which are off
by default. Both change what an account means — one connection or several, and
whether logging in takes a nick back — so they are the operator's decision, not
the server's.

## Against another server

irctest is the only measure that compares IRC servers on the same terms, so it
is worth pointing it at one. Ergo is the closest comparison — modern, IRCv3
first, with accounts and history built in the way rIRCd has them.

```
curl -sL https://github.com/ergochat/ergo/releases/download/v2.19.1/ergo-2.19.1-linux-x86_64.tar.gz | tar xz
cd target/irctest && PATH=$PWD/../../ergo-2.19.1-linux-x86_64:$PATH \
  ../irctest-venv/bin/pytest --controller irctest.controllers.ergo \
  -m 'not implementation-specific and not deprecated and not strict' \
  --deselect 'irctest/server_tests/links.py::ServicesLinksTestCase::testLinksWithServices' \
  --timeout 600 -n 4 -q -rs
```

Same checkout, same markers, same machine, 10 September 2026:

| | rIRCd 1.4.0 | Ergo 2.19.1 |
|---|---|---|
| passed | **544** | 527 |
| failed | 0 | 0 |
| skipped | **10** | 26 |

Neither fails anything. The difference is all in the skips, and a skip is the
harness being told the server does not do that at all: Ergo skips
`ACCOUNTEXTBAN`, all four `ELIST` search tokens, `INVITE_LIST`, `MULTI_NAMES`,
`LINKS`, `WALLOPS` and SASL re-authentication. rIRCd runs every test Ergo runs
and sixteen more, and passes them.

Four of the ten rIRCd skips are not a gap at all. irctest parametrises the
casemapping tests over `ascii` and `rfc1459` and skips whichever the server does
not advertise; rIRCd implements both, so the other four pass under the other
setting:

    IRCTEST_RIRCD_CASEMAPPING=rfc1459 tests/irctest/run.sh -k ChannelCaseSensitivity
    4 passed, 2 skipped

Which is the mirror of the default run. Across the two configurations rIRCd
passes 548 of the 557 tests collected, and the six that never run are two for
non-UTF-8 messages — refused on purpose, this server advertises `UTF8ONLY` — and
four `WHO` tests irctest marks "not consistently implemented" and skips for
everybody.

There is also a `strict` marker for tests asserting a stricter reading than the
specification requires. They are left out of the default run because passing
them is a choice rather than conformance, but they are worth running:

    IRCTEST_MARKERS=strict tests/irctest/run.sh
    4 passed

One of those four used to fail, and it was a real defect rather than a strict
reading: rIRCd asked for channel operator status to `INVITE` on any channel,
where the specifications ask for it only on an invite-only one.

Read it for what it is. It is one comparison against one server on one
selection of tests, it says nothing about the several servers irctest supports
that are not measured here, and Ergo does things irctest has no test for. What
it does say is that on the tests both servers are asked, rIRCd answers more of
them.

## Failures are findings

A failure here is a claim about rIRCd, not about the harness — but check which
it is before changing the server. The suite found that `QUIT` never closed the
connection: rIRCd removed the client from its own state and left the socket
open until it timed out.
