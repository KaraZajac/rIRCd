#!/usr/bin/env python3
"""What the server says it does, it does.

ISUPPORT is a promise: a client that reads NICKLEN=32 will not offer a longer
one, and one that reads TOPICLEN=307 will not warn somebody their topic is
about to be cut. A number advertised and not enforced — or enforced at a
different number — is the server lying about itself, and the client has no
way to see through it.

Every expectation here is read out of the server's own ISUPPORT rather than
written down, so this suite does not check that the numbers are any
particular value. It checks that the numbers the server gives out are the
numbers it keeps.
"""
import time

from harness import Client, check, section, summary

RUN = format(int(time.time()) % 100000, "05d")
# Flood control drops what it will not carry, so filling a hundred-entry list
# from an ordinary connection would measure the rate limiter rather than the
# limit. The harness gives this address a class with room to do it.
BULK = "127.0.0.8"


def isupport_of(client):
    """Every ISUPPORT token, as a dict. Valueless tokens map to ''."""
    tokens = {}
    for line in client.find(" 005 "):
        # :server 005 nick TOKEN=value TOKEN … :are supported by this server
        body = line.split(" 005 ", 1)[1].split(" ", 1)[1]
        for tok in body.split(" :", 1)[0].split():
            name, _, value = tok.partition("=")
            tokens[name] = value
    return tokens


probe = Client(f"isup{RUN}")
TOKENS = isupport_of(probe)


def trailing(line, after):
    """The last parameter of a line, whether or not it was sent with a colon.

    A trailing parameter only needs its colon when it holds a space or is
    empty, so a one-word topic arrives without one."""
    _, _, rest = line.partition(after)
    rest = rest.strip()
    return rest[1:] if rest.startswith(":") else rest


def number(name):
    raw = TOKENS.get(name, "")
    return int(raw) if raw.isdigit() else None


section("the lengths it promises")

n = number("NICKLEN")
if n:
    fits, over = "n" * (n - 1), "n" * n + "x"
    mark = probe.mark()
    probe.send(f"NICK {fits}")
    probe.read(0.8)
    check(f"a nick of {n} characters is taken", bool(probe.find("NICK", fits, lines=probe.since(mark))),
          probe.since(mark)[-2:])
    mark = probe.mark()
    probe.send(f"NICK {over}")
    probe.read(0.8)
    check(f"one of {n + 1} is refused", bool(probe.find(" 432 ", lines=probe.since(mark))),
          probe.since(mark)[-2:])
    probe.send(f"NICK isup{RUN}")
    probe.read(0.5)

n = number("CHANNELLEN")
if n:
    fits = "#" + "c" * (n - 1)
    over = "#" + "c" * n
    mark = probe.mark()
    probe.send(f"JOIN {fits}")
    probe.read(1.0)
    check(f"a channel name of {n} is joined", bool(probe.find("JOIN", fits, lines=probe.since(mark))),
          probe.since(mark)[-2:])
    probe.send(f"PART {fits}")
    mark = probe.mark()
    probe.send(f"JOIN {over}")
    probe.read(1.0)
    check(f"one of {n + 1} is refused", bool(probe.find(" 403 ", lines=probe.since(mark))),
          probe.since(mark)[-2:])

n = number("KEYLEN")
if n:
    room = f"#key{RUN}"
    probe.join(room)
    mark = probe.mark()
    probe.send(f"MODE {room} +k {'k' * n}")
    probe.read(0.8)
    check(f"a key of {n} is taken", bool(probe.find("MODE", "+k", lines=probe.since(mark))),
          probe.since(mark)[-2:])
    probe.send(f"MODE {room} -k {'k' * n}")
    mark = probe.mark()
    probe.send(f"MODE {room} +k {'k' * (n + 1)}")
    probe.read(0.8)
    check(f"one of {n + 1} is refused", bool(probe.find(" 696 ", lines=probe.since(mark))),
          probe.since(mark)[-2:])

section("the lengths it cuts rather than refuses")

n = number("TOPICLEN")
if n:
    room = f"#top{RUN}"
    probe.join(room)
    probe.send(f"TOPIC {room} :{'t' * (n + 50)}")
    probe.read(1.0)
    mark = probe.mark()
    probe.send(f"TOPIC {room}")
    probe.read(1.0)
    shown = next((l for l in probe.since(mark) if " 332 " in l), "")
    kept = len(trailing(shown, f"{room} ")) if shown else -1
    check(f"a topic longer than {n} is cut to it, not refused", kept == n, (kept, shown[:80]))

n = number("AWAYLEN")
if n:
    probe.send(f"AWAY :{'a' * (n + 50)}")
    probe.read(0.8)
    watcher = Client(f"awy{RUN}")
    mark = watcher.mark()
    watcher.send(f"WHOIS isup{RUN}")
    watcher.wait_for(" 318 ", " 401 ", seconds=5)
    shown = next((l for l in watcher.since(mark) if " 301 " in l), "")
    kept = len(trailing(shown, f"isup{RUN} ")) if shown else -1
    check(f"an away message longer than {n} is cut to it", kept == n, (kept, shown[:80]))
    probe.send("AWAY")
    probe.read(0.5)
    watcher.close()

n = number("KICKLEN")
if n:
    room = f"#kick{RUN}"
    probe.join(room)
    victim = Client(f"vic{RUN}")
    victim.join(room)
    time.sleep(0.5)
    mark = victim.mark()
    probe.send(f"KICK {room} vic{RUN} :{'k' * (n + 50)}")
    victim.read(1.2)
    shown = next((l for l in victim.since(mark) if " KICK " in l), "")
    kept = len(trailing(shown, f"vic{RUN} ")) if shown else -1
    check(f"a kick comment longer than {n} is cut to it", kept == n, (kept, shown[:80]))
    victim.close()

section("the lists it says it holds")

n = number("CHANLIMIT").__class__ and (int(TOKENS["CHANLIMIT"].split(":")[1]) if TOKENS.get("CHANLIMIT", "").count(":") else None)
if n:
    joiner = Client(f"many{RUN}", source=BULK)
    # A line holds only so much, so fifty channel names go in handfuls.
    wanted_chans = [f"#many{RUN}x{i}" for i in range(n)]
    for i in range(0, len(wanted_chans), 10):
        joiner.send("JOIN " + ",".join(wanted_chans[i:i + 10]))
    # Wait for the last one rather than for a moment: joining fifty channels
    # is fifty channels' worth of work.
    joiner.wait_for(f"#many{RUN}x{n - 1} :End", seconds=30)
    joined = len({l.split()[3] for l in joiner.find(" 366 ")})
    mark = joiner.mark()
    joiner.send(f"JOIN #many{RUN}over")
    joiner.read(1.2)
    check(f"{n} channels are allowed", joined == n, joined)
    check("and the one after that is refused", bool(joiner.find(" 405 ", lines=joiner.since(mark))),
          joiner.since(mark)[-2:])
    joiner.close()

maxlist = TOKENS.get("MAXLIST", "")
if ":" in maxlist:
    letters, _, cap = maxlist.partition(":")
    cap = int(cap)
    letter = letters[0]
    room = f"#list{RUN}"
    lister = Client(f"lst{RUN}", source=BULK)
    lister.join(room)
    sent = 0
    while sent < cap:
        batch = min(4, cap - sent)
        masks = " ".join(f"m{sent + i}{RUN}!*@*" for i in range(batch))
        lister.send(f"MODE {room} +{letter * batch} {masks}")
        sent += batch
    mark = lister.mark()
    lister.send(f"MODE {room} {letter}")
    lister.wait_for(" 368 ", seconds=30)
    held = len(lister.find(" 367 ", lines=lister.since(mark)))
    check(f"a list takes the {cap} it promises", held == cap, held)
    mark = lister.mark()
    lister.send(f"MODE {room} +{letter} onemore{RUN}!*@*")
    lister.read(1.5)
    check("and refuses the one after that",
          bool(lister.find(" 478 ", lines=lister.since(mark))), lister.since(mark)[-2:])
    lister.close()

n = number("SILENCE")
if n:
    quiet = Client(f"sil{RUN}", source=BULK)
    for i in range(n):
        quiet.send(f"SILENCE +s{i}{RUN}!*@*")
    mark = quiet.mark()
    quiet.send("SILENCE")
    quiet.wait_for(" 272 ", seconds=20)
    held = len(quiet.find(" 271 ", lines=quiet.since(mark)))
    check(f"an ignore list takes the {n} it promises", held == n, held)
    mark = quiet.mark()
    quiet.send(f"SILENCE +over{RUN}!*@*")
    quiet.read(1.5)
    check("and refuses the one after that",
          bool(quiet.find(" 511 ", lines=quiet.since(mark))), quiet.since(mark)[-2:])
    quiet.close()

n = number("MONITOR")
if n:
    watch = Client(f"mon{RUN}", source=BULK)
    mark = watch.mark()
    # A hundred nicks do not fit on one line, so they go in handfuls.
    wanted = [f"w{i}{RUN}" for i in range(n + 1)]
    for i in range(0, len(wanted), 20):
        watch.send("MONITOR + " + ",".join(wanted[i:i + 20]))
    watch.read(2.0)
    check(f"a monitor list holds the {n} it promises, and says so at {n + 1}",
          bool(watch.find(" 734 ", lines=watch.since(mark))), watch.since(mark)[-2:])
    watch.close()

n = number("METADATA")
if n:
    keeper = Client(f"meta{RUN}", source=BULK)
    for i in range(n):
        keeper.send(f"METADATA * SET k{i}{RUN} :v")
    keeper.wait_for(f"k{n - 1}{RUN}", seconds=20)
    mark = keeper.mark()
    keeper.send(f"METADATA * SET over{RUN} :v")
    keeper.read(1.5)
    check(f"metadata holds the {n} keys it promises, and no more",
          bool(keeper.find("FAIL METADATA", lines=keeper.since(mark))), keeper.since(mark)[-2:])
    keeper.close()

section("a number that is configured is the number it advertises")

# CHANLIMIT used to be written into the token as a literal fifty while the
# configuration said whatever it said. The token is built from the setting
# now, so changing the setting has to change both the promise and the limit.
import os as _os

CONFIG = _os.environ.get("SMOKE_CONFIG", "")
if CONFIG:
    original = open(CONFIG).read()

    def rehash_to(text):
        open(CONFIG, "w").write(text)
        op = Client(f"cfg{RUN}")
        op.send(f"OPER {_os.environ.get('SMOKE_OPER_NAME', 'smokeoper')} "
                f"{_os.environ.get('SMOKE_OPER_PASSWORD', 'smoke-oper-password')}")
        op.wait_for(" 381 ", " 464 ", seconds=5)
        op.send("REHASH")
        op.wait_for(" 382 ", seconds=5)
        op.close()
        time.sleep(0.5)

    try:
        assert "max_channels_per_client = 50" in original
        rehash_to(original.replace("max_channels_per_client = 50",
                                   "max_channels_per_client = 7", 1))
        after = Client(f"few{RUN}")
        tokens = isupport_of(after)
        said = tokens.get("CHANLIMIT", "")
        check("the advertised channel limit follows the setting", said == "#:7", said)
        after.send("JOIN " + ",".join(f"#few{RUN}n{i}" for i in range(7)))
        after.wait_for(f"#few{RUN}n6 :End", seconds=20)
        mark = after.mark()
        after.send(f"JOIN #few{RUN}over")
        after.read(1.2)
        check("and the server keeps to it", bool(after.find(" 405 ", lines=after.since(mark))),
              after.since(mark)[-2:])
        after.close()
    finally:
        rehash_to(original)

probe.close()
summary("isupport")
