#!/usr/bin/env python3
"""Session multiplexing: one account, several connections.

The thing worth testing here is the seam. Inside the server a connection has an
id and a user has an id, and for a client with one connection those two strings
are equal — so every place that confuses them works perfectly until somebody
opens a second connection. These tests open the second connection.
"""

import os
import subprocess
import time

from harness import Client, check, section, summary

RUN = format(int(time.time()) % 100000, "05d")
ACCOUNT = f"multi{RUN}"
PASSWORD = "multiclient-password"
CHAN = f"#multi{RUN}"

RIRCD = os.environ.get("SMOKE_RIRCD_BIN", "target/debug/rircd")
CONFIG = os.environ.get("SMOKE_CONFIG", "")


def make_account():
    out = subprocess.run(
        [RIRCD, "--config", CONFIG, "adduser", ACCOUNT],
        input=f"{PASSWORD}\n{PASSWORD}\n",
        capture_output=True,
        text=True,
    )
    return out.returncode == 0, (out.stdout + out.stderr).strip()


def session(nick=None, caps="sasl message-tags server-time echo-message account-tag"):
    """Another connection for the shared account.

    Same nick and same account is what makes it another session rather than
    another user — that is the rule the server applies.
    """
    nick = nick or ACCOUNT
    c = Client()
    c.send("CAP LS 302")
    c.read(0.5)
    c.send("CAP REQ :" + caps)
    c.read(0.3)
    c.sasl_plain(ACCOUNT, PASSWORD)
    c.send(f"NICK {nick}")
    c.send(f"USER {nick} 0 * :{nick}")
    c.nick = nick
    c.send("CAP END")
    c.wait_for(" 376 ", " 422 ", " 001 ", seconds=6)
    return c


section("account")
ok, detail = make_account()
check("account created for the session tests", ok, detail)

section("two connections, one user")
first = session()
first.join(CHAN)
second = session()

check(
    "a new connection is put back into the channels its user is in",
    bool(second.find("JOIN", CHAN)) and bool(second.find(" 366 ", CHAN)),
    second.lines[-6:],
)

mark = second.mark()
second.send(f"JOIN {CHAN}")
second.read(1.5)
check(
    "an explicit JOIN from a second connection is answered, not ignored",
    bool(second.find("JOIN", CHAN, lines=second.since(mark)))
    and bool(second.find(" 366 ", CHAN, lines=second.since(mark))),
    second.since(mark)[-4:],
)

# Count in the member list only: the channel here spells the same as the
# account, and appears earlier on the same line.
members = " ".join(
    l.split(f"{CHAN} ", 1)[-1] for l in second.find(" 353 ", lines=second.since(mark))
)
check(
    "the user is listed in the channel once, not once per connection",
    members.count(ACCOUNT) == 1,
    members,
)

# A mask search walks the whole client table, which answers to a user's own id
# and to every connection reaching it. Somebody with two clients open is still
# one person to WHO.
mark = second.mark()
second.send(f"WHO {ACCOUNT}*")
second.wait_for(" 315 ", seconds=5)
who_lines = second.find(" 352 ", lines=second.since(mark))
check(
    "WHO on a mask lists the user once, not once per connection",
    len(who_lines) == 1,
    who_lines,
)

section("privileges belong to the user, not the connection")
# `first` created the channel, so the *user* is an operator. Every op check has
# to agree, whichever connection asks.

mark = second.mark()
second.send(f"TOPIC {CHAN} :set from the second connection")
second.read(1.5)
check(
    "TOPIC from the second connection is allowed",
    not second.find(" 482 ", lines=second.since(mark)),
    second.since(mark)[-3:],
)

mark = second.mark()
second.send(f"MODE {CHAN} +m")
second.read(1.5)
check(
    "MODE from the second connection is allowed",
    not second.find(" 482 ", lines=second.since(mark)),
    second.since(mark)[-3:],
)

# +m is now set, and the user is an op, so both connections may still speak.
mark = first.mark()
second.send(f"PRIVMSG {CHAN} :speaking through the second connection")
first.read(1.5)
check(
    "a moderated channel still hears the second connection of an op",
    bool(first.find("speaking through the second connection", lines=first.since(mark))),
    first.since(mark)[-3:],
)

outsider = Client(f"out{RUN}")
outsider.join(CHAN)
mark = outsider.mark()
outsider.send(f"PRIVMSG {CHAN} :and this one should not get through")
outsider.read(1.5)
check(
    "a moderated channel still refuses an unvoiced outsider",
    bool(outsider.find(" 404 ", lines=outsider.since(mark))),
    outsider.since(mark)[-3:],
)

mark = second.mark()
second.send(f"MODE {CHAN} -m")
second.read(1.0)
second.send(f"KICK {CHAN} out{RUN} :goodbye")
second.read(1.5)
check(
    "KICK from the second connection is allowed",
    not second.find(" 482 ", lines=second.since(mark)),
    second.since(mark)[-3:],
)
check("the kick landed", bool(outsider.wait_for("KICK", seconds=3)))
outsider.close()

mark = second.mark()
second.send(f"INVITE nobody{RUN} {CHAN}")
second.read(1.5)
check(
    "INVITE from the second connection is allowed",
    not second.find(" 482 ", lines=second.since(mark)),
    second.since(mark)[-3:],
)

mark = second.mark()
second.send(f"METADATA {CHAN} SET display-name :from the second connection")
second.read(1.5)
check(
    "channel METADATA from the second connection is allowed",
    not second.find("FAIL METADATA KEY_NO_PERMISSION", lines=second.since(mark)),
    second.since(mark)[-3:],
)

section("delivery reaches every connection")
third = session()
third.send(f"JOIN {CHAN}")
third.read(1.0)

talker = Client(f"talk{RUN}")
talker.join(CHAN)
m1, m3 = first.mark(), third.mark()
talker.send(f"PRIVMSG {CHAN} :hello every connection")
first.read(1.5)
third.read(1.5)
check("the first connection received it", bool(first.find("hello every connection", lines=first.since(m1))))
check("the third connection received it too", bool(third.find("hello every connection", lines=third.since(m3))))

m1, m3 = first.mark(), third.mark()
talker.send(f"PRIVMSG {ACCOUNT} :a direct message to one nick")
first.read(1.5)
third.read(1.5)
check(
    "a direct message reaches every connection of the account",
    bool(first.find("a direct message to one nick", lines=first.since(m1)))
    and bool(third.find("a direct message to one nick", lines=third.since(m3))),
    (first.since(m1)[-2:], third.since(m3)[-2:]),
)

section("one connection leaving is not the user leaving")
m1 = first.mark()
third.close()
time.sleep(0.8)
check(
    "closing one connection does not part the user from the channel",
    not first.find("QUIT", ACCOUNT, lines=first.since(m1)),
    first.since(m1)[-3:],
)

mark = talker.mark()
talker.send(f"PRIVMSG {CHAN} :still there?")
first.read(1.5)
check("the remaining connections still receive channel traffic", bool(first.find("still there?")))

section("a capability belongs to a connection, not to the account")
# A user's capabilities are the union of its connections', which is right for
# deciding which tags a message may carry and wrong for deciding whether to
# send it at all: a client that never asked for `away-notify` must not be sent
# an AWAY because the phone in the same pocket did.
rich = session(caps="sasl message-tags server-time echo-message extended-join away-notify")
plain = session(caps="sasl")
rich.join(CHAN)
plain.read(0.5)
talker.join(CHAN)
rich.read(0.5)
plain.read(0.5)

m_rich, m_plain = rich.mark(), plain.mark()
talker.send("AWAY :stepping out")
rich.read(1.0)
plain.read(1.0)
check(
    "AWAY reaches the connection that asked for away-notify",
    bool([l for l in rich.since(m_rich) if " AWAY " in l or l.endswith(" AWAY")]),
    rich.since(m_rich)[-3:],
)
check(
    "and not the one on the same account that did not",
    not [l for l in plain.since(m_plain) if " AWAY " in l or l.endswith(" AWAY")],
    plain.since(m_plain)[-3:],
)
talker.send("AWAY")
talker.read(0.5)

# echo-message: the same, for a client's own message coming back.
m_plain = plain.mark()
plain.send(f"PRIVMSG {CHAN} :from the plain connection")
plain.read(1.0)
check(
    "no echo to a connection that did not ask for echo-message",
    not [l for l in plain.since(m_plain) if "from the plain connection" in l],
    plain.since(m_plain)[-3:],
)

# extended-join changes the shape of a reply, so it has to follow the
# connection that asked rather than the account.
m_plain = plain.mark()
plain.send(f"JOIN {CHAN}")
plain.read(1.0)
joins = [l for l in plain.since(m_plain) if " JOIN " in l]
check(
    "a JOIN reply is in the form this connection negotiated",
    bool(joins) and all(len(l.split()) == 3 for l in joins),
    joins,
)

# CAP LIST answers for the connection, not for everything the account holds.
m_plain = plain.mark()
plain.send("CAP LIST")
plain.wait_for(" CAP ", seconds=5)
listed = " ".join(l for l in plain.since(m_plain) if " CAP " in l)
check(
    "CAP LIST names only what this connection negotiated",
    "away-notify" not in listed and "extended-join" not in listed,
    listed,
)

rich.close()
plain.close()
talker.close()
second.close()
first.close()
summary("multiclient")
