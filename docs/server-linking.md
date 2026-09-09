# Server linking

Two or more rIRCd servers form one network. Users, channels and messages are
shared; nothing IRCv3 is lost on the way across.

This document is the protocol. It is written down because a link protocol is a
promise between two programs that were built at different times.

## What this is not

rIRCd links to rIRCd. It does not speak TS6, and it is not trying to: TS6
predates message tags, and everything rIRCd does well — msgid, server-time,
account, chathistory, metadata — would have to be flattened or dropped to fit
through it. A network that wants to mix ircds is better served by one of the
servers that was designed for that.

There is no services protocol either. Account registration, nick protection and
channel founders are part of rIRCd, so there is no Atheme or Anope to link.

## Identity

Every server has a **SID**: three characters, a digit followed by two
alphanumerics, unique on the network.

    [server]
    sid = "1AA"

Every user has a **UID**: its server's SID followed by six characters, so
`1AAAAAAAB`. A UID is assigned when the user registers and never changes, which
is what makes a nick change safe to relay — the message says who it is about by
UID, and a nick in flight cannot misdirect it.

Servers are named by SID and users by UID in every message between servers.
Names and nicks appear only where a human will read them.

## The link

Server traffic has its own listener. A client that reaches it is refused, and a
server that reaches a client port is treated as a client — the two never share
a port, so a mistake in one configuration cannot become an authentication
bypass in the other.

    [server]
    listen_links = ["0.0.0.0:7000"]

    [[links]]
    name = "irc2.example.org"
    sid = "2AA"
    host = "10.0.0.2"
    port = 7000
    send_password = "what we send"
    receive_password = "what we expect"
    tls = true
    autoconnect = true

`send_password` and `receive_password` are separate on purpose: each direction
has its own secret, so one leaked configuration does not let the holder link in
both directions.

### Handshake

The side that connects speaks first, and the side that accepts answers with the
same three lines:

    PASS <password> TS 1 <sid>
    CAPAB :<token> <token> ...
    SERVER <name> 1 :<description>

Both sides check the password, that the SID and name are the ones the
configuration expects, and that neither is already on the network. Anything
else on that connection before `SERVER` closes it.

### Burst

Each side then sends what it knows, in this order, and finishes with `EOB`:

1. `SERVER` for every other server it is carrying, prefixed by the SID that
   introduced it, so the peer learns the shape of the network.
2. `UID <nick> <hops> <nick_ts> <user> <host> <uid> <account> :<realname>` for
   every user, prefixed by the SID of the server it is on.
3. `SJOIN <channel_ts> <channel> <modes> :<@+uid> ...` for every channel, then
   its topic and its ban, exception and invite-exception lists.
4. `EOB`.

Until both sides have sent `EOB` the link is bursting, and conflicts are
resolved by timestamp rather than refused.

## Propagation

A message that changes shared state goes to every link except the one it came
from, with the originator's UID or SID as its prefix and its tags intact. That
is the whole rule: `PRIVMSG`, `NOTICE`, `TAGMSG`, `JOIN`, `PART`, `KICK`,
`MODE`, `TOPIC`, `NICK`, `QUIT`, `AWAY`, `ACCOUNT`, `CHGHOST`, `SETNAME`,
`INVITE`, `METADATA`.

`msgid` and `time` are carried, not regenerated, so a message has one identity
and one timestamp across the network — which is what lets chathistory on one
server answer for a conversation that happened on another.

## Conflicts

**Nicks.** The older registration keeps the nick. The newer one is renamed to
its own UID and told so. Nobody is disconnected for a collision.

**Channels.** The older channel timestamp wins. The younger side clears its
channel modes and its operators, which is the rule every TS network uses and
the only one that converges without a tie-break.

**Servers.** A SID or a name that is already on the network refuses the link,
loudly. Two servers with one identity is not a state to recover from.

## Splits

When a link drops, every user behind it quits with `*.net *.split` and every
server behind it is forgotten. Channels left empty are removed. A link with
`autoconnect` set is retried with a widening delay.

## Testing

    tests/smoke/run-link.sh

brings up two servers with their own databases, links them, and runs
`tests/smoke/test_link.py` against both ends.
