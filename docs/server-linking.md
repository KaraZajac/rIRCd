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

Every server on the network must also agree on `[server] casemapping`, which is
what decides that two names are the same name. Two servers that disagree would
each put the same channel in a different place, and there is no message that can
put it back.

## The link

Server traffic has its own listener. A client that reaches it is refused, and a
server that reaches a client port is treated as a client — the two never share
a port, so a mistake in one configuration cannot become an authentication
bypass in the other.

    [server]
    listen_links_tls = ["0.0.0.0:7000"]

    [tls]
    cert = "/etc/rIRCd/cert.pem"
    key  = "/etc/rIRCd/key.pem"

    [[links]]
    name = "irc2.example.org"
    sid = "2AA"
    host = "10.0.0.2"
    port = 7000
    send_password = "what we send"
    receive_password = "what we expect"
    tls = true
    fingerprint = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    autoconnect = true

`send_password` and `receive_password` are separate on purpose: each direction
has its own secret, so one leaked configuration does not let the holder link in
both directions.

### TLS

A link carries every private message that crosses it and the password that
opened it, so it should be encrypted between two machines. `listen_links_tls`
accepts links with the certificate in `[tls]`, and `tls = true` on a `[[links]]`
block dials one.

Which server is at the other end is decided by `fingerprint`: the SHA-256 of
the peer's certificate, in the form `openssl x509 -in cert.pem -noout -sha256
-fingerprint` prints (colons and case are ignored). There is no list of
certificate authorities here, and none is wanted — the two operators have
spoken to each other, so the certificate is known in advance, and pinning it
means a self-signed one is as good as any other.

A `[[links]]` block with `tls = true` and no fingerprint is refused at startup:
without one this server would be encrypting the link to whoever answered rather
than to that peer. A block *with* a fingerprint refuses a peer that presents no
certificate at all, which is what a connection to the plaintext listener would
be — otherwise the pin could be stepped around by dialling the other port.

Each side pins the other, so both directions are checked: the server that dials
presents its own certificate too, which is why `[tls]` must be configured even
on a server that only ever dials out.

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
   `CACCESS <channel_ts> <channel> <letter> :<account> ...` for who it belongs
   to, `TB <channel> <topic_ts> <setter> :<topic>` for its topic and
   `BMASK <channel_ts> <channel> <letter> :<mask> ...` for each of its ban,
   exception, invite-exception and quiet lists.

   A channel with nobody in it is bursted when somebody owns it, and then it
   has no `SJOIN` — there is no one to join — so `CACCESS` is what creates it
   on the other side and has to come before `TB` and `BMASK`.
4. `EOB`.

Until both sides have sent `EOB` the link is bursting, and conflicts are
resolved by timestamp rather than refused.

## Propagation

A message that changes shared state goes to every link except the one it came
from, with the originator's UID or SID as its prefix and its tags intact. That
is the whole rule: `PRIVMSG`, `NOTICE`, `TAGMSG`, `JOIN`, `PART`, `KICK`,
`MODE`, `TOPIC`, `NICK`, `QUIT`, `AWAY`, `ACCOUNT`, `CHGHOST`, `SETNAME`,
`INVITE`, `METADATA`, `CACCESS`.

### `CACCESS`

`CACCESS <channel_ts> <channel> <letter> :<account> ...` says who a channel
belongs to: `f` for its founder, `o` for the operators whose status was granted
to last, `v` for the voices. The names are accounts rather than nicks, because
a nick is only what somebody is called at the moment and this has to mean the
same person at both ends. A name prefixed with `-` says the status was taken
away; without it, given.

It merges rather than replaces, so two servers that each learned part of a
channel's access list end up holding all of it. The founder is the exception,
because a channel has exactly one: the older channel keeps the founder it has,
and when both were made in the same second the account that sorts first wins —
arbitrary, but the same answer on both sides, and converging on an arbitrary
answer beats disagreeing about a considered one.

Each server writes down what it learns, so it does not forget at the next
restart and start disagreeing with the network all over again.

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

## What is carried today

The protocol above is what a link is for. This is how far the implementation has
got, so that nobody has to read the source to find out:

| | |
|---|---|
| The link, its handshake and its keepalive | yes |
| `SERVER`, so the network's shape is known past the peer | yes |
| The user burst, and users announced as they register | yes |
| `NICK`, `QUIT`, `AWAY`, `KILL` | yes |
| Nick collisions, settled by timestamp | yes |
| `PRIVMSG`, `NOTICE`, `TAGMSG` between users on different servers | yes |
| The channel burst — `SJOIN`, `CACCESS`, `TB`, `BMASK` — and channel collisions | yes |
| Channel ownership: founder, operator and voice lists, by account | yes |
| `JOIN`, `PART`, `KICK`, `MODE`, `TOPIC`, and messages to a channel | yes |
| `ACCOUNT`, `CHGHOST`, `SETNAME`, `INVITE`, `METADATA` | yes |
| Chathistory: both ends of a conversation keep it | yes |
| TLS, with each side pinned to the other's certificate | yes |
| `WHOIS` forwarded, for the idle time only that server knows | yes |
| `GHOST`, for a session held on another server | yes |

`SANICK` is not here and never was: it is an operator forcibly renaming
somebody, which no part of this server does, so there is nothing to carry
across a link. It is a feature to decide on rather than a gap to close.

A `WHOIS` for somebody on another server is answered from what this one was

### What a link is allowed to say

A link is the most trusted connection a server has: whatever a peer says about
its users is believed, because there is nothing to check it against. The
boundary of that trust is that **a link speaks for the servers it carries and
for nothing else**. Every message that arrives with a prefix — a user id or a
server id — is checked against what that link is known to carry before anything
is done with it.

Without that, one compromised server on a network is every server on it. Local
users are keyed by this server's own ids, so a peer allowed to name any id could
send `:1AAAAAAAB QUIT` and disconnect somebody on the server it had just linked
to. `tests/smoke/test_link_hostile.py` does exactly that, three hundred ids at a
time, and checks that everybody is still there afterwards.

### Asking somebody else to act

`GHOST` closes the session using a nick so the account that owns it can take it
back, and the connections are on the server that session is on. So the request
goes there:

    :<asker> GHOST <target>

It is addressed to one server, passed along by any in between, and there is
nothing to wait for — the session closing is announced as an ordinary `QUIT`,
which is how everybody including the asker finds out.

Everything the asking server checked is checked again on arrival, from what the
receiving server knows rather than from what it was told: that the asker has an
account, that the account owns the nick being reclaimed, and that they are not
asking to close themselves. A link is trusted to speak for its own users, not to
have got the rules right — and accounts cross a link, so the far side can check
this for itself.

### Asking, rather than announcing

Everything above is an announcement: something happened here and the network is
told. A `WHOIS` is the first thing that is a question. Almost all of the answer
comes from what this server was already told — nick, name, account, server —
but how long somebody has been quiet is known only to the server they are
typing at, changes every time they say anything, and is not worth telling
anybody about until asked.

    :<asker> WHOISREQ <target> <token>
    :<target> WHOISREP <asker> <token> <idle seconds> <signon>

The asking server issues the token, so a peer cannot name one that was never
given out, and the answer is only accepted for the user who asked. The question
goes to the one server that can answer it rather than to the whole network, and
is passed along by any server in between.

Nothing waits for the answer: the rest of the reply is sent when it arrives, or
after three seconds, whichever happens first — and whichever of the two gets
there first is the one that finishes the reply, so a client sees the line that
ends the list exactly once. The questions outstanding are bounded, because a
peer that never answers must not be able to leave anything behind; past the
ceiling a `WHOIS` is answered the way it was before there was anywhere to ask,
without an idle line.

That shape — a token the asker chose, one addressed recipient, a bounded wait
that gives up on its own — is the one anything else that needs an answer from
another server should follow.

## Testing

    tests/smoke/run-link.sh

brings up two servers with their own databases, links them, and runs
`tests/smoke/test_link.py` against both ends. Add `--tls` and it makes a
certificate for each side, pins them to one another, and runs the same tests
over an encrypted link — a link is a link once it is up, so the checks do not
change.
