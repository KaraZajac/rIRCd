# rIRCd

A bleeding-edge IRC server in Rust, following [IRCv3 specifications](https://ircv3.net/irc/).

## Requirements

- Rust (stable, 2021 edition or later)
- MariaDB or MySQL server

## Initial Setup

### 1. Set up the database

Create a database and user in MariaDB:

```sql
CREATE DATABASE rircdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'rirc'@'localhost' IDENTIFIED BY 'your-password';
GRANT ALL PRIVILEGES ON rircdb.* TO 'rirc'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

The database schema (tables for users, channels, channel history, etc.) is created automatically on first startup — no SQL migration files to run.

### 2. Install rIRCd

```bash
cargo build --release
sudo cp target/release/rircd /usr/local/bin/
```

### 3. Run the interactive setup

```bash
sudo rircd init
```

This starts an interactive prompt that asks for:

- **Server hostname** and **network name**
- **Plain-text port** (default: 6667) and optionally a **TLS port** with cert/key paths
- **Database credentials** (host, port, name, user, password)
- **Message of the day**
- Optionally, **email verification** for account registration (SMTP host, port, from address)
- Optionally, an **IRC operator** account (password is bcrypt-hashed automatically)

A `config.toml` is written to `/etc/rIRCd/` with all your answers filled in. If the file already exists you are asked before overwriting.

Example session:

```
rIRCd interactive setup
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Press Enter to accept the [default] value.

[Server]
  Server hostname [irc.example.com]: irc.mynetwork.org
  Network name [rIRCd]: MyNet
  Plain-text IRC port [6667]:
  Message of the day [Welcome to rIRCd!]: Welcome to MyNet!

[TLS]
  Enable TLS listener? [y/N]: y
  TLS port [6697]:
  Path to certificate (PEM) [/etc/rIRCd/cert.pem]:
  Path to private key (PEM) [/etc/rIRCd/key.pem]:

[Database]
  (rIRCd requires MariaDB/MySQL for user accounts and channel history.)
  Database host [localhost]:
  Database port [3306]:
  Database name [rircdb]:
  Database user [rirc]:
  Database password:

[Email verification]
  (Requires accounts registered with REGISTER to confirm an address with VERIFY.)
  Enable email verification? [y/N]:

[IRC Operator]
  Create an IRC operator account? [Y/n]:
  Operator name [admin]:
  Operator password:
  Operator password (confirm):

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Config written to /etc/rIRCd/config.toml
The database schema is created automatically on first startup.

Start the server with:  rircd run
```

You can always hand-edit `/etc/rIRCd/config.toml` afterwards — see [Configuration Reference](#configuration-reference) below.

### 4. Start the server

```bash
sudo rircd run
```

Connect with any IRC client to `localhost:6667` (or whatever port you configured).

---

## Configuration Reference

The only file rIRCd needs is `/etc/rIRCd/config.toml`. All user accounts, channels, and message history are stored in MariaDB.

### `[server]`

| Key | Default | Description |
|-----|---------|-------------|
| `name` | `rIRCd.local` | Server hostname shown to clients |
| `casemapping` | `ascii` | Which names count as the same name. `ascii` folds A–Z and nothing else, and is what a network started today should use. `rfc1459` also folds `[]\~` onto `{}|^`, which a network that has been running since the nineties cannot stop doing without renaming its channels. Advertised as `CASEMAPPING`; every server on one network must agree |
| `listen` | `[":6667"]` | Plain-text listener addresses |
| `listen_tls` | `[]` | TLS listener addresses (requires `[tls]`) |
| `listen_ws` | `[]` | WebSocket listener addresses (e.g. `[":7667"]`) |
| `listen_wss` | `[]` | WebSocket-over-TLS listener addresses (requires `[tls]`) |
| `motd` | `"Welcome to rIRCd!"` | Message of the day (inline text, multiline OK) |
| `registration_timeout_secs` | `60` | Time allowed to complete NICK/USER before disconnect |
| `ping_timeout_secs` | `90` | How long to wait for PONG before sending next PING |
| `disconnect_timeout_secs` | `150` | Time after missed PONG before disconnecting client |
| `nick_protection` | `true` | Reserve a registered nick for its account; others get 433 |
| `trusted_proxies` | `[]` | Addresses whose `X-Forwarded-For` is believed. A plaintext WebSocket listener usually sits behind a reverse proxy, and the header is how the proxy says who the client is — but it is only a header, and anybody can send one. Believed from nobody by default, so the connecting address is used. **If you serve WebSockets behind nginx or similar, add the proxy's address here or every client will look like the proxy** |
| `channel_creation` | `anyone` | Who may bring a new channel into being: `anyone`, `accounts` or `opers`. Only creating is gated, never joining one that already exists. `accounts` is the useful one — a channel made by somebody not logged in has no founder and never gets one, so requiring an account makes every channel owned from its first moment |
| `admin_name` / `admin_location` / `admin_email` | _(unset)_ | Shown by `ADMIN` (256–259) |
| `client_tag_deny` | _(unset)_ | List of client-only tags to drop (e.g. `["+typing"]` or `["*"]` to drop all) |
| `cloak_key` | _(unset)_ | If set, connecting clients receive an HMAC-SHA256-based virtual host cloak (e.g. `"mysecret"`) |
| `description` | `rIRCd v<version>` | One-line description of this server, shown by `LINKS` |
| `register_before_connect` | `true` | Allow `REGISTER` before the handshake finishes; advertised as `before-connect` |
| `multiclient` | `false` | Let one account hold several connections at once — a desktop and a phone, say. They share a nick and a single place in every channel; anything addressed to the user reaches all of them, while the answer to a command goes back to the connection that sent it, and each connection sees only the message tags it negotiated. Needs SASL: a connection joins an account it has proved it belongs to, and no other |
| `persistent_sessions` | `false` | Treat an account as one continuing session: logging in takes its nick back from an earlier session and rejoins that session's channels. Off by default — it disconnects the earlier session, which is what someone reconnecting after a dropped link wants and what someone with two clients open does not |
| `password` | _(unset)_ | A password every connection must send with `PASS` before registering. Stored in the clear on purpose: it is shared with everyone allowed on the server, so it is a door key rather than a secret about any one person. A wrong or missing one gets 464 and the link is closed |

### `[[links]]` and server linking

Two or more rIRCd servers form one network. The protocol, and why it is not
TS6, is in [docs/server-linking.md](docs/server-linking.md).

```toml
[server]
sid = "1AA"                      # this server's identity on the network
listen_links_tls = ["0.0.0.0:7000"]  # server traffic never shares a client port

[[links]]
name = "irc2.example.org"
sid = "2BB"
host = "10.0.0.2"
port = 7000
send_password = "what we send"
receive_password = "what we expect"
tls = true
fingerprint = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
autoconnect = true
```

| Key | Default | Description |
|-----|---------|-------------|
| `sid` | _(derived from the name)_ | Three characters, a digit then two alphanumerics, unique on the network. Derived from the server name when unset, which is a coin toss for a network — set it before linking |
| `listen_links` | `[]` | Addresses to accept links on. A client that reaches one gets nothing, and a server that reaches a client port is treated as a client |
| `listen_links_tls` | `[]` | The same, encrypted with the certificate in `[tls]`. A link carries every private message that crosses it, so this is what a link between two machines should be |
| `tls` | `false` | Dial this peer over TLS. Needs a `fingerprint`, and needs `[tls]` set on this server too, because the peer pins this one in the same way |
| `fingerprint` | _(unset)_ | SHA-256 of the peer's certificate, as `openssl x509 -in cert.pem -noout -sha256 -fingerprint` prints it. This is what says the far end is the server meant rather than whoever answered; there is no list of certificate authorities here, which is also why a self-signed certificate is as good as any other. A link told which certificate to expect refuses a peer that presents none, so the plaintext port is not a way around it |
| `send_password` / `receive_password` | — | Separate on purpose: each direction has its own secret, so one leaked configuration does not let the holder link both ways |
| `autoconnect` | `false` | Keep the link up, retrying with a widening delay |

An operator with the `links` privilege can also shape the network by hand:
`CONNECT <server>` dials a `[[links]]` block now rather than waiting for its
next retry, and `SQUIT <server> [:<reason>]` drops the link to a directly
attached server, telling it why first so the far end logs a decision rather
than a failure. A server behind a peer is that peer's to drop. Both are
announced to every operator, and a link that `autoconnect` keeps up comes back
on its own after a `SQUIT` — set `autoconnect = false` and `REHASH` first if
it is meant to stay down.

A link carries everything two servers need to agree on: who is connected, what
they are called, which channels they are in and what is said in them — and who
those channels belong to. Ownership is carried as accounts rather than nicks,
because it has to mean the same person at both ends, and it is merged rather
than replaced: two servers that each learned part of the truth end up holding
all of it, and where they disagree about a founder the older channel keeps its
own. A channel nobody is standing in is bursted too when somebody owns it, so a
server joining the network learns whose it is rather than finding out from
whoever walks in next.

A link also carries the two things that need an answer rather than an
announcement — a `WHOIS` asks the server somebody is on how long they have been
quiet, and a `GHOST` asks the server a stale session is on to close it. What a
link is allowed to say, and what it is not, is in
[docs/server-linking.md](docs/server-linking.md).

`tests/smoke/run-link.sh` brings up two servers with their own databases on
their own ports, links them, and checks what each one knows about the other.
`--tls` runs the same checks over an encrypted link, with a throwaway
certificate for each side.

### Serving a hidden service

Behind a Tor onion service every client reaches the server from `127.0.0.1`.
`max_connections_per_ip` then reads as "this many people may use the server
through Tor at once", which is not a rule anybody meant to write — and it
cannot be fixed by counting more carefully, because the addresses genuinely are
all the same. There is nothing to tell apart.

Give the hidden service a listener of its own and name it:

```toml
[server]
listen = ["0.0.0.0:6667", "127.0.0.1:6668"]   # 6668 is the one Tor forwards to

[limits]
max_connections_per_ip = 16                   # still true of the public port
shared_address_listeners = ["127.0.0.1:6668"]
max_clients_behind_one_address = 256
```

The public port keeps the per-address limit, which is the stronger rule. The
onion's port is capped as a whole: a weaker promise, and the strongest one
available, because it bounds what the door can let through without pretending
to know who is coming through it.

Worth knowing: a host ban lands on every onion client at once, since they are
one address, and the cost of a failed login is counted per address too, so one
person guessing passwords makes the others wait. `WEBIRC` does not help here —
the connection's slot is claimed before the first line is read, so a gateway
that could say who the client really is says it too late to matter.

### `[network]`

| Key | Default | Description |
|-----|---------|-------------|
| `name` | `rIRCd` | Network name (shown in 005 NETWORK) |
| `icon` | _(unset)_ | URL to a network icon image (advertised as `ICON=` in ISUPPORT; draft/network-icon) |

### `[database]`

| Key | Default | Description |
|-----|---------|-------------|
| `host` | `localhost` | MariaDB/MySQL host |
| `port` | `3306` | MariaDB/MySQL port |
| `user` | _(empty)_ | Database username |
| `password` | _(empty)_ | Database password |
| `database` | `rircdb` | Database name |

### `[tls]`

Optional. Both fields must be set to enable TLS listeners. `REHASH` reloads the
certificate in place, so a renewal does not need a restart.

| Key | Description |
|-----|-------------|
| `cert` | Path to PEM certificate file |
| `key` | Path to PEM private key file |
| `client_certs` | If `true`, request TLS client certificates for SASL EXTERNAL (default `false`) |

Example:

```toml
[server]
listen_tls = [":6697"]

[tls]
cert = "/etc/rIRCd/cert.pem"
key  = "/etc/rIRCd/key.pem"
```

### `[limits]`

| Key | Default | Description |
|-----|---------|-------------|
| `max_channels_per_client` | `50` | Max channels a single client may join |
| `max_connections_per_ip` | `16` | Connections allowed from one address at a time; 0 for no limit. An IPv6 address counts by its /64 — the smallest allocation anybody is given — so a client that picks a fresh address per connection is still one client. Read at startup, not on rehash |
| `max_connections_per_ip_per_minute` | `30` | New connections one address may make in a minute; 0 for no limit. The concurrent limit never sees a client that connects and hangs up in a loop, and each of those costs a handshake. Read at startup |
| `max_registrations_per_ip` | `30` | Registrations one address may make in ten minutes; 0 for no limit. Each is a hash, a row, and with `[email]` a message to an address the client chose. Thirty in ten minutes is an office behind one NAT on its first day; a hundred is a script. Read at each attempt, so a rehash changes it |
| `shared_address_listeners` | `[]` | Listeners where every client arrives from the same address — a Tor hidden service, or anything behind a local proxy. The per-address limit cannot mean anything there, so connections on these are counted against the listener instead. Must name a `listen`, `listen_tls`, `listen_ws` or `listen_wss` address exactly; the server refuses to start if it does not, because a typo would silently leave the listener capped at `max_connections_per_ip`. Read at startup, not on rehash |
| `max_clients_behind_one_address` | `256` | The cap that stands in for the per-address one on those listeners; 0 leaves only `max_clients` |
| `max_remote_users` | `250000` | Users this server will hold on behalf of other servers; 0 for no limit. A link is trusted with what it says about its users, not with how many of them there is room for: past this, further introductions are refused and logged, and the link stays up |
| `max_servers` | `512` | Servers this one will know about, direct peers included; 0 for no limit. No network has more than a few hundred |
| `max_clients` | `10000` | Connections allowed in total; 0 for no limit. Every other limit is per address, and anybody with IPv6 has a great many /64s to rent, so this is the one they meet |
| `max_line_length` | `512` | Longest message body accepted, before tags; advertised as `LINELEN` |
| `flood_burst` | `10` | Commands a client may send back to back before being throttled |
| `flood_rate` | `1` | Commands per second the flood allowance refills at |
| `min_password_length` | `6` | Shortest password `REGISTER` accepts; advertised in `draft/account-registration` |
| `max_targets` | `4` | Recipients one `PRIVMSG`, `NOTICE`, `TAGMSG` or `KICK` may name at once; advertised as `TARGMAX` |

### `[[opers]]`

Define IRC operators. Multiple `[[opers]]` blocks are allowed.

```toml
[[opers]]
name = "admin"
hostmask = "*"            # optional; restrict by host
password_hash = "$2a$..." # generate with: rircd genpasswd

[[opers]]
name = "helper"
password_hash = "$2a$..."
privileges = ["kill", "ban"]   # omit for all privileges
```

`privileges` limits what an operator may do: `kill`, `ban` (KLINE/UNKLINE, DLINE/UNDLINE),
`rehash`, `die`, `sethost`, `wallops`, `channels` (`CHANOWN` on a channel that
is not theirs), `links` (`CONNECT` and `SQUIT`). Omitting the key keeps the previous behaviour, where every

An operator block's `hostmask` (`user@host` or `nick!user@host`, judged on the
real address, not the cloak) is where that operator is allowed to be; `OPER`
from anywhere else is refused with 491. An operator block may ask for more than a password. `require_tls = true`
refuses `OPER` over a connection that is not TLS, so the password never crosses
a wire in the clear. `certfp = "SHA256:…"` (the fingerprint as `openssl x509
-noout -sha256 -fingerprint` prints it, colons optional) refuses `OPER` unless
that client certificate was presented — as a second factor when
`password_hash` is set too, and on its own when it is left empty, in which
case `OPER <name>` with no password is the whole ceremony.

```toml
[[opers]]
name = "kara"
certfp = "3B:8F:…:A1"
require_tls = true
privileges = ["kill", "ban", "channels"]
```
`kill` also covers `SANICK <nick> <newnick>`, the milder cousin of `KILL`: somebody
sitting on a name they should not have is moved off it rather than off the
network, told who did it, and the network sees an ordinary nick change — a user
on another server is renamed by that server at this one's request.
operator may do everything — so this only narrows operators who were already
narrowed, and `channels` has to be listed for them to move a channel.

### `[filehost]`

Optional, and how somebody shares a picture here. There is no upload bot and
no third-party host: the server keeps the file itself. A client reads the
`FILEHOST` token out of ISUPPORT, `POST`s the file there over HTTPS with the
same account credentials it uses for SASL — HTTP Basic, because that is what
the extension says — and is handed back a URL in the `Location` header to
paste into the channel. Anybody with the link can fetch it; only somebody with
an account can put one there.

| Key | Default | Description |
|-----|---------|-------------|
| `listen` | `0.0.0.0:8080` | Where the file host listens |
| `public_url` | _(required)_ | The base URL people will actually reach it on (e.g. `https://irc.example.com/uploads`). Its path is where the routes are mounted, so a reverse proxy in front needs no special case, and an `https://` one makes the server serve it with the certificate from `[tls]` |
| `upload_dir` | `/var/lib/rircd/uploads` | Where the files go |
| `max_size` | `52428800` (50 MiB) | The largest file it will take; anything over gets 413 |
| `max_uploads_per_hour` | `60` | How many files one account may put there in an hour; `0` for as many as it likes, which on a server anybody can register on means as much disk as it likes. Over it is 429 with a `Retry-After` |

The credentials are the account's, so guessing at them here costs what guessing
at them over IRC costs: the same allowance is spent per address, and an address
that keeps getting it wrong is answered `429` with a `Retry-After` **without a
password being checked at all**. Otherwise every bit of the care the IRC side
takes over passwords would be one HTTP request away from being beside the
point.

A file is stored under a name of the server's choosing — a UUID, keeping only
a sanitised extension — so nothing an uploader writes becomes a path, and
nothing they upload can overwrite anything. `tests/smoke/test_filehost.py`
covers the lot, including the links that try to leave the directory.

Nothing reclaims that disk on its own. `[expiry] uploads_days` is how you say
how long a file is kept; without it the server says so at startup, because a
directory that only ever grows is worth knowing about before it matters. The
sweep touches regular files in the upload directory and nothing else — not a
symbolic link, not a subdirectory, not a dotfile.

Example:

```toml
[filehost]
listen = "0.0.0.0:8080"
public_url = "https://irc.example.com/uploads"
upload_dir = "/var/lib/rircd/uploads"
max_size = 52428800
```

### `[email]`

Optional. Turns on email verification for account registration (draft/account-registration `VERIFY`). With this section present, `REGISTER` requires a real address, the account is stored unusable, and a code is mailed to the address; the account only becomes usable once `VERIFY` confirms the code. The `email-required` token is added to the advertised `draft/account-registration` capability so clients know to ask for an address.

Mail is sent over SMTP with rustls — no system TLS libraries needed.

| Key | Default | Description |
|-----|---------|-------------|
| `smtp_host` | _(required)_ | SMTP server hostname |
| `smtp_port` | `587` | SMTP port (587 STARTTLS, 465 implicit TLS, 25 plain) |
| `smtp_user` | _(unset)_ | SMTP username; omit for an unauthenticated relay |
| `smtp_password` | _(unset)_ | SMTP password |
| `encryption` | `starttls` | `starttls`, `tls` (implicit) or `none` |
| `from` | _(required)_ | From address, e.g. `ExampleNet <noreply@example.com>` |
| `subject` | `Your IRC account verification code` | Subject line |
| `code_expiry_secs` | `86400` | How long a code stays valid |
| `reset_subject` | `Your IRC password reset code` | Subject line of a `RESETPASS` mail. Reset codes are good for fifteen minutes regardless of `code_expiry_secs`: they arrive by mail that anybody holding the inbox can use |
| `mail_gap_secs` | `900` | The least time between two messages to one address, whoever asks and by whichever of `REGISTER` or `RESETPASS`. Asking for a message is free and the address is the client's to choose, so the address itself gets a say. The gap starts only when a message actually goes out, so a registration refused for its password does not cost the person their real attempt |

```toml
[email]
smtp_host = "smtp.example.com"
smtp_port = 587
encryption = "starttls"
from = "ExampleNet <noreply@example.com>"
smtp_user = "noreply@example.com"
smtp_password = "s3cr3t"
code_expiry_secs = 86400
```

### `[webpush]`

Optional. Enables Web Push notifications (draft/webpush, [RFC 8030](https://www.rfc-editor.org/rfc/rfc8030)/[8291](https://www.rfc-editor.org/rfc/rfc8291)/[8292](https://www.rfc-editor.org/rfc/rfc8292)) so mobile and web clients can be woken for messages while their app is asleep. When configured, the `draft/webpush` capability is advertised and clients register endpoints with `WEBPUSH REGISTER`.

A VAPID key pair is generated on first start and stored in `key_file` (mode 0600). Its public key is advertised to capable clients in the `VAPID=` ISUPPORT token and used to sign every push request — **back this file up**: replacing it invalidates every existing subscription.

| Key | Default | Description |
|-----|---------|-------------|
| `contact` | _(required)_ | VAPID `sub` claim — a `mailto:` or `https:` URL identifying the operator |
| `key_file` | `/etc/rIRCd/vapid.key` | Where the VAPID private key is stored (created if missing) |
| `max_subscriptions_per_account` | `5` | Endpoints one account may have registered at once |
| `ttl_secs` | `3600` | TTL requested of the push service per notification |
| `max_failures` | `5` | Consecutive delivery failures before a subscription is dropped |
| `allow_private_endpoints` | `false` | Permit endpoints resolving to loopback/private addresses (testing only) |

```toml
[webpush]
contact = "mailto:admin@example.com"
key_file = "/etc/rIRCd/vapid.key"
max_subscriptions_per_account = 5
ttl_secs = 3600
```

Subscriptions belong to an **account**, so a client must be logged in (SASL or `REGISTER`) before `WEBPUSH REGISTER`; they are stored in MariaDB and survive restarts.

```
WEBPUSH REGISTER <endpoint> p256dh=<key>;auth=<secret>
WEBPUSH UNREGISTER <endpoint>
```

Endpoints must use `https` and must not resolve to loopback, private, link-local or carrier-grade-NAT addresses. A notification carries exactly one IRC message (with `msgid`, `time` and `account` tags), encrypted with `aes128gcm` per RFC 8291, and is sent for:

- direct `PRIVMSG`/`NOTICE` to the user, and
- channel `PRIVMSG`/`NOTICE` that mention their nick.

Notifications also reach users who are **not connected**: when a registered user
joins a channel, that membership is remembered, so a mention still pushes to them
while they are away — and the message itself is waiting in channel history when
they return. Leaving the channel, or being kicked from it, ends that.

Endpoints the push service reports as gone (404/410), or that fail `max_failures` times in a row, are removed automatically. Clients should re-send an identical `WEBPUSH REGISTER` periodically (daily is typical) to keep a subscription fresh.

### `[dnsbl]`

Ask a DNS blocklist about every public address that connects. The addresses
that open connections to IRC servers by the thousand are the same ones that do
it to everybody else, and somebody has already written them down.

```toml
[dnsbl]
zones = ["dnsbl.dronebl.org"]   # the first that answers decides
action = "reject"               # or "warn": let them in, and log
timeout_secs = 2
cache_secs = 600
```

Each address is asked about once and the answer remembered. A lookup that
times out counts as not listed — a resolver outage must never lock everybody
out — and addresses that are not public are never asked about, nor is anything
arriving on a `shared_address_listeners` port, since the address there is
everybody's. A listed address is turned away before its first line with
`ERROR :Closing link: Your address is listed in <zone>`.

### `[webirc]`

Optional. Enables WEBIRC gateway support so reverse proxies can pass the real client IP.

```toml
[webirc]
password = "gateway-secret"
```

### Full example config

```toml
[server]
name = "irc.example.com"
listen = [":6667"]
listen_tls = [":6697"]
motd = """
Welcome to Example IRC!
Have fun and be nice.
"""
registration_timeout_secs = 60
ping_timeout_secs = 90
disconnect_timeout_secs = 150

[network]
name = "ExampleNet"

[database]
host = "localhost"
port = 3306
user = "rirc"
password = "s3cr3t"
database = "rircdb"

[tls]
cert = "/etc/rIRCd/cert.pem"
key  = "/etc/rIRCd/key.pem"

[limits]
max_channels_per_client = 50

[[opers]]
name = "admin"
hostmask = "*"
password_hash = "$2a$12$..."

[filehost]
listen = "0.0.0.0:8080"
public_url = "https://irc.example.com/uploads"
upload_dir = "/var/lib/rircd/uploads"
max_size = 52428800

[email]
smtp_host = "smtp.example.com"
smtp_port = 587
encryption = "starttls"
from = "ExampleNet <noreply@example.com>"
smtp_user = "noreply@example.com"
smtp_password = "s3cr3t"

[webpush]
contact = "mailto:admin@example.com"
key_file = "/etc/rIRCd/vapid.key"
```

---

### Reloading

`REHASH` from an operator and `SIGHUP` from outside do the same thing: read the
configuration again and put it in place without dropping anybody. The
certificate is re-read too, which is the point of it — renewals happen on
somebody else's schedule, and restarting to pick one up would disconnect
everyone.

```bash
systemctl reload rircd        # the unit file sends SIGHUP
kill -HUP "$(cat /etc/rIRCd/rircd.pid)"
```

For Let's Encrypt, that is the deploy hook:

```bash
certbot renew --deploy-hook 'systemctl reload rircd'
```

What survives the reload is everything a connection is holding: the database
pool, the history writer, the servers already linked, and the Web Push key —
rotating that last one would invalidate every push subscription registered
under it. A configuration that will not load leaves the running one alone and
says why in the log.

### `[[classes]]`

`[limits]` says what *a* client may do, which is the right answer only when
every client is the same one. A gateway carrying two hundred people from one
address, a bot that must not be pinged out while it thinks, and somebody on a
phone are not the same thing, and a server with one set of numbers is a server
tuned for whichever of them it would rather lose.

```toml
[[classes]]
name = "gateway"
hosts = ["10.0.0.5", "192.168.0.0/16"]
max_per_ip = 0          # this address may bring as many as it likes
max_clients = 500       # but no more than this many at once, all told
ping_secs = 300
sendq = 8192

[[classes]]
name = "everybody"      # no hosts: the one everybody else falls into
max_per_ip = 5
```

| Key | Meaning |
|---|---|
| `hosts` | Addresses in this class: globs (`10.0.0.*`, `*.example.org`) or networks in CIDR form. **Empty matches everybody**, so that class goes last |
| `max_clients` | How many connections this class may hold at once. The one over it is turned away with `This class of connection is full` |
| `max_per_ip` | How many one address may hold within this class; `0` for as many as it likes |
| `ping_secs` | How long a connection here may be quiet before it is pinged |
| `flood_burst`, `flood_rate` | Commands it may send back to back, and how fast the allowance refills |
| `sendq` | Messages that may be queued for it before it is dropped for not reading. A gateway needs a deeper queue than a phone |

A connection lands in the first class whose `hosts` it matches. Anything a class
leaves unset falls through to `[limits]` and `[server]`, so adding a class
changes nothing except what it says. `STATS y` lists the classes with how many
connections are in each, and `TRACE` calls each connection by its class —
falling back to how it arrived (`plain`, `tls`, `websocket`) when no class
named it.

Classes are read when the server starts, not on `REHASH`: the part of the
server that accepts connections took its copy at startup. `STATS y` reports
that copy rather than the file, so it never claims a class that is not in
force.

### `[expiry]`

What a services package would call nick and channel expiry. Off unless set:
this is a policy about other people's names and rooms, and a server with real
people on it should choose it rather than be handed one.

```toml
[expiry]
accounts_days = 365   # erase an account nobody has logged in to for a year
channels_days = 90    # give up a registration nobody holding it has visited for 90 days
uploads_days = 30     # let go of a shared file after a month
```

| Key | Default | Meaning |
|---|---|---|
| `accounts_days` | `0` (never) | An account nobody has logged in to for this long is erased: its nick is free again, its grouped nicks with it, its profile and read markers go with it, and the channels it founded are left without a founder — the people in them are told, as with `DROPACCOUNT` |
| `channels_days` | `0` (never) | A registration nobody who holds the channel — founder or standing operator — has been in for this long is given up. The channel keeps its topic and its modes; it is simply nobody's, and the next person in gets `@` the way they would in any fresh channel |
| `uploads_days` | `0` (never) | A file shared through `[filehost]` is let go of this long after it was uploaded, and its link becomes a 404. Kept by age rather than by whether anybody still wants it, because nothing here knows who has a link — so this is really a statement of how long a link is good for, which is a thing people can be told in advance. Unlike "until the disk fills", which is what leaving it unset means |

An operator can keep a name or a room out of expiry's reach with
`NOEXPIRE <account|#channel> ON` (`OFF` puts it back; without either it says
which it is). What a services package calls the same thing.

"Unseen" is measured the way a person would measure it. A login is use, and so
is a holder standing in the room — including one who connected months ago and
never left: the sweep looks at who is connected before it looks at the clock,
and refreshes the clock for them rather than expiring them. It runs a couple of
minutes after startup, once an hour after that, and on every `REHASH`, so a
changed policy can be seen to work. The clock starts the first time this
version runs, so nobody expires on the day of an upgrade. Operators are told
what each sweep let go of, and what it let go of is announced across links the
way `DROPACCOUNT` and `CHANACCESS` withdrawals are.

## CLI Commands

| Command | Description |
|---------|-------------|
| `rircd init [--dir /etc/rIRCd]` | Create config directory with a default `config.toml` |
| `rircd [--config /etc/rIRCd/config.toml] run` | Start the server; connects to DB, inits schema, writes PID file |
| `rircd [--config /etc/rIRCd/config.toml] stop` | Send SIGTERM to the running server (Unix only) |
| `rircd [--config /etc/rIRCd/config.toml] status` | Check if the server is running via PID file |
| `rircd genpasswd` | Interactively hash a password for use in `[[opers]]` |
| `rircd adduser <nick> [password]` | Create an account without connecting as a client; reads the password from stdin when omitted |

`--config` is a global flag, so it goes **before** the subcommand.

The PID file is written to the same directory as `config.toml` (e.g. `/etc/rIRCd/rircd.pid`) and is removed on clean shutdown. `rircd stop` and `rircd status` use it to find the process.

---

## User Accounts

User registration is handled via the IRC `REGISTER` command (draft/account-registration):

```
REGISTER * [email|*] <password>
```

The account name must be `*` or your current nick — the server advertises `before-connect` (so registering during connection negotiation, before `CAP END`, works) but not `custom-account-name`.

This stores a bcrypt hash of the password (for SASL PLAIN) and full SCRAM credentials (for SASL SCRAM-SHA-256) in MariaDB. Passwords must be at least 6 characters. On success the client is logged in immediately, exactly as if it had authenticated with SASL.

### Email verification

If an [`[email]`](#email) section is configured, registration takes a second step. `REGISTER` then requires a real address, and replies:

```
REGISTER VERIFICATION_REQUIRED <account> :A verification code has been sent to <email>
```

The account exists but cannot authenticate — SASL PLAIN, SCRAM-SHA-256 and EXTERNAL all refuse it — until the mailed code is confirmed:

```
VERIFY <account|*> <code>
```

On success the server replies `VERIFY SUCCESS <account>` and logs the client in. Codes are compared in constant time, are case-insensitive, and expire after `code_expiry_secs` (24h by default); an unverified account whose code has expired is deleted, freeing the name for registration again. Expired rows are also swept at startup.

If the mail cannot be sent, the registration is rolled back and the client receives `FAIL REGISTER TEMPORARILY_UNAVAILABLE`.

Authentication is supported via two SASL mechanisms:

**SASL PLAIN:**
```
CAP REQ :sasl
AUTHENTICATE PLAIN
AUTHENTICATE <base64-encoded NUL-separated authzid NUL authcid NUL password>
```

**SASL SCRAM-SHA-256** (recommended):
```
CAP REQ :sasl
AUTHENTICATE SCRAM-SHA-256
AUTHENTICATE <base64-encoded client-first-message>
AUTHENTICATE <base64-encoded client-final-message>
```

SCRAM-SHA-256 uses PBKDF2 key derivation (4096 iterations) and provides mutual authentication — the server proves it knows your credentials without ever seeing your password in clear text over the protocol exchange.

Accounts are keyed by nick (lowercase). There is no separate admin interface for user management — use direct SQL queries on the `users` table if needed.

---

### Reserved names

`RESV [<seconds>] <pattern> :<reason>` keeps a name for the network.
A pattern beginning with `#` is about channels and anything else about nicks,
so `#help*` never stops anybody being called `helpdesk`.

```
RESV #staff :for the people who run this place
RESV *serv :nobody here speaks for services
```

Somebody who asks for a reserved channel is told why (479), and somebody who
asks for a reserved nick likewise (432). That is the difference between this
and a spam filter: a filter is quiet on purpose, because telling a spammer
what caught them hands them the way around it, while a reservation is a rule
people are meant to be able to read.

Operators are not held to it — reserving the staff channel and then being
unable to enter it would be a strange way to run a network — and a channel
that already has people in it keeps them; the reservation stops anybody else
coming in. Reservations are stored, cross links, and expire on their own when
given a duration. `UNRESV <pattern>` gives the name back.

### Shuns

A K-line closes the connection, which tells whoever was behind it to come back
from another address. `SHUN [<seconds>] <nick!user@host> :<reason>` leaves them
connected and lets nothing they say reach anybody:

- They may listen, answer a `PING`, and leave. Everything else they type quietly
  does nothing — no error, no numeric, no hint. A shun that announced itself
  would just be a slower kill.
- `QUIT` and `PART` still work, without the parting words: a quit reason is
  shouted into every channel they were in, so it is dropped with the rest.
- They are never told, and neither is anybody else except the operators, under
  snomask `b`.

Shuns live beside K-lines and D-lines: stored in the database, carried to every
server when set, listed by `STATS s`, lifted by `UNSHUN`, and expiring on their
own when given a duration. A mask made only of wildcards is refused, and so is
one covering the operator setting it.

### Exemptions

`ELINE [<seconds>] <mask> :<reason>` says who none of that applies to.

Every blocklist eventually lists somebody who belongs here — a shared address,
a VPN, an exit node — and without a way to say so the only answers are to stop
believing the list for everybody or to stop asking it. Both give up more than
the one address was worth. An exemption is how one address is vouched for while
the rest of it stands.

```
ELINE *!*@10.0.0.0/8 :the office
ELINE 30d *!*@vpn.example :people we know come through here
```

It covers every kind of refusal this server makes on its own account: a D-line
and the blocklist at the door, and a K-line or a shun once there is a nick to
judge. It is judged twice — on the address alone before there is a nick, and on
`nick!user@host` after — so being vouched for does not stop when somebody says
who they are.

It is not a promise about behaviour. `KILL` still works, and so does a channel
ban: an exemption is about the standing rules, not about an operator's hand.

Like the bans it lives in the database, goes to every server when set, expires
on its own when given a duration, and is refused if the mask is nothing but
wildcards — that one would vouch for the network and undo every ban at once.
`STATS e` reads them back and `UNELINE` stops vouching. Unlike a ban, a mask
covering the operator setting it is allowed: that check exists to stop somebody
shutting themselves out by accident, and an exemption cannot.

A mask and a kind together are what name an entry, so a K-line, a shun and an
exemption can each stand against the same mask and lifting one leaves the
others.

### Spam filters

`SPAMFILTER` is a pattern, what it is looked for in, and what happens when it
is found — what other servers call the same thing. Operators with the `ban`
privilege.

```
SPAMFILTER ADD <targets> <action> [<seconds>] :<pattern>
SPAMFILTER DEL <id|pattern>
SPAMFILTER LIST
SPAMFILTER TEST :<text>
```

| Part | Meaning |
|---|---|
| `targets` | Letters: `p` private messages, `c` channel messages, `n` nicks, `t` topics, `q` quit reasons, `r` real names — or `*` for all of them |
| `action` | `warn` (let it through and tell the operators), `block` (refuse the line), `kill` (refuse it and close the connection), `kline` / `dline` (refuse it and ban the address for `<seconds>`, 0 for no end) |
| `<pattern>` | A glob, matched as a ban mask is — say `*phrase*` to catch it anywhere in a line. Between slashes (`/…/`) it is a regular expression instead |

A pattern made only of wildcards is refused, and so is one that matches the
nick or real name of the operator adding it. Operators are never filtered: a
filter that killed the person who could lift it is a server nobody can get
back into. The sender is never told which pattern caught them — that would be
handing them the way around it — so a blocked message is simply "not
delivered", a blocked topic "not set", and a filtered quit reason becomes
"Quit". The operators are told, under snomask `f`, and so is the log.

Filters are kept in the database, carried to every server when they are set,
and bursted to a server that links afterwards, so the network agrees on them.
Server bans and reservations are bursted the same way, capped at 512 of each:
a server that has been running for years has a ban list that is not a greeting.
`SPAMFILTER TEST` asks what a line would hit without anybody sending it, and
`LIST` shows each filter's id, what it watches, and how many times it has
matched since the server started. At most 64 filters, each pattern at most 512
characters: every line a client sends is held against all of them on the one
dispatch loop, so the cost is a budget rather than a preference. Regular
expressions are matched in time linear in the line, so a pattern cannot be
made to hang the server.

### Looking after your own account

There is no NickServ to message, so the account commands are commands.
`REGISTER` and `VERIFY` make one, `PASSWD` changes its password, `RESETPASS`
recovers it, `GROUP` reserves the other nicks you go by, and `DROPACCOUNT`
ends it. Two more fill the gaps:

`ACCOUNTINFO` says what the server is holding about you — when the account was
registered and last seen, the address on it, every nick grouped to it, the
channels it founded, whether an operator has kept it out of the expiry sweep.
An operator with the `ban` privilege can ask about somebody else's;
nobody else can.

`SETEMAIL <current password> <new address>` moves the account to another
address. The address is what a forgotten password goes to, so this is the one
change that could quietly take an account away from the person who owns it,
and it asks for two things: the password, which says it is you, and a code
read at the new address, which says you can receive there.

```
SETEMAIL hunter2 me@newhost.example
-> NOTE SETEMAIL SENT me@newhost.example :A code is on its way…
SETEMAIL K7M2QJ4T
-> NOTE SETEMAIL CHANGED alice :alice is now at me@newhost.example
```

Until the code comes back the account keeps the address it had, so a borrowed
session cannot point it somewhere else and wait for a reset. Reading the new
address proves as much as reading the first one did, so an account that never
verified is verified by this. One code at a time per account, and the address
itself is held to the same `mail_gap_secs` as `REGISTER` and `RESETPASS`.

### Grouped nicks

An account's own name is reserved for it. `GROUP` reserves the nick you are
using as well — the work nick, the phone nick — so nobody else can sit on it,
and so that being logged in is enough to use any of them. Up to five besides
the account's own name; `GROUP -<nick>` gives one back, `GROUP *` lists them.
You have to be using a nick to group it: reserving names you have never been
seen under is squatting, and the server does not help with that. A grouped
nick goes when the account goes, whether by `DROPACCOUNT` or by expiry, and
cannot be registered as an account by anybody else while it is held.

## Accounts, Channels and Moderation

rIRCd has no separate services package: what NickServ and ChanServ do on a
traditional network is done by the server itself, against MariaDB.

| Traditional services feature | rIRCd |
|---|---|
| Nick registration | `REGISTER` / `VERIFY` (draft/account-registration), with optional email verification |
| Identify | SASL PLAIN, SCRAM-SHA-256 or EXTERNAL — no `/msg NickServ` |
| Nick protection | Registered nicks are reserved for their account (`nick_protection`) |
| Nick recovery | `GHOST <nick>` closes a stale session of your own that is holding it, wherever on the network it is |
| Password change | `PASSWD <current> <new>` — the current one is asked for even though you are logged in, and your other logins are closed |
| Password recovery | `RESETPASS <account>` mails a code; `RESETPASS <account> <code> <new>` uses it and closes every login to the account |
| Dropping an account | `DROPACCOUNT <password>` — removes the account and everything that named it; channels it founded are left with no founder |
| Channel access list | `CHANACCESS #channel` — the founder, and everyone whose operator or voice status is remembered |
| Giving a channel up | `CHANDROP #channel` — by the founder, or by an operator with the `channels` privilege; operators keep their standing |
| Channel founder | The account that creates a channel; always opped on join, never shut out of it by its own `+b`/`+i`/`+k`/`+l`, and not kickable or deoppable in it |
| Channel transfer | `CHANOWN #channel <account>` — by the founder, or by an operator, said out loud in the channel |
| Channel access lists | `MODE +o` / `+v` on an **account** is remembered and restored on the next join. Somebody not logged in holds the status while they are there and no longer: a name proves nothing, so remembering one would hand the status to whoever took it next |
| Channel modes, topic, key | Persisted; kept when an owned channel empties, and restored on startup |
| Ban lists (`AKICK`-ish) | `+b`, `+e`, `+I` and `+q` masks are persisted and restored |
| Network bans | `KLINE` / `UNKLINE`, persisted and enforced on connect — on every server: a ban set on one crosses the links, closes what it matches there, and is written down there too. A mask made of wildcards is refused, typed or received. Hosts may be networks (`*@203.0.113.0/24`). `DLINE` / `UNDLINE` ban an address or network at the socket, before anything is spent on the connection |
| Server notices | User mode `+s` with a mask of letters says which server notices an operator hears — `a` accounts, `b` bans, `c` connections, `f` floods, `k` kills and forced nick changes, `l` links, `n` nick changes, `o` OPER attempts, `s` server (REHASH, expiry). `MODE <you> +s +cn` adds, `-s` clears; a new operator starts with everything but connections and nick changes. `HELP SNOMASK` |
| Vhosts | `SETHOST` (oper), plus automatic cloaking via `cloak_key` |
| Server-side ignore | `SILENCE +<mask>` / `-<mask>` / `SILENCE` to list — a mask is somebody who does not exist to you: no message, notice or invitation of theirs arrives, and nothing tells them so. `nick`, `nick!user@host` and `~a:account` are all masks; 32 per person, advertised as `SILENCE=32` |

Still absent: per-channel access *levels* beyond operator and voice, `AKICK`,
and memos.

### Owning a channel

Whoever creates a channel while logged in is its founder, which is an account
rather than a nick — whoever is logged in as it owns the channel, on any
connection and under any name.

A founder is opped whenever they come back, cannot be kicked out of their own
channel, cannot be deopped in it, and is not shut out by its own `+b`, `+i`,
`+k` or `+l`. An operator turning on the person who appointed them is how a
channel gets stolen, and none of those doors opens that way.

That leaves ownership needing a door of its own, which is `CHANOWN`:

```
CHANOWN #channel              what it says: who this channel belongs to
CHANOWN #channel <account>    hand it on
```

The founder may hand their own channel on — somebody leaves a project and the
channel should go where the project went. A network operator may hand on any
channel, because one whose founder has vanished, or whose founder is the
problem, has no other way out. An operator doing it is announced in the channel
as an operator and logged by name: an operator who wants a channel can already
kick, mode and ban their way through it, so what keeps them honest is not being
unable to act but being unable to act quietly.

The outgoing founder keeps operator status. Handing a channel on is not the
same as being thrown out of it. The new owner must be an account that exists,
and the change crosses the network as a `CACCESS` line, so every server agrees
about whose channel it is.

`CHANACCESS #channel` lists who has the run of a channel — its founder, and
everyone whose operator or voice status is remembered between visits. A status
that is remembered is a status that can be forgotten about, and this is how a
founder sees what they have given away. Like `CHANOWN`, it answers "no such
channel" to somebody who cannot see a `+s` or `+i` channel.

`CHANDROP #channel` gives a channel up: the founder may give up their own, and
an operator with the `channels` privilege may take the founder off any. The
operators keep their standing, so the channel goes on being somebody's to run;
it just stops being anybody's to own, and `CHANOWN` by an operator is how it
gets an owner again. It is said in the channel, whoever did it.

### Your account

There is no NickServ to `SET PASSWORD` at, so the server answers for it:

```
PASSWD <current> <new>                        change your password
RESETPASS <account>                           have a reset code mailed to you
RESETPASS <account> <code> <new password>     use it
DROPACCOUNT <password>                        remove your account
```

`PASSWD` asks for the current password even though you are logged in — a
logged-in session is not proof of knowing it — and closes your other logins,
since a changed password is meant to lock somebody out and a live session is
the somebody. With `multiclient`, your other devices are the same login and
stay.

`RESETPASS <account>` answers the same way whatever happened, because a
command that said "no such account" would be a way of finding out which names
are accounts. It sends at most one code per quarter hour to an account, the
code is good for that long, and using it closes every login to the account:
whoever is resetting the password cannot log in, so any session that exists is
somebody else's. It needs `[email]`; without it there is nowhere to send a code.

`DROPACCOUNT` removes the account and everything that named it — its profile,
its read markers, its push endpoints, its place on every operator and voice
list — because a name that is free to register again must not come with a
previous life attached. Channels it founded are left with no founder; their
operators keep their standing and a network operator can give them a new one.

Every one of these is charged against the same failed-login budget as a bad
SASL or `OPER` attempt, and so is `REGISTER` itself: each registration is a
hash, a row, and with `[email]` a message to an address the client chose,
which unbounded is an open mail relay for anybody who can connect. No address
is mailed twice in a quarter hour whoever asks, by `REGISTER` or `RESETPASS`.
A password check is a password check whatever command it arrives in.

Operators are told, by server notice, when somebody becomes an operator and
when somebody fails to. It is how a stolen operator password gets noticed.

A channel made by somebody who is not logged in has no founder, and never gets
one — there was no account to write down. `channel_creation = "accounts"` is
the setting that closes that: it gates *making* a channel, never joining one,
so every channel on the network is owned from its first moment. `opers` makes
the channel list something decided rather than grown, which suits a private
network and would be hostile on a general one.

## Channel Persistence

Channels, topics, modes, operator lists, voice lists, and message history are all stored in MariaDB automatically.

A channel that belongs to somebody — it has a founder, or an operator whose
status was granted to last — stays known when the last person walks out, with
its modes, bans, topic and access lists intact, so it is still itself when
somebody comes back. A channel nobody owns is forgotten when it empties, the
way a name two people used for an afternoon should be: modes on their own do
not keep one alive, because with nobody able to lift them a `+k` whose key is
forgotten would seal the channel rather than save it.

- **Topic** — persisted whenever a channel topic is set; 333 RPL_TOPICWHOTIME and 329 RPL_CREATIONTIME sent on JOIN.
- **Channel modes** — mode flags (`+imnstRcC`), key (`+k`), user limit (`+l`), join throttle (`+j`) and flood limit (`+f`) are saved to the database on every MODE change, kept when an owned channel empties, and restored on startup.
- **Expiry** — a registration is kept for as long as `[expiry]` says, which by default is forever; see that section.
- **Ban and exception lists** — `+b`, `+e`, `+I` and `+q` masks are saved per channel and restored, so neither an empty room nor a restart makes an owned channel forget who was banned.
- **Operators / Voice** — stored per channel **by account**; whoever logs in to one receives `@`/`+` automatically when they join, under any nick. Status granted to somebody with no account applies while they are present and is not written down. Rows stored under a bare nick by an older version are dropped at startup, with a count in the log — they granted nothing that could be trusted, because nick reservation is what would have protected them and it fails open when the database is unreachable.
- **Direct messages** — private conversations are stored per nick pair and replayed by `CHATHISTORY <nick>`; `CHATHISTORY TARGETS` lists only the requesting user's own conversations.
- **Message history** — PRIVMSG, NOTICE, and channel events (JOIN, PART, QUIT, TOPIC, NICK) are appended (up to 1,000 entries per channel, oldest pruned). Clients with `draft/chathistory` can request history via `CHATHISTORY LATEST/BEFORE/AFTER/AROUND/BETWEEN #channel <cursor> <limit>` or list active conversations with `CHATHISTORY TARGETS timestamp=<from> timestamp=<to> <limit>`. Clients with `draft/event-playback` receive the full event timeline; otherwise only messages are returned.
- **Edit history** — Edited messages retain a pointer to their original msgid. On CHATHISTORY replay, clients with `draft/message-edit` receive the `+draft/edit` tag so they can update their local buffer.
- **Read markers** — `MARKREAD` timestamps are persisted per account in MariaDB and survive server restarts.
- **Metadata** — `METADATA` key-value entries set on users and channels are persisted in MariaDB.

---

## IRCv3 Support

Capability names follow the registry: features the specifications advertise with
an ISUPPORT token (WHOX, UTF8ONLY, BOT, ACCOUNTEXTBAN) are **not** advertised as
capabilities, and work for every client. Names rIRCd advertised before 1.4 are
still accepted in `CAP REQ` so older clients keep working.

| Capability / feature | Status | Notes |
|----------------------|--------|--------|
| **capability-negotiation** | Full | CAP LS/REQ/ACK/NAK/END, 302 multi-line |
| **message-tags** | Full | Parse & send tags; TAGMSG; msgid/server-time/account tags |
| **Client-only tags** | Full | Server forwards `+`-prefixed tags on PRIVMSG/NOTICE/TAGMSG |
| **server-time** | Full | `time` tag on messages for capped clients |
| **message-ids** | Full | `msgid` tag (with message-tags); unique id per message |
| **batch** | Full | NAMES and chathistory wrapped in BATCH |
| **echo-message** | Full | PRIVMSG, NOTICE, TAGMSG echoed to sender when cap set |
| **multi-prefix** | Full | NAMES/WHO send all prefixes in rank order (`@%+`) |
| **extended-join** | Full | JOIN `#ch account :realname` for clients with cap |
| **account-tag** | Full | `account=` tag on messages for capped clients |
| **account-notify** | Full | ACCOUNT on SASL login/quit to channel peers with cap |
| **chghost** | Full | SETHOST/SETUSER (oper-only); CHGHOST to channel peers with cap |
| **setname** | Full | SETNAME command; broadcast to setname peers |
| **away-notify** | Full | AWAY to channel peers with cap when user sets/unsets away |
| **invite-notify** | Full | INVITE to channel members with cap when someone is invited |
| **labeled-response** | Full | Client `label` tag echoed on all replies |
| **standard-replies** | Full | FAIL for SETNAME, REDACT, UTF-8 errors |
| **no-implicit-names** | Full | No NAMES burst on JOIN when client has cap |
| **userhost-in-names** | Full | NAMES (353) with full `nick!user@host` when client has cap |
| **UTF8ONLY** | Full | ISUPPORT token (not a capability); non-UTF-8 rejected with `FAIL … INVALID_UTF8` |
| **cap-notify** | Full | CAP NOTIFY with current cap list on REQ/ACK and END; dynamic `CAP NEW`/`CAP DEL` on REHASH |
| **draft/extended-isupport** | Full | ISUPPORT command; 005 before registration |
| **WHOX** | Full | ISUPPORT token (not a capability); `WHO <target> %fields[,token]` answered with 354 RPL_WHOSPCRPL for any client |
| **bot-mode** | Full | `BOT=B` ISUPPORT token (not a capability); umode +B, `bot` tag, RPL_WHOISBOT (335) |
| **draft/oper-tag** | Full | `draft/oper=<name>` tag on messages from IRC operators, for clients with the cap |
| **draft/message-redaction** | Full | REDACT command; soft-delete in DB; CHATHISTORY replays REDACT events for client sync |
| **draft/message-edit** | Full | PRIVMSG with `+draft/edit=<msgid>` tag; DB-backed ownership check; edit history replayed in CHATHISTORY |
| **draft/react** | Full | TAGMSG with `+draft/react=<emoji>`; forwarded via client-only tag relay |
| **draft/unreact** | Full | TAGMSG with `+draft/unreact=<emoji>`; forwarded via client-only tag relay |
| **typing** | Full | TAGMSG with `+typing=active/paused/done`; forwarded via client-only tag relay |
| **reply** | Full | Messages with `+reply=<msgid>` tag forwarded as-is |
| **ACCOUNTEXTBAN** | Full | ISUPPORT token (not a capability); MODE +b ~a:account, JOIN 474 when banned by account |
| **EXTBAN mute** | Full | ISUPPORT `EXTBAN=~,OSajmnrt`; `MODE +b ~m:nick!*@*` keeps someone from talking without keeping them out. Voice lifts it, and `MODE +e ~m:mask` excepts from it. `MODE #chan +b` with no mask reads the list without needing op, and RPL_BANLIST/RPL_EXCEPTLIST/RPL_INVITELIST name who set each entry and when |
| **sasl** | Full | AUTHENTICATE PLAIN, SCRAM-SHA-256, and EXTERNAL (TLS client cert); 903/904; certfp auto-associated on PLAIN/SCRAM login |
| **monitor** | Full | MONITOR +/−/C/L/S; 730/731/732/733/734; on join/quit/nick |
| **extended-monitor** | Full | AWAY/ACCOUNT/CHGHOST/SETNAME forwarded for monitored nicks; `nick!user@host` masks (`*`/`?`) may be monitored as well as plain nicks |
| **sts** | Full | Strict Transport Security; advertised in CAP LS only when TLS is configured; `duration=2592000` |
| **draft/channel-rename** | Full | RENAME old new [reason]; op-only; fallback PART+JOIN for clients without cap |
| **draft/chathistory** | Full | CHATHISTORY LATEST/BEFORE/AFTER/AROUND/BETWEEN/TARGETS for channels **and direct conversations**; BATCH chathistory; DB-backed; limit 200 |
| **draft/event-playback** | Full | JOIN/PART/QUIT/TOPIC/NICK events stored in DB and replayed in CHATHISTORY |
| **draft/network-icon** | Full | Optional `ICON=` ISUPPORT token; config `network.icon` |
| **draft/read-marker** | Full | MARKREAD target [timestamp]; per-account, persisted in MariaDB. A client with no account keeps its marker for the life of the connection only — a connection id does not come back tomorrow to read it |
| **draft/metadata-2** / **draft/metadata-3** | Full | METADATA GET/LIST/SET/CLEAR/SUB/UNSUB/SUBS/SYNC; key-value per user and channel. A person's keys are filed under their **account**, not their nick, so a profile follows the person whatever they are called and the next holder of a name never inherits an avatar or a display name that was never theirs. Somebody with no account has their keys filed under the nick, never written down, and dropped when the connection goes; logging in during registration files them under the account instead. Metadata set under a nick by an older version is moved onto its account at startup, and dropped if no account by that name exists. Both names of the same specification are advertised; replies to a `-3` client come back in a `metadata` batch and subscription notices as RPL_KEYVALUE. `before-connect` lets a client set its own keys during registration; RPL_WHOISKEYVALUE (760) carries them in WHOIS. An invite-only or secret channel does not hand its metadata to non-members |
| **STATUSMSG** | Full | PRIVMSG/NOTICE to `@#channel` (ops+) or `+#channel` (voiced+); advertised in 005 `STATUSMSG=@+` |
| **draft/account-registration** | Full | REGISTER \* [email] password; logs the client in on success; optional email verification via VERIFY (`[email]` config) |
| **draft/multiline** | Full | BATCH draft/multiline; max-bytes=4096, max-lines=20; fallback for non-multiline clients |
| **draft/pre-away** | Full | AWAY during registration; applied after NICK/USER complete |
| **draft/channel-context** | Full | `+draft/channel-context` tag forwarded to channel members |
| **draft/client-batch** | Full | Client-originated BATCH types collected and relayed to recipients |
| **CLIENTTAGDENY** | Full | Optional 005 token; config `server.client_tag_deny` |
| **WebIRC** | Full | WEBIRC password gateway hostname ip; config `[webirc]` |
| **WebSocket** | Full | IRCv3 WebSocket transport; `listen_ws`/`listen_wss` config; subprotocol `text.ircv3.net` |
| **draft/webpush** | Full | `WEBPUSH REGISTER`/`UNREGISTER`; VAPID-signed, aes128gcm-encrypted pushes for DMs and highlights; `VAPID=` ISUPPORT token; `[webpush]` config |
| **draft/filehost** | Full | HTTPS file upload endpoint with HTTP Basic auth (same credentials as SASL PLAIN); reuses `[tls]` certs; `FILEHOST=` / `draft/FILEHOST=` ISUPPORT tokens; MIME-typed downloads; configurable max upload size |

---

## Roadmap

Features under consideration for future releases:

| Feature | Description |
|---------|-------------|
| **Offline direct messages** | Accept a `PRIVMSG` to a registered user who is not connected, store it, and push it — today an offline nick still answers 401, and only channel mentions reach absent users |
| **custom-account-name** | Let an account be named something other than the current nick; needs channel op/voice lists to stop treating nicks and account names as interchangeable first |

---

## Standard IRC Commands

In addition to IRCv3 features, rIRCd implements the standard IRC command set:

| Command | Numerics | Description |
|---------|----------|-------------|
| `LIST` | 321/322/323 | List channels. `ELIST=CMNTU`: `>N`/`<N` by user count, a glob name mask, `!mask` for the channels it does not match, `C>N`/`C<N` by how long ago the channel was created, `T>N`/`T<N` by how long ago the topic was set (both in minutes) |
| `LUSERS` | 251/252/254/255/265/266 | Server user/channel statistics |
| `VERSION` | 351 | Server version string |
| `TIME` | 391 | Server local time |
| `INFO` | 371/374 | Server info and uptime |
| `LINKS` | 364/365 | Linked servers (single-server: lists self) |
| `STATS u` | 242/219 | Server uptime |
| `STATS o` | 243/219 | IRC operator list |
| `STATS k` | 216/219 | Server bans in force, with time remaining |
| `STATS m` | 212/219 | How often each command has been used |
| `WHOWAS` | 314/312/369 | Historical nick info; the last 5 visits of each of the last 10,000 nicks in memory, 20 per nick in the database for 30 days |
| `WHO` mask | 352/315 | Supports glob masks (`*`, `?`) against nick!user@host; respects +i invisible mode |
| `HELP` / `HELPOP` | 704/705/706 | Per-command help text |
| `KNOCK` | 710/711 | Request invite to an invite-only channel; notifies ops |
| `KILL` | — | Oper-only: forcibly disconnect a user; broadcasts QUIT to their channels |
| `KLINE` | — | Oper-only: `KLINE [<seconds>] <mask> :<reason>` — refuse connections matching a mask; existing ones are closed. The host may be a network in CIDR form (`*@203.0.113.0/24`, `*@2001:db8::/32`). Persisted in MariaDB |
| `UNKLINE` | — | Oper-only: remove a ban |
| `DLINE` | — | Oper-only: `DLINE [<seconds>] <address\|network> :<reason>` — turn an address away the moment it connects, before the handshake, the blocklist lookup or a connection slot has been spent on it. CIDR for a network; nothing wider than a /8 (IPv4) or /16 (IPv6). Crosses links like `KLINE`; `STATS d` lists them |
| `UNDLINE` | — | Oper-only: lift a D-line |
| `TESTMASK` | — | Oper-only: `TESTMASK <mask>` — how many people a K-line on this mask would hit, here and on the rest of the network (724), before anybody sets it |
| `SPAMFILTER` | — | Oper-only (`ban`): patterns an operator would rather never see again; see **Spam filters** |
| `SHUN` | — | Oper-only (`ban`): `SHUN [<seconds>] <mask> :<reason>` — leave somebody connected and let nothing they say reach anybody. See **Shuns** |
| `RESV` | — | Oper-only (`ban`): `RESV [<seconds>] <pattern> :<reason>` — a name this network keeps for itself. `#`-patterns are channels, anything else nicks |
| `UNRESV` | — | Oper-only (`ban`): give a reserved name back |
| `UNSHUN` | — | Oper-only (`ban`): lift a shun |
| `ELINE` | — | Oper-only (`ban`): `ELINE [<seconds>] <mask> :<reason>` — say who the bans and the blocklist do not apply to. See **Exemptions** |
| `UNELINE` | — | Oper-only (`ban`): stop vouching for a mask |
| `GROUP` | — | Reserve the nick you are using for your account; `GROUP -<nick>` releases one, `GROUP *` lists them |
| `SETEMAIL` | — | `SETEMAIL <current password> <new address>` then `SETEMAIL <code>` — move your account to another address. See **Looking after your own account** |
| `ACCOUNTINFO` | — | `ACCOUNTINFO [<account>]` — what the server is holding about an account. Yours without asking; somebody else's needs the `ban` privilege. `ACCINFO` is the same command |
| `NOEXPIRE` | — | Oper-only (`channels`): keep an account or a channel out of `[expiry]`'s reach |
| `MAP` | — | The network as a tree with a user count per server (015/017) |
| `STATS` | — | `STATS u` uptime and `STATS m` command counts are for anybody; `o` (operator blocks), `k` (K-lines), `d` (D-lines), `s` (shuns), `e` (exemptions), `y` (connection classes — 218), `l` (what each connection has carried: send queue, messages and bytes each way, how long it has been open — 211) and `t` (what this server has been doing — 249) are for operators |
| `TRACE` | — | Oper-only: `TRACE [<nick>]` — the connections this server is holding (204/205) and the servers it is linked to (206), ending with 262. The class is how each one arrived: `plain`, `tls` or `websocket` |
| `SAJOIN` | — | Oper-only (`channels`): `SAJOIN <nick> <#channel>` — put somebody in a channel. The server invites them, so `+b`, `+i`, `+k`, `+l` and `+j` open; `+O`, `+Z` and `+R` still hold, because a forced join that broke a channel's promise would be the server lying on the operator's behalf. Somebody on another server is joined by that server at this one's request |
| `SAPART` | — | Oper-only (`channels`): `SAPART <nick> <#channel> [:<reason>]` — take somebody out of a channel; an ordinary PART, with the reason given |
| `SAMODE` | — | Oper-only (`channels`): `SAMODE <#channel> <modes> [<args>]` — set channel modes without holding ops there. Shown as the operator's own MODE; the operators are told it was done this way |
| `DIE` | — | Oper-only: shut the server down |
| `ADMIN` | 256/257/258/259 | Who runs this server (`[server] admin_*`) |
| `GHOST` | — | Close a stale session holding a nick your account owns, on this server or another one |
| `WALLOPS` | — | Oper-only: broadcast a message to all users with `+w` |
| `MOTD` | 375/372/376 | Send the message of the day |
| `ISON` | 303 | Check which nicks in a list are currently online |
| `USERHOST` | 302 | Return `nick=+user@host` info for up to 5 nicks |

---

## User Modes

| Mode | Set by | Description |
|------|--------|-------------|
| `+B` | User | Bot mode — shown in WHOIS as a bot (RPL_WHOISBOT 335) |
| `+i` | User | Invisible — hidden from WHO unless sharing a channel |
| `+o` | Server | IRC operator — set by successful OPER command |
| `+r` | Server | Registered — set automatically on SASL login |
| `+w` | User | Receives WALLOPS broadcasts from opers |
| `+s` | Oper | Server notice mask — `MODE <you> +s [+\|-]<letters>` chooses which server notices you hear (`a` accounts, `b` bans, `c` connections, `f` floods, `k` kills, `l` links, `n` nick changes, `o` OPER attempts, `s` server); `-s` clears it. `HELP SNOMASK` |
| `+g` | Callerid — only people on your `ACCEPT` list may send you direct messages. A sender who is not is told once (716/717) and you are told who knocked (718), once a minute per knocker. `ACCEPT <nick>`, `ACCEPT -<nick>`, `ACCEPT *` to list |

---

## Channel Modes

| Mode | Description |
|------|-------------|
| `+o` | Channel operator |
| `+v` | Voice (+) |
| `+h` | Half-op (%) |
| `+b` | Ban list — glob masks and the extended bans `~a:` (account), `~r:` (real name), `~j:` (in another channel), `~S:` (client certificate), `~O` (operators), `~m:` (mute rather than ban), `~n:` (no nick change) and `~t:` (lifts itself). The prefixes peel one at a time, so they stack: `~m:~r:*spam*` mutes by real name, `~t:1h:~j:#raiders` expires |
| `+e` | Ban exception list — exempt users bypass `+b` bans |
| `+I` | Invite exception list — matching users bypass `+i` without explicit INVITE |
| `+q` | Quiet list — silences matching users without kicking |
| `+i` | Invite-only |
| `+m` | Moderated — only `+v`/`+h`/`+o` may speak |
| `+n` | No external messages |
| `+s` | Secret channel |
| `+t` | Topic restricted to ops |
| `+k` | Channel key (password) |
| `+l` | User limit |
| `+j` | Join throttle, `<joins>:<seconds>` — no more than that many joins in that many seconds (480 past it). Whoever holds the channel, whoever it invited, and operators are let past, so a join flood slows the crowd without locking the owner out |
| `MLOCK` | Not a mode but a lock on them: `MLOCK #chan +nt-k` says `n` and `t` stay on and `k` stays off, and a MODE from anybody but the founder (or a server operator) that would change one is refused (742). Kept with the channel, carried to every server. `MLOCK #chan` shows it, `MLOCK #chan OFF` clears it |
| `+f` | Flood limit, `<lines>:<seconds>` — one line over it from one person and the server kicks them (`Channel flood (limit is 5 lines in 10 seconds)`); the line itself is not delivered. Ops, half-ops and operators are not the crowd it is for, and the founder cannot be kicked by it any more than by anyone else |
| `+N` | No nick changes while in the channel (447), unless you are an op or half-op there, or a server operator |
| `+T` | No NOTICEs to the channel from anybody who is not an op or half-op; dropped silently, as a refused NOTICE always is |
| `+z` | Op-moderated: what somebody who may not speak (`+m`, `+M`, `+q`, a mute) says is delivered to the ops and half-ops as a message to `@#channel` instead of being refused — moderation the moderators can see |
| `+O` | Operators only: nobody else may join (520). Only a server operator may set it |
| `+L` | Overflow channel: when the channel is full (`+l`), somebody joining is told where they are being sent (470) and joins `#overflow` instead. One hop only |
| `+b ~t:…` | A timed ban: `+b ~t:30m:nick!*@*` lifts itself after 30 minutes — `s`, `m`, `h`, `d`, or a bare number of minutes, up to a year. The server removes it with a `MODE -b` everybody sees, on every server. The same on `+q`, and around another extban (`~t:1h:~a:account`) |
| `+b ~r:…` | A ban on the real name rather than the hostmask: `+b ~r:*seedy_marketing*`. A glob, because a real name is a sentence — and since a mode parameter cannot hold a space, `_` stands for one on both sides. Somebody who gave no real name is matched only by a pattern that matches nothing in particular |
| `+b ~j:#chan` | A ban on being somewhere else: `+b ~j:#raiders` keeps out whoever is in `#raiders` at the moment they try to come in |
| `+b ~S:…` | A ban on the TLS client certificate: `~S:*` is everybody who brought one, `~S:3b8f*` a particular one. Mostly useful as `+e ~S:*` — anybody who can prove who they are is excepted |
| `+b ~n:…` | Keeps one person's name still: they may talk, but not change nick while in the channel (447). The one-person version of `+N`, lifted by `+e ~n:mask`. Not a ban on coming in |
| `+b ~O` | Matches the server's operators. Written as a ban it is legal and does nothing useful; written as `+e ~O` it excepts them from what the room bans |
| `+R` | Registered users only — unregistered users cannot join or speak |
| `+M` | Only registered users may speak; anybody may join. Somebody given a voice or ops may speak regardless, as with `+m`. The anti-spam mode for a channel that wants to stay open to lurkers |
| `+Z` | TLS only — a connection not over TLS cannot join, and the mode cannot be set while anybody in the channel is not on TLS (490). What is said in a `+Z` channel has never crossed a wire in the clear on any hop this server controls |
| `+c` | Strip mIRC colour and formatting codes from messages |
| `+C` | Block CTCP messages (including `/me` actions) |

---

## What it says it does

`ISUPPORT` is a promise. A client that reads `NICKLEN=32` will not offer a
longer one; one that reads `TOPICLEN=307` will not warn somebody their topic is
about to be cut. Each of those numbers lives in exactly one place now — the
token the server sends and the code that enforces it read the same constant —
because they used to be written twice, which is how `CHANLIMIT` came to
advertise fifty while the configuration said something else.

`tests/smoke/test_isupport.py` holds the server to it. Every expectation in
that suite is read out of the server's own `ISUPPORT` rather than written down,
so it does not check that the numbers are any particular value: it checks that
the numbers the server gives out are the numbers it keeps. A nick one character
over the advertised length is refused, a topic fifty over is cut to exactly it,
a list takes the number it promises and refuses the next, and changing a
configured limit changes both the token and the behaviour.

## Performance

Measured rather than claimed. `tests/smoke/throughput.py <receivers> <senders>`
puts every client in one channel, so each message a sender posts is delivered
to every receiver, and reads the server's own CPU out of `/proc` around the
burst alone — so the figures are steady-state delivery, not the cost of
setting the connections up.

```
tests/smoke/run.sh --stop
SMOKE_BIN=$PWD/target/release/rircd tests/smoke/run.sh --serve-only
SMOKE_SERVER_PID=$(pgrep -x rircd) python3 tests/smoke/throughput.py 500 5
```

`SMOKE_BIN` matters: the suites run the debug build because they are about
behaviour, and a debug build spends most of its time somewhere production
never goes. On a quiet sixteen-core machine over loopback, 500 receivers in
one channel and 5 senders:

| | |
|---|---|
| Deliveries | ~126,000 a second |
| One message to all 500 | p50 9.7 ms, p99 19.2 ms |
| Server CPU per delivery | ~21 µs — about 9 µs its own work, about 12 µs asking the kernel |

The second half of that is the interesting one. Every message is written to
every recipient as it arrives rather than being held back to fill a buffer, so
a delivery costs roughly one task wakeup and one `write` on the recipient's
socket. That is the price of a chat server that answers immediately, and it is
where the time goes: the server's own work — matching, tagging, copying — is
the smaller half, and the fan-out loop builds one copy per set of negotiated
capabilities rather than one per person so that it stays that way.

## Testing

`cargo test` runs the unit and integration tests: message formatting, RFC 8291
encryption vectors, capability gating, verification-code rules, and fuzzers that
throw arbitrary bytes at the parser and at the link protocol.

End-to-end, against a real server with a throwaway MariaDB and an SMTP sink
behind it:

```bash
tests/smoke/run.sh                  # every suite, then tear down
tests/smoke/run.sh --keep           # leave it up for manual poking
tests/smoke/run-link.sh             # two servers, linked
tests/smoke/run-link.sh --tls       # the same, over an encrypted link
```

And against [progval/irctest](https://github.com/progval/irctest), which is the
suite the other IRC servers are measured with:

```bash
tests/smoke/run.sh --serve-only     # it needs the database
tests/irctest/run.sh
```

Where that leaves things, on the same checkout with the same markers: rIRCd
passes **544 of 557** with nothing failing, and four more under
`IRCTEST_RIRCD_CASEMAPPING=rfc1459` — which this server implements and the
default run therefore skips. The six that never run are two for non-UTF-8
messages, refused on purpose, and four `WHO` tests irctest marks "not
consistently implemented" and skips for everybody. For something to measure
against, Ergo 2.19.1 on the same machine passes 527 and skips 26.

Two of the suites are about being attacked rather than being correct:
`test_hostile.py` is a client that is not trying to be a client, and
`test_link_hostile.py` is a peer that lies about which servers it speaks for.
And `soak.py` runs for hours against a linked pair, watching for memory or open
files that grow when they should not.

See [tests/smoke/README.md](tests/smoke/README.md) and
[tests/irctest/README.md](tests/irctest/README.md).

---

## License

BSD 3-Clause. See [LICENSE](LICENSE).
