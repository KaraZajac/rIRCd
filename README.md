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
| `listen` | `[":6667"]` | Plain-text listener addresses |
| `listen_tls` | `[]` | TLS listener addresses (requires `[tls]`) |
| `motd` | `"Welcome to rIRCd!"` | Message of the day (inline text, multiline OK) |
| `registration_timeout_secs` | `60` | Time allowed to complete NICK/USER before disconnect |
| `ping_timeout_secs` | `90` | How long to wait for PONG before sending next PING |
| `disconnect_timeout_secs` | `150` | Time after missed PONG before disconnecting client |
| `client_tag_deny` | _(unset)_ | List of client-only tags to drop (e.g. `["+typing"]` or `["*"]` to drop all) |

### `[network]`

| Key | Default | Description |
|-----|---------|-------------|
| `name` | `rIRCd` | Network name (shown in 005 NETWORK) |

### `[database]`

| Key | Default | Description |
|-----|---------|-------------|
| `host` | `localhost` | MariaDB/MySQL host |
| `port` | `3306` | MariaDB/MySQL port |
| `user` | _(empty)_ | Database username |
| `password` | _(empty)_ | Database password |
| `database` | `rircdb` | Database name |

### `[tls]`

Optional. Both fields must be set to enable TLS listeners.

| Key | Description |
|-----|-------------|
| `cert` | Path to PEM certificate file |
| `key` | Path to PEM private key file |

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
| `max_line_length` | `8191` | Max IRC line length in bytes |

### `[[opers]]`

Define IRC operators. Multiple `[[opers]]` blocks are allowed.

```toml
[[opers]]
name = "admin"
hostmask = "*"           # optional; restrict by host
password_hash = "$2a$..." # generate with: rircd genpasswd
```

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
max_line_length = 8191

[[opers]]
name = "admin"
hostmask = "*"
password_hash = "$2a$12$..."
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `rircd init [--dir /etc/rIRCd]` | Create config directory with a default `config.toml` |
| `rircd run [--config /etc/rIRCd/config.toml]` | Start the server; connects to DB, inits schema, writes PID file |
| `rircd stop [--config /etc/rIRCd/config.toml]` | Send SIGTERM to the running server (Unix only) |
| `rircd status [--config /etc/rIRCd/config.toml]` | Check if the server is running via PID file |
| `rircd genpasswd` | Interactively hash a password for use in `[[opers]]` |

The PID file is written to the same directory as `config.toml` (e.g. `/etc/rIRCd/rircd.pid`) and is removed on clean shutdown. `rircd stop` and `rircd status` use it to find the process.

---

## User Accounts

User registration is handled via the IRC `REGISTER` command (draft/account-registration) from any connected client:

```
REGISTER * [email|*] <password>
```

This stores a bcrypt hash of the password (for SASL PLAIN) and full SCRAM credentials (for SASL SCRAM-SHA-256) in MariaDB. Passwords must be at least 6 characters.

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

## Channel Persistence

Channels, topics, operator lists, voice lists, and message history are all stored in MariaDB automatically:

- **Topic** — persisted whenever a channel topic is set.
- **Operators / Voice** — stored per channel; users in these lists receive `@`/`+` automatically when they join.
- **Message history** — PRIVMSG and NOTICE to channels are appended (up to 1,000 messages per channel, oldest pruned). Clients with `draft/chathistory` can request history via `CHATHISTORY LATEST #channel * <limit>`.

---

## IRCv3 Support

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
| **utf8only** | Full | Non-UTF-8 rejected with FAIL when client has standard-replies |
| **cap-notify** | Full | CAP NOTIFY with current cap list on REQ/ACK and END |
| **draft/extended-isupport** | Full | ISUPPORT command; 005 before registration |
| **whox** | Full | WHO with %fields; 354 RPL_WHOSPCRPL |
| **bot** | Full | Umode +B; RPL_WHOISBOT (335) in WHOIS |
| **message-redaction** | Full | REDACT command; msgid store; broadcast to channel/DM recipients |
| **draft/message-edit** | Full | PRIVMSG with `+draft/edit=<msgid>` tag; sender ownership validated |
| **draft/react** | Full | TAGMSG with `+draft/react=<emoji>`; forwarded via client-only tag relay |
| **typing** | Full | TAGMSG with `+typing=active/paused/done`; forwarded via client-only tag relay |
| **reply** | Full | Messages with `+reply=<msgid>` tag forwarded as-is |
| **account-extban** | Full | MODE +b ~a:account; JOIN 474 when banned by account |
| **sasl** | Full | AUTHENTICATE PLAIN and SCRAM-SHA-256; 903/904; advertised as `sasl=PLAIN,SCRAM-SHA-256` |
| **monitor** | Full | MONITOR +/−/C/L/S; 730/731/732/733/734; on join/quit/nick |
| **extended-monitor** | Full | MONITOR patterns with `nick!user@host` globs (`*`/`?` wildcards) |
| **sts** | Full | Strict Transport Security; advertised in CAP LS only when TLS is configured; `duration=2592000` |
| **draft/channel-rename** | Full | RENAME old new [reason]; op-only; fallback PART+JOIN for clients without cap |
| **draft/chathistory** | Full | CHATHISTORY LATEST/BEFORE/AFTER; BATCH chathistory; DB-backed; limit 200 |
| **draft/read-marker** | Full | MARKREAD target [timestamp]; per-account in-memory store |
| **draft/metadata-2** | Full | METADATA GET/LIST/SET/CLEAR; in-memory key-value per user/channel |
| **draft/account-registration** | Full | REGISTER \* [email] password; VERIFY returns INVALID_CODE (no email verification) |
| **draft/multiline** | Full | BATCH draft/multiline; max-bytes=4096, max-lines=20; fallback for non-multiline clients |
| **draft/pre-away** | Full | AWAY during registration; applied after NICK/USER complete |
| **draft/channel-context** | Full | `+draft/channel-context` tag forwarded to channel members |
| **draft/client-batch** | Full | Client-originated BATCH types collected and relayed to recipients |
| **CLIENTTAGDENY** | Full | Optional 005 token; config `server.client_tag_deny` |
| **WebIRC** | Full | WEBIRC password gateway hostname ip; config `[webirc]` |

---

## Standard IRC Commands

In addition to IRCv3 features, rIRCd implements the standard IRC command set:

| Command | Numerics | Description |
|---------|----------|-------------|
| `LUSERS` | 251/252/254/255/265/266 | Server user/channel statistics |
| `VERSION` | 351 | Server version string |
| `TIME` | 391 | Server local time |
| `INFO` | 371/374 | Server info and uptime |
| `LINKS` | 364/365 | Linked servers (single-server: lists self) |
| `STATS u` | 242/219 | Server uptime |
| `STATS o` | 243/219 | IRC operator list |
| `WHOWAS` | 314/312/369 | Historical nick info; up to 5 entries per nick, in-memory |
| `HELP` | 704/705/706 | Per-command help text |
| `KNOCK` | 710/711 | Request invite to an invite-only channel; notifies ops |
| `KILL` | — | Oper-only: forcibly disconnect a user; broadcasts QUIT to their channels |
| `WALLOPS` | — | Oper-only: broadcast a message to all users with `+w` |
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

---

## Channel Modes

| Mode | Description |
|------|-------------|
| `+o` | Channel operator |
| `+v` | Voice (+) |
| `+h` | Half-op (%) |
| `+b` | Ban list (supports `~a:account` extban and glob masks) |
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
| `+R` | Registered users only — unregistered users cannot join or speak |
| `+c` | Strip mIRC colour and formatting codes from messages |
| `+C` | Block CTCP messages (including `/me` actions) |

---

## License

See [LICENSE](LICENSE).
