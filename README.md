# rIRCd

A bleeding-edge IRC server in Rust, following [IRCv3 specifications](https://ircv3.net/irc/).

## Quick Start

```bash
# One-time setup (creates /etc/rIRCd/ with config, users, channels, motd)
sudo rircd init

# Run the server
sudo rircd run

# In another terminal: stop the server
sudo rircd stop

# Check if the server is running
rircd status
```

Connect with any IRC client to `localhost:6667`.

## Configuration

Config files live in `/etc/rIRCd/`:

| File | Purpose |
|------|---------|
| `config.toml` | Server identity, listeners, timeouts, MOTD, optional `server.client_tag_deny` (list of client-only tags to drop, or `["*"]` for all) |
| `users.toml` | Registered user accounts (nick, password, email, public_key) for SASL |
| `channels.toml` | Channel config: name, topic, operators, voice (applied on join) |
| `motd` | Message of the day |
| `history/` | Directory for channel message history (one `.toml` file per channel) |

**users.toml** uses `[[user]]` tables with `nick`, `password` (bcrypt; use `rircd genpasswd`), `email`, and `public_key`. SASL authentication uses the nick as the account name.

**channels.toml** uses `[[channel]]` tables with `name`, `topic`, `operators` (nicks/accounts that get @ on join), and `voice` (nicks/accounts that get + on join). Channels listed here are created on startup with the given topic; operators and voice are applied when those users join.

**history/** holds `channel_name.toml` files (channel name without `#`) with a `messages` array of `{ ts, source, text, msgid }`. PRIVMSG and NOTICE to channels are appended automatically. Clients with **draft/chathistory** can request history via `CHATHISTORY LATEST #channel * limit` (or legacy `CHATHISTORY #channel [count]`); replies use BATCH chathistory when client has batch+message-tags (limit 200).

When the server runs, it writes its PID to `rircd.pid` in the same directory as `config.toml` (e.g. `/etc/rIRCd/rircd.pid`). This is used by `rircd stop` and `rircd status`.

## Commands

- `rircd init [--dir /etc/rIRCd]` — Initialize config directory
- `rircd run` — Start the server (writes PID file, handles SIGINT/SIGTERM for clean shutdown)
- `rircd stop` — Stop the running server (sends SIGTERM; Unix only)
- `rircd status` — Show whether the server is running (checks PID file and process)
- `rircd genpasswd` — Generate bcrypt hash for passwords

All commands (except `init` and `genpasswd`) use `--config` to find the config file; the PID file path is derived from the config path (e.g. `--config /etc/rIRCd/config.toml` → `/etc/rIRCd/rircd.pid`).

## IRCv3 support

Implementation status for capabilities we advertise and related behaviour:

| Capability / feature | Status | Notes |
|----------------------|--------|--------|
| **capability-negotiation** | Full | CAP LS/REQ/ACK/NAK/END, 302 multi-line |
| **message-tags** | Full | Parse & send tags; TAGMSG; msgid/server-time/account tags |
| **Client-only tags (typing, react, reply, etc.)** | Full | Server forwards +prefixed tags on PRIVMSG/NOTICE/TAGMSG per message-tags |
| **server-time** | Full | `time` tag on messages for capped clients |
| **message-ids** | Full | `msgid` tag (with message-tags); unique id per message |
| **batch** | Full | NAMES (353/366) and chathistory wrapped in BATCH; no netsplit/netjoin batch types |
| **echo-message** | Full | PRIVMSG, NOTICE, TAGMSG echoed to sender when cap set |
| **multi-prefix** | Full | NAMES/WHO send all prefixes in rank order (@%+) when client has cap |
| **extended-join** | Full | JOIN `#ch account :realname` for clients with cap |
| **account-tag** | Full | `account=` tag on messages for capped clients |
| **account-notify** | Full | ACCOUNT on SASL login/quit to channel peers with cap |
| **chghost** | Full | SETHOST/SETUSER (oper-only) set vhost/vuser; CHGHOST to channel peers with cap |
| **setname** | Full | SETNAME command, broadcast to setname peers, NAMELEN in 005, FAIL on error |
| **away-notify** | Full | AWAY to channel peers with cap when user sets/unsets away |
| **invite-notify** | Full | INVITE to channel members with cap when someone is invited |
| **labeled-response** | Full | Client `label` tag echoed on all replies to that client |
| **standard-replies** | Full | FAIL for SETNAME (INVALID_REALNAME), REDACT, UTF-8; can extend to other errors |
| **no-implicit-names** | Full | No NAMES burst on JOIN when client has cap |
| **userhost-in-names** | Full | NAMES (353) with full `nick!user@host` when client has cap |
| **pre-away** | Full | AWAY during registration; applied after NICK/USER complete |
| **utf8only** | Full | Non-UTF-8 rejected with FAIL \* INVALID_UTF8 (when client has standard-replies) |
| **cap-notify** | Full | CAP NOTIFY with current cap list on REQ/ACK and END when client has cap |
| **draft/extended-isupport** | Full | ISUPPORT command; 005 before registration |
| **whox** | Full | WHO with %fields; 354 RPL_WHOSPCRPL |
| **bot** | Full | Umode +B; RPL_WHOISBOT (335) in WHOIS |
| **message-redaction** | Full | REDACT command; msgid store; broadcast to channel/DM recipients |
| **account-extban** | Full | MODE +b ~a:account; JOIN 474 when banned by account |
| **sasl** | Full | AUTHENTICATE PLAIN, 903/904, account on client/pending |
| **monitor** | Full | MONITOR +/−/C/L/S; 730 RPL_MONONLINE, 731 RPL_MONOFFLINE, 732/733/734; on join/quit/nick |
| **draft/channel-rename** | Full | RENAME old new [reason]; op-only; fallback PART+JOIN for clients without cap |
| **draft/chathistory** | Full | CHATHISTORY LATEST/BEFORE/AFTER; BATCH chathistory; file history; CHATHISTORY=200 in 005 |
| **draft/read-marker** | Full | MARKREAD target [timestamp]; per-account store; sent on JOIN when cap set |
| **draft/metadata-2** | Full | METADATA GET/LIST/SET/CLEAR; in-memory key-value per user/channel; 761/766, FAIL |
| **draft/account-registration** | Full | REGISTER \* [email] password (account = current nick); VERIFY (INVALID_CODE if no verification) |
| **draft/multiline** | Full | BATCH draft/multiline; PRIVMSG/NOTICE lines; max-bytes=4096, max-lines=20; fallback for non-multiline clients |
| **CLIENTTAGDENY** | Full | Optional 005 token and relay filtering; config `server.client_tag_deny` (e.g. `["+typing"]` or `["*"]`) |
| **WebIRC** | Full | WEBIRC password gateway hostname ip (config [webirc] password); real IP from gateways |

**Other behaviour:** RPL_ISUPPORT (005) with NAMELEN, CHANLIMIT, WHOX, BOT, ACCOUNTEXTBAN=~a, MONITOR=100, CHATHISTORY=200, MSGREFTYPES=msgid,timestamp, optional CLIENTTAGDENY; INVITE and 341; OPER (sets oper flag for SETHOST/SETUSER); TLS listeners; MOTD. Account registration appends to `users.toml` (bcrypt).

## License

See [LICENSE](LICENSE).
