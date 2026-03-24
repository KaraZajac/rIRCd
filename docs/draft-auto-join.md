# draft/auto-join — IRCv3 Auto-Join Specification

**Status**: Draft
**Version**: 0.1
**Author**: rIRCd contributors

## Introduction

The `draft/auto-join` capability allows the server to send a list of channels
that the client should automatically join on connect. The channel list is
configured by the server administrator.

This is useful for directing new users to community channels, help channels,
or any default set of channels the network wants clients to join.

## Capability

    cap name:  draft/auto-join
    value:     (none)

The capability has no value parameters.

## Server Behaviour

### Configuration

The server administrator configures a comma-separated list of channels in the
server configuration:

    [server]
    auto_join = "#general, #help, #dev"

### Sending AUTOJOIN on connect

After the server has completed client registration (numerics 001-005, MOTD),
if the client has enabled `draft/auto-join` via `CAP REQ`, the server MUST
send the configured channel list using one or more `AUTOJOIN` messages:

    :<server> AUTOJOIN <channel>[,<channel>...]

If the channel list would exceed the 512-byte IRC line limit, the server MUST
split it across multiple `AUTOJOIN` messages.

If no `auto_join` channels are configured, the server MUST NOT send any
`AUTOJOIN` message.

### Message format

    :<server> AUTOJOIN #general,#help,#dev

Parameters:

| Position | Name     | Description                                    |
|----------|----------|------------------------------------------------|
| 1        | channels | Comma-separated list of channel names          |

The comma-separated format mirrors the `JOIN` command syntax, so clients can
feed the parameter directly into their own `JOIN` command.

## Client Behaviour

### Requesting the capability

    CAP REQ draft/auto-join

The client SHOULD only request this capability if it intends to act on the
channel list.

### Handling AUTOJOIN

On receiving an `AUTOJOIN` message, the client SHOULD:

1. Parse the comma-separated channel list from parameter 1.
2. Issue `JOIN <channels>` for the channels it wants to join.
3. Optionally filter or reorder the list based on user preferences.

The client MAY:

- Join all channels silently (typical for first-time users).
- Display the list to the user for confirmation before joining.
- Merge the list with its own stored channel list.
- Ignore channels it is already in (on reconnect).

### Collecting multiple AUTOJOIN messages

If the server splits the list across multiple `AUTOJOIN` messages, the client
SHOULD collect and combine all of them before joining. The client MAY use a
short delay or join after receiving the first non-AUTOJOIN message from the
server.

## Examples

### Basic auto-join

    Client: CAP LS 302
    Server: CAP * LS :draft/auto-join sasl ...
    Client: CAP REQ :draft/auto-join
    Server: CAP * ACK :draft/auto-join
    Client: NICK jdoe
    Client: USER jdoe 0 * :John Doe
    Client: CAP END
    Server: :irc.example.com 001 jdoe :Welcome ...
    ...registration numerics and MOTD...
    Server: :irc.example.com AUTOJOIN #general,#help,#dev
    Client: JOIN #general,#help,#dev

### No channels configured

    ...registration completes, cap is enabled...
    (no AUTOJOIN message is sent)

### Large channel list (split across messages)

    Server: :irc.example.com AUTOJOIN #a,#b,#c,#d,#e,#f,#g,#h,#i,#j
    Server: :irc.example.com AUTOJOIN #k,#l,#m,#n,#o,#p,#q,#r,#s,#t

## Security Considerations

- The channel list is server-configured and identical for all clients.
  It does not leak per-user information.
- The client always has the final say on whether to join — the server
  never force-joins. Clients can ignore the list entirely.
- Secret (+s) or keyed (+k) channels SHOULD NOT be placed in the
  auto-join list unless the administrator intends all connecting clients
  to attempt to join them.

## ISUPPORT

No ISUPPORT token is defined. The capability in `CAP LS` is sufficient for
feature discovery.
