#!/usr/bin/env python3
"""IRCv3 WebSocket transport: a client on ws:// must be a first-class IRC client."""

import os

from harness import IRC_HOST, Client, check, section, summary
from wsclient import WebSocketError, WsClient

WS_PORT = int(os.environ.get("SMOKE_WS_PORT", "16668"))

section("handshake")
ws = WsClient(IRC_HOST, WS_PORT)
check("server accepts the upgrade", ws.sock is not None)
check("negotiates the text.ircv3.net subprotocol",
      ws.subprotocol == "text.ircv3.net", ws.subprotocol)

section("registration over WebSocket")
ws.register("wsuser", caps=["message-tags", "server-time", "echo-message", "batch"])
check("001 welcome", bool(ws.find(" 001 ")), ws.lines[:4])
check("005 ISUPPORT", bool(ws.find(" 005 ")), ws.lines[:8])
check("MOTD delivered", bool(ws.find(" 376 ")) or bool(ws.find(" 422 ")))

section("messaging between a WebSocket client and a TCP client")
tcp = Client("tcpuser", caps=["message-tags", "server-time"])
tcp.join("#wsroom")
mark = tcp.mark()
ws.send("JOIN #wsroom")
ws.read(1.5)
tcp.read(1.0)
check("WebSocket JOIN reaches TCP peers",
      bool(tcp.find("JOIN", "#wsroom", lines=tcp.since(mark))), tcp.since(mark))
check("the WebSocket client sees its own JOIN", bool(ws.find("JOIN", "#wsroom")), ws.lines[-5:])

mark = tcp.mark()
ws.send("PRIVMSG #wsroom :hello from a websocket")
tcp.read(1.5)
check("message crosses ws -> tcp",
      bool(tcp.find("PRIVMSG", "hello from a websocket", lines=tcp.since(mark))), tcp.since(mark))

mark = ws.mark()
tcp.send("PRIVMSG #wsroom :and back from tcp")
ws.read(1.5)
crossed = ws.find("PRIVMSG", "and back from tcp", lines=ws.since(mark))
check("message crosses tcp -> ws", bool(crossed), ws.since(mark))
check("tags survive the transport", bool(crossed) and "time=" in crossed[0], crossed)

section("a long line over one frame")
long_text = "x" * 400
mark = tcp.mark()
ws.send(f"PRIVMSG #wsroom :{long_text}")
tcp.read(1.5)
check("a 400-character message arrives intact",
      bool(tcp.find(long_text, lines=tcp.since(mark))), [l[:80] for l in tcp.since(mark)])

section("PING/PONG keepalive")
mark = ws.mark()
ws.send("PING wskeepalive")
ws.read(1.5)
check("server answers PING", bool(ws.find("PONG", lines=ws.since(mark))), ws.since(mark))

section("quitting")
mark = tcp.mark()
ws.close()
tcp.read(2.0)
check("peers see the QUIT when the socket closes",
      bool(tcp.find("QUIT", lines=tcp.since(mark))), tcp.since(mark))

section("binary subprotocol")
try:
    binary = WsClient(IRC_HOST, WS_PORT, subprotocol="binary.ircv3.net")
    check("binary.ircv3.net is also offered",
          binary.subprotocol == "binary.ircv3.net", binary.subprotocol)
    binary.close()
except WebSocketError as e:
    check("binary.ircv3.net is also offered", False, str(e))

tcp.close()
summary("websocket")
