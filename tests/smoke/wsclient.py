"""A tiny WebSocket client, enough to speak IRC over the IRCv3 WebSocket transport.

Standard library only: does the HTTP upgrade by hand and implements the framing
subset a client needs (masked text frames out, unmasked frames in).
"""

import base64
import os
import socket
import struct
import time


class WebSocketError(Exception):
    pass


class WsClient:
    """An IRC connection carried over WebSocket, with the same surface as Client."""

    def __init__(self, host, port, subprotocol="text.ircv3.net", timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.lines = []
        self._buf = b""
        self._text = ""
        self.nick = None
        self.subprotocol = None
        self._handshake(host, port, subprotocol)

    # ── handshake ─────────────────────────────────────────────────────────────

    def _handshake(self, host, port, subprotocol):
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: {subprotocol}\r\n"
            f"\r\n"
        )
        self.sock.sendall(request.encode())

        self.sock.settimeout(5)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WebSocketError("connection closed during handshake")
            response += chunk

        head, _, rest = response.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode()
        if "101" not in status:
            raise WebSocketError(f"upgrade refused: {status}")
        for header in head.split(b"\r\n")[1:]:
            name, _, value = header.decode().partition(":")
            if name.strip().lower() == "sec-websocket-protocol":
                self.subprotocol = value.strip()
        self._buf = rest

    # ── framing ───────────────────────────────────────────────────────────────

    def _send_frame(self, payload, opcode=0x1):
        data = payload.encode() if isinstance(payload, str) else payload
        header = bytearray([0x80 | opcode])
        mask = os.urandom(4)
        length = len(data)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", length)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(bytes(header) + masked)

    def _decode_frames(self):
        """Pull complete frames out of the buffer, returning their payloads."""
        out = []
        while True:
            if len(self._buf) < 2:
                return out
            first, second = self._buf[0], self._buf[1]
            opcode = first & 0x0F
            masked = second & 0x80
            length = second & 0x7F
            offset = 2
            if length == 126:
                if len(self._buf) < offset + 2:
                    return out
                length = struct.unpack("!H", self._buf[offset:offset + 2])[0]
                offset += 2
            elif length == 127:
                if len(self._buf) < offset + 8:
                    return out
                length = struct.unpack("!Q", self._buf[offset:offset + 8])[0]
                offset += 8
            mask = b""
            if masked:
                if len(self._buf) < offset + 4:
                    return out
                mask = self._buf[offset:offset + 4]
                offset += 4
            if len(self._buf) < offset + length:
                return out
            payload = self._buf[offset:offset + length]
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            self._buf = self._buf[offset + length:]

            if opcode == 0x9:  # ping
                self._send_frame(payload, opcode=0xA)
            elif opcode == 0x8:  # close
                raise WebSocketError("server closed the WebSocket")
            elif opcode in (0x1, 0x2, 0x0):
                out.append(payload.decode("utf-8", "replace"))

    # ── IRC surface, mirroring harness.Client ─────────────────────────────────

    def send(self, line):
        # The IRCv3 WebSocket transport sends one message per IRC line.
        self._send_frame(line)
        return self

    def read(self, seconds=1.0):
        self.sock.settimeout(seconds)
        end = time.time() + seconds
        while time.time() < end:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            self._buf += chunk
            for payload in self._decode_frames():
                self._text += payload
                # Frames may or may not carry the trailing CRLF.
                while "\n" in self._text:
                    line, self._text = self._text.split("\n", 1)
                    line = line.rstrip("\r")
                    if line:
                        self.lines.append(line)
                        if line.startswith("PING"):
                            self.send("PONG " + line.split(" ", 1)[1])
                if self._text.strip() and "\n" not in self._text:
                    stripped = self._text.strip()
                    if stripped.startswith((":", "@", "PING", "ERROR")):
                        self.lines.append(stripped)
                        if stripped.startswith("PING"):
                            self.send("PONG " + stripped.split(" ", 1)[1])
                        self._text = ""
        return self.lines

    def register(self, nick, caps=None):
        self.nick = nick
        self.send("CAP LS 302")
        self.read(0.7)
        if caps:
            self.send("CAP REQ :" + " ".join(caps))
        self.send(f"NICK {nick}")
        self.send(f"USER {nick} 0 * :{nick}")
        self.send("CAP END")
        self.wait_for(" 376 ", " 422 ", " 001 ", seconds=6)
        return self

    def wait_for(self, *needles, seconds=5.0):
        start = len(self.lines)
        end = time.time() + seconds
        while time.time() < end:
            for line in self.lines[start:]:
                if any(n in line for n in needles):
                    return line
            self.read(0.3)
        for line in self.lines[start:]:
            if any(n in line for n in needles):
                return line
        return None

    def mark(self):
        return len(self.lines)

    def since(self, mark):
        return self.lines[mark:]

    def find(self, *needles, lines=None):
        pool = self.lines if lines is None else lines
        return [l for l in pool if all(n in l for n in needles)]

    def close(self):
        try:
            self.send("QUIT :done")
            self._send_frame(b"", opcode=0x8)
            self.sock.close()
        except (OSError, WebSocketError):
            pass
