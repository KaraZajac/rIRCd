#!/usr/bin/env python3
"""Minimal SMTP sink for the smoke tests.

Speaks just enough SMTP for lettre to hand over a message, and writes each one to
`<out-dir>/mail-<n>.txt`. No TLS: the smoke config sets `encryption = "none"`.

    smtpsink.py <port> <out-dir>
"""

import os
import socketserver
import sys
import threading

_lock = threading.Lock()
_counter = 0
_out_dir = "."


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        global _counter
        self.wfile.write(b"220 sink.test ESMTP\r\n")
        in_data = False
        body = []

        while True:
            line = self.rfile.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\r\n")

            if in_data:
                if text == ".":
                    in_data = False
                    with _lock:
                        _counter += 1
                        path = os.path.join(_out_dir, f"mail-{_counter}.txt")
                    tmp = path + ".part"
                    with open(tmp, "w") as f:
                        f.write("\n".join(body))
                    os.rename(tmp, path)
                    body = []
                    self.wfile.write(b"250 2.0.0 Ok: queued\r\n")
                else:
                    # Undo dot-stuffing (RFC 5321 section 4.5.2).
                    body.append(text[1:] if text.startswith("..") else text)
                continue

            command = text.upper()
            if command.startswith(("EHLO", "HELO")):
                self.wfile.write(b"250-sink.test\r\n250 8BITMIME\r\n")
            elif command == "DATA":
                in_data = True
                self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif command == "QUIT":
                self.wfile.write(b"221 2.0.0 Bye\r\n")
                return
            else:
                # MAIL FROM, RCPT TO, RSET, NOOP...
                self.wfile.write(b"250 2.0.0 Ok\r\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    global _out_dir
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 12525
    _out_dir = sys.argv[2] if len(sys.argv) > 2 else "."
    os.makedirs(_out_dir, exist_ok=True)
    print(f"SMTP sink listening on 127.0.0.1:{port}, writing to {_out_dir}", flush=True)
    Server(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
