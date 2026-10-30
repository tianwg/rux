#!/usr/bin/env python3
"""Test client for rux's control protocol.

Talks rex.control.v1 over the server's Unix socket. Set REX_SOCKET to
point at a running rux-server; otherwise the client uses rux's default
socket, /tmp/rux.sock.

Usage:
  rexclient.py methods                     # list methods via help.all
  rexclient.py call METHOD '{"json":1}'    # call one method
  rexclient.py raw                         # read events for a while
"""
import base64
import json
import os
import socket
import ssl
import struct
import sys
import threading
import zlib

SOCK = os.environ.get("REX_SOCKET") or "/tmp/rux.sock"
PROTO = "rex.control.v1"


class WS:
    def __init__(self, path="/api/control", sock=None, protocol=PROTO):
        self.sock = sock or SOCK
        self.path = path
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(self.sock)
        self.protocol = protocol
        self.key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            "Host: rex\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {self.key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: {protocol}\r\n"
            "\r\n"
        )
        self.s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise RuntimeError("handshake EOF")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        self.head = head.decode("latin1")
        if "101" not in self.head.split("\r\n")[0]:
            raise RuntimeError("handshake failed: " + self.head)
        self.buf = rest
        self.lock = threading.Lock()

    def send_json(self, obj):
        payload = json.dumps(obj, separators=(",", ":")).encode()
        self._frame(0x1, payload)

    def _frame(self, opcode, payload):
        mask = os.urandom(4)
        n = len(payload)
        hdr = bytes([0x80 | opcode])
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self.lock:
            self.s.sendall(hdr + mask + masked)

    def _read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise EOFError
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv_frame(self):
        """Return (opcode, payload) for the next complete frame."""
        msg = b""
        opcode = None
        while True:
            b0, b1 = self._read_exact(2)
            fin, rsv1, op = b0 >> 7, (b0 >> 6) & 1, b0 & 0x0F
            ln = b1 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._read_exact(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._read_exact(8))[0]
            payload = self._read_exact(ln)
            if op == 9:
                self._frame(10, payload)
                continue
            if op == 8:
                raise EOFError("close")
            if rsv1:
                d = zlib.decompressobj(-15)
                payload = d.decompress(payload + b"\x00\x00\xff\xff") + d.flush()
            if opcode is None:
                opcode = op
            msg += payload
            if fin:
                return opcode, msg

    def recv_json(self):
        msg = b""
        while True:
            b0, b1 = self._read_exact(2)
            fin, rsv1, op = b0 >> 7, (b0 >> 6) & 1, b0 & 0x0F
            ln = b1 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._read_exact(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._read_exact(8))[0]
            payload = self._read_exact(ln)
            if op == 9:  # ping
                self._frame(10, payload)
                continue
            if op == 8:
                raise EOFError("close")
            if rsv1:
                d = zlib.decompressobj(-15)
                payload = d.decompress(payload + b"\x00\x00\xff\xff") + d.flush()
            msg += payload
            if fin:
                return json.loads(msg)


def call(method, params=None, quiet=False):
    ws = WS()
    ws.send_json({"type": "hello", "client": {"kind": "cli", "platform": "macos", "name": "probe", "version": "0.0.0"}, "api_revision": 7})
    welcome = ws.recv_json()
    if not quiet:
        print(json.dumps(welcome), file=sys.stderr)
    req = {"type": "request", "id": "probe-1", "method": method}
    if params is not None:
        req["payload"] = params
    ws.send_json(req)
    while True:
        msg = ws.recv_json()
        if msg.get("type") == "response" and msg.get("id") == "probe-1":
            return msg


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "call":
        params = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
        out = call(sys.argv[2], params)
        print(json.dumps(out, indent=2)[:20000])
    elif cmd == "raw":
        ws = WS()
        ws.send_json({"type": "hello", "client": {"kind": "cli", "platform": "macos", "name": "probe", "version": "0.0.0"}, "api_revision": 7})
        print(json.dumps(ws.recv_json()))
        while True:
            print(json.dumps(ws.recv_json()))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
