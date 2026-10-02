#!/usr/bin/env python3
"""
Test servers for stress-testing Heimdall's VPN from an emulator.

Runs on the development machine, bound to 127.0.0.1. An Android emulator reaches it as 10.0.2.2,
so traffic from the emulator's shell goes app -> Heimdall's TUN -> Heimdall's upstream socket ->
here. Started and stopped by run-stress.sh; see StressClient.java for the client side.

  HTTP  : port BASE     deterministic downloads, uploads and misbehaving responses
  TCP   : port BASE + 1 byte echo
  UDP   : port BASE + 2 datagram echo

HTTP paths (n = body size in bytes, seed = content seed):
  GET  /bytes?n=&seed=          body with Content-Length
  GET  /chunked?n=&seed=        body with chunked transfer encoding
  GET  /close?n=&seed=          body delimited by connection close
  GET  /slow?n=&seed=&ms=       body with Content-Length, written in 1 KB pieces every `ms`
  GET  /closefast?n=&seed=      body with Content-Length, socket closed right after the last byte
  GET  /rst?n=&seed=            half of the announced body, then a TCP reset
  GET  /hang                    accepts the request and never answers
  POST /echo                    reads the body, answers with its length and SHA-256 as JSON
  POST /slowread?bps=           like /echo, but reads the body at `bps` bytes per second

Every body response carries X-Sha256 so the client can verify what it received.
"""
import hashlib
import json
import socket
import socketserver
import struct
import sys
import threading
import time
from urllib.parse import urlparse, parse_qs

BLOCK = 64 * 1024


def body_blocks(n, seed):
    """Yields a deterministic body of n bytes in blocks."""
    base = bytes((i * 31 + seed * 17 + (i >> 8)) & 0xFF for i in range(BLOCK))
    sent = 0
    index = 0
    while sent < n:
        # vary each block a little so that reordered or duplicated blocks change the hash
        block = struct.pack(">I", index) + base[4:]
        take = min(BLOCK, n - sent)
        yield block[:take]
        sent += take
        index += 1


def body_sha256(n, seed):
    h = hashlib.sha256()
    for block in body_blocks(n, seed):
        h.update(block)
    return h.hexdigest()


class HttpHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.request.settimeout(120)
        self.buffer = b""

    def read_until(self, marker):
        while marker not in self.buffer:
            chunk = self.request.recv(65536)
            if not chunk:
                return None
            self.buffer += chunk
        head, self.buffer = self.buffer.split(marker, 1)
        return head

    def read_exact(self, n, bps=0):
        h = hashlib.sha256()
        remaining = n
        while remaining > 0:
            if self.buffer:
                chunk, self.buffer = self.buffer[:remaining], self.buffer[remaining:]
            else:
                chunk = self.request.recv(min(65536, remaining) if not bps else min(bps // 10 or 1, remaining))
                if not chunk:
                    return None, n - remaining
                if bps:
                    time.sleep(0.1)
            h.update(chunk)
            remaining -= len(chunk)
        return h.hexdigest(), n

    def send_head(self, status, headers):
        lines = ["HTTP/1.1 " + status] + [f"{k}: {v}" for k, v in headers.items()]
        self.request.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())

    def handle(self):
        try:
            while self.handle_one():
                pass
        except (ConnectionError, socket.timeout, OSError):
            pass

    def handle_one(self):
        head = self.read_until(b"\r\n\r\n")
        if head is None:
            return False
        lines = head.decode("latin-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        url = urlparse(target)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        n = int(q.get("n", "0"))
        seed = int(q.get("seed", "1"))
        keep_alive = headers.get("connection", "").lower() != "close"
        path = url.path

        if method == "POST":
            length = int(headers.get("content-length", "0"))
            digest, received = self.read_exact(length, int(q.get("bps", "0")) if path == "/slowread" else 0)
            body = json.dumps({"length": received, "sha256": digest}).encode()
            self.send_head("200 OK", {"Content-Type": "application/json", "Content-Length": len(body)})
            self.request.sendall(body)
            return keep_alive and digest is not None

        if path == "/hang":
            time.sleep(600)
            return False

        sha = body_sha256(n, seed)
        if path == "/bytes" or path == "/slow" or path == "/closefast":
            self.send_head("200 OK", {"Content-Length": n, "X-Sha256": sha})
            if path == "/slow":
                delay = int(q.get("ms", "100")) / 1000.0
                for block in body_blocks(n, seed):
                    for i in range(0, len(block), 1024):
                        self.request.sendall(block[i:i + 1024])
                        time.sleep(delay)
            else:
                for block in body_blocks(n, seed):
                    self.request.sendall(block)
            return keep_alive and path != "/closefast"
        if path == "/chunked":
            self.send_head("200 OK", {"Transfer-Encoding": "chunked", "X-Sha256": sha})
            for block in body_blocks(n, seed):
                self.request.sendall(f"{len(block):x}\r\n".encode() + block + b"\r\n")
            self.request.sendall(b"0\r\n\r\n")
            return keep_alive
        if path == "/close":
            self.send_head("200 OK", {"Connection": "close", "X-Sha256": sha})
            for block in body_blocks(n, seed):
                self.request.sendall(block)
            return False
        if path == "/rst":
            self.send_head("200 OK", {"Content-Length": n, "X-Sha256": sha})
            sent = 0
            for block in body_blocks(n, seed):
                if sent + len(block) > n // 2:
                    break
                self.request.sendall(block)
                sent += len(block)
            time.sleep(0.3)
            # linger 0 turns close() into a reset
            self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return False

        body = b"not found"
        self.send_head("404 Not Found", {"Content-Length": len(body)})
        self.request.sendall(body)
        return keep_alive


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(120)
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    break
                self.request.sendall(data)
            # the client half-closed: finish our side too
            self.request.shutdown(socket.SHUT_WR)
        except (ConnectionError, socket.timeout, OSError):
            pass


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class ThreadedTcp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 512


class ThreadedUdp(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    base = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    servers = [
        ThreadedTcp(("127.0.0.1", base), HttpHandler),
        ThreadedTcp(("127.0.0.1", base + 1), EchoHandler),
        ThreadedUdp(("127.0.0.1", base + 2), UdpEchoHandler),
    ]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"stress servers listening on 127.0.0.1: http {base}, tcp echo {base + 1}, udp echo {base + 2}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
