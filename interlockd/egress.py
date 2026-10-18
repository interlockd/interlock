"""`interlock egress-proxy`: an HTTP(S) forward proxy that decides every outbound destination host.

    interlock egress-proxy --listen 127.0.0.1:7392 [--strict]
    interlock sandbox --egress http://127.0.0.1:7392 -- my-agent      # OS: localhost only; the proxy is the way out

CONNECT tunnels (HTTPS) and absolute-URI requests (plain HTTP) are both supported. HTTPS is tunnelled, never
decrypted: the proxy sees the destination host and port, not the content. Each new host in a session is decided
by the daemon as a `net_connect` tool call (the egress rules apply: metadata endpoints, raw IPs, sharing services,
unknown hosts) and recorded; `--strict` additionally refuses any host outside `trust.allowed_hosts`. Decisions are
cached per host for the proxy's lifetime.
"""

from __future__ import annotations

import select
import socket
import socketserver
import threading
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

from .integrations.client import InterlockClient


class Decider:
    def __init__(self, client: InterlockClient, *, strict: bool = False, allowed_hosts: list[str] | None = None,
                 session: str = "egress-proxy"):
        self.client, self.strict, self.allowed = client, strict, allowed_hosts or []
        self.session = session
        self.cache: dict[str, tuple[bool, str]] = {}
        self.lock = threading.Lock()

    def _allowlisted(self, host: str) -> bool:
        return any(host == h or fnmatchcase(host, h) or host.endswith("." + h.lstrip("*.")) for h in self.allowed)

    def allow(self, host: str, port: int) -> tuple[bool, str]:
        key = f"{host}:{port}"
        with self.lock:
            if key in self.cache:
                return self.cache[key]
        scheme = "https" if port == 443 else "http"
        v = self.client.decide("pre_action", "net_connect", {"url": f"{scheme}://{host}:{port}/", "host": host, "port": port},
                               session=self.session)
        if v is None:
            ok, why = (not self.client.fails_closed()), "daemon unreachable"
        elif self.client.stops(v):
            ok, why = False, v.get("reason") or "refused by policy"
        elif self.strict and not self._allowlisted(host):
            ok, why = False, f"{host} is not in trust.allowed_hosts (strict)"
        else:
            ok, why = True, ""
        with self.lock:
            self.cache[key] = (ok, why)
        return ok, why


def _relay(a: socket.socket, b: socket.socket) -> None:
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 60)
            if not r:
                return
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        return


def make_server(listen: str, decider: Decider) -> socketserver.ThreadingTCPServer:
    host, _, port = listen.rpartition(":")

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            c = self.request
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 65536:
                chunk = c.recv(4096)
                if not chunk:
                    return
                head += chunk
            first = head.split(b"\r\n", 1)[0].decode("latin-1")
            try:
                method, target, _ = first.split(" ", 2)
            except ValueError:
                return
            if method.upper() == "CONNECT":
                h, _, p = target.rpartition(":")
                dest_host, dest_port, forward = h.strip("[]"), int(p or 443), b""
            else:
                u = urlsplit(target)
                if not u.hostname:
                    c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    return
                dest_host, dest_port = u.hostname, u.port or 80
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                forward = head.replace(target.encode("latin-1"), path.encode("latin-1"), 1)
            ok, why = decider.allow(dest_host, dest_port)
            if not ok:
                body = f"[interlock] connection to {dest_host}:{dest_port} refused: {why}\n".encode()
                c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: "
                          + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                return
            try:
                up = socket.create_connection((dest_host, dest_port), timeout=15)
            except OSError as e:
                msg = f"upstream unreachable: {type(e).__name__}\n".encode()
                c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: " + str(len(msg)).encode() + b"\r\n\r\n" + msg)
                return
            with up:
                if forward:
                    up.sendall(forward)
                else:
                    c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                _relay(c, up)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    return Server((host or "127.0.0.1", int(port)), Handler)
