"""Egress proxy: CONNECT and plain-HTTP forwarding to allowed hosts; refusals for metadata endpoints, strict-mode
unlisted hosts, and (fail closed) an unreachable daemon; one decision per host."""

from __future__ import annotations

import socket
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from interlockd.api import ApiServer
from interlockd.egress import Decider, make_server
from interlockd.integrations.client import InterlockClient


@pytest.fixture
def upstream():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): ...
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "5"); self.end_headers(); self.wfile.write(b"hello")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def client(settings, tmp_path):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(tmp_path)]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    api = ApiServer(d, "tok", "127.0.0.1", 0); api.start_background()
    yield InterlockClient(url="http://{}:{}".format(*api.address), token="tok", agent_type="egress-proxy"), d
    api.shutdown()


def _proxy(decider):
    srv = make_server("127.0.0.1:0", decider)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _connect(pport, host, port):
    s = socket.create_connection(("127.0.0.1", pport), timeout=10)
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    status = s.recv(4096).decode(errors="replace")
    return s, status


def test_forwarding_and_refusals(client, upstream):
    c, d = client
    dec = Decider(c, allowed_hosts=["localhost"])
    srv, pport = _proxy(dec)
    try:
        s, status = _connect(pport, "localhost", upstream)               # HTTPS-style tunnel to an allowed host
        assert status.startswith("HTTP/1.1 200")
        s.sendall(f"GET / HTTP/1.1\r\nHost: localhost:{upstream}\r\nConnection: close\r\n\r\n".encode())
        assert b"hello" in s.recv(4096); s.close()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{pport}"}))
        assert opener.open(f"http://localhost:{upstream}/x", timeout=10).read() == b"hello"   # plain HTTP
        s, status = _connect(pport, "169.254.169.254", 80)               # cloud metadata endpoint: refused, never dialled
        assert status.startswith("HTTP/1.1 403") and "metadata" in status.lower(); s.close()
        n = len(list(d.spool.iter_records()))
        _connect(pport, "localhost", upstream)[0].close()
        assert len(list(d.spool.iter_records())) == n                      # cached: one decision per host
    finally:
        srv.shutdown()


def test_strict_refuses_unlisted_hosts(client):
    c, _ = client
    srv, pport = _proxy(Decider(c, strict=True, allowed_hosts=["github.com"]))
    try:
        _, status = _connect(pport, "example.invalid", 443)
        assert status.startswith("HTTP/1.1 403") and "strict" in status
    finally:
        srv.shutdown()


def test_daemon_down_fail_closed(monkeypatch):
    monkeypatch.setenv("INTERLOCK_FAIL_MODE", "closed")
    srv, pport = _proxy(Decider(InterlockClient(url="http://127.0.0.1:9", token="tok")))
    try:
        _, status = _connect(pport, "github.com", 443)
        assert status.startswith("HTTP/1.1 403") and "unreachable" in status
    finally:
        srv.shutdown()
