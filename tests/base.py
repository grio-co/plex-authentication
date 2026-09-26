"""Shared fixtures for the plex-forward-auth test-suite (stdlib only).

The gateway reads its configuration from the environment at import time, so we
set a known configuration *before* importing it. Individual tests override
module attributes with ``unittest.mock.patch.object`` where they need a
different policy.

``ServerTestCase`` starts the real HTTP server on an ephemeral loopback port so
the handler, cookie and header code paths are exercised end-to-end. Every
function that talks to plex.tv / Tautulli is patched out; the suite never
touches the network.
"""
import http.client
import io
import json
import os
import sys
import threading
import unittest
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "forward-auth"))

TEST_ENV = {
    "APP_SECRET": "unit-test-secret-do-not-use",
    "ALLOWED_PLEX_IDS": "1382106, 42",
    "ALLOWED_PLEX_EMAILS": "Owner@Example.com",
    "TRUSTED": "10.0.0.0/8, 192.168.1.0/24",
    "PUBLIC_URL": "https://auth.example.com/",
    "REDIRECT_SUFFIX": ".example.com",
    "COOKIE_DOMAIN": ".example.com",
    "COOKIE_NAME": "plexauth",
    "SESSION_DAYS": "30",
    "MEMBER_HOSTS": "members.example.com",
    "TAUTULLI_URL": "",
    "TAUTULLI_KEY": "",
}
for _k, _v in TEST_ENV.items():
    os.environ[_k] = _v

import plex_forward_auth as mod  # noqa: E402  (must follow the env setup)

OWNER = {"id": 1382106, "username": "owner", "email": "owner@example.com"}
STRANGER = {"id": 999, "username": "stranger", "email": "stranger@example.net"}
MEMBER = {"id": 555, "username": "member", "email": "member@example.net"}


def session_cookie(payload, secret=None):
    """Return ``name=value`` for a signed session cookie, optionally signed with
    a different secret to simulate a forged token."""
    if secret is None:
        return f"{mod.COOKIE_NAME}={mod.sign(payload)}"
    with mock.patch.object(mod, "SECRET", secret.encode()):
        tok = mod.sign(payload)
    return f"{mod.COOKIE_NAME}={tok}"


def fake_urlopen_json(data):
    """A stand-in for ``urllib.request.urlopen`` returning a JSON body."""
    def _open(*_a, **_kw):
        return io.BytesIO(json.dumps(data).encode())
    return _open


def parse_set_cookie(header):
    """Split a Set-Cookie header into (name, value, {attr_lower: value})."""
    parts = [p.strip() for p in header.split(";")]
    name, _, value = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name, value, attrs


class ServerTestCase(unittest.TestCase):
    """Runs the real gateway on 127.0.0.1:<ephemeral> for the whole class."""

    @classmethod
    def setUpClass(cls):
        cls.server = mod.Server(("127.0.0.1", 0), mod.H)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        # Nothing in the suite may reach the network.
        self._no_net = mock.patch.object(
            mod.urllib.request, "urlopen",
            side_effect=AssertionError("network access attempted in tests"))
        self._no_net.start()
        self.addCleanup(self._no_net.stop)

    def request(self, path, headers=None, method="GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            body = resp.read()
            return resp.status, resp.getheaders(), body
        finally:
            conn.close()

    @staticmethod
    def header(headers, name):
        for k, v in headers:
            if k.lower() == name.lower():
                return v
        return None

    @staticmethod
    def headers_named(headers, name):
        return [v for k, v in headers if k.lower() == name.lower()]
