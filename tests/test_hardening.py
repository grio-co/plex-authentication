"""Cookie attribute configuration, proxy-header trust and sign-in rate limiting."""
import os
import time
import unittest
from unittest import mock

from base import ServerTestCase, mod, OWNER, session_cookie, parse_set_cookie

REMOTE = {"X-Real-IP": "203.0.113.9"}
OTHER = {"X-Real-IP": "198.51.100.4"}


def payload():
    return {"sub": "1382106", "name": "owner", "email": "owner@example.com",
            "adm": True, "mbr": True, "exp": int(time.time()) + 3600}


# ---------------------------------------------------------------- cookie flags
class CookieAttrsUnitTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(mod.cookie_attrs(), "; Path=/; HttpOnly; Secure; SameSite=Lax; Domain=.example.com")
        self.assertTrue(mod.COOKIE_SECURE)
        self.assertEqual(mod.COOKIE_SAMESITE, "Lax")
        self.assertTrue(mod.TRUST_PROXY_HEADERS)

    def test_secure_off(self):
        with mock.patch.object(mod, "COOKIE_SECURE", False):
            self.assertEqual(mod.cookie_attrs(), "; Path=/; HttpOnly; SameSite=Lax; Domain=.example.com")

    def test_samesite_strict_and_host_only(self):
        with mock.patch.object(mod, "COOKIE_SAMESITE", "Strict"), mock.patch.object(mod, "COOKIE_DOMAIN", ""):
            self.assertEqual(mod.cookie_attrs(), "; Path=/; HttpOnly; Secure; SameSite=Strict")

    def test_httponly_cannot_be_disabled(self):
        with mock.patch.object(mod, "COOKIE_SECURE", False), mock.patch.object(mod, "COOKIE_SAMESITE", "None"):
            self.assertIn("HttpOnly", mod.cookie_attrs())


class EnvParsingTests(unittest.TestCase):
    def test_env_bool(self):
        for raw, expect in [("1", True), ("true", True), ("YES", True), ("on", True),
                            ("0", False), ("false", False), ("no", False), ("off", False),
                            ("garbage", False)]:
            with mock.patch.dict(os.environ, {"X_BOOL": raw}):
                self.assertEqual(mod._env_bool("X_BOOL", True), expect, raw)
        with mock.patch.dict(os.environ, {"X_BOOL": ""}):
            self.assertTrue(mod._env_bool("X_BOOL", True))
            self.assertFalse(mod._env_bool("X_BOOL", False))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(mod._env_bool("X_BOOL", True))

    def test_env_samesite(self):
        for raw, expect in [("lax", "Lax"), ("STRICT", "Strict"), (" none ", "None"), ("", "Lax")]:
            with mock.patch.dict(os.environ, {"X_SS": raw}):
                self.assertEqual(mod._env_samesite("X_SS"), expect, raw)
        with mock.patch.dict(os.environ, {"X_SS": "bogus"}), mock.patch("builtins.print") as p:
            self.assertEqual(mod._env_samesite("X_SS"), "Lax")
            p.assert_called_once()


class CookieFlagsHttpTests(ServerTestCase):
    def callback(self):
        with mock.patch.object(mod, "plex_poll", return_value="tok"), \
             mock.patch.object(mod, "plex_user", return_value=OWNER):
            return self.request("/callback?pin=1", REMOTE)

    def test_default_session_cookie_flags(self):
        status, headers, _ = self.callback()
        self.assertEqual(status, 302)
        _, _, attrs = parse_set_cookie(self.header(headers, "Set-Cookie"))
        self.assertIn("httponly", attrs)
        self.assertIn("secure", attrs)
        self.assertEqual(attrs["samesite"], "Lax")
        self.assertEqual(attrs["path"], "/")
        self.assertEqual(attrs["domain"], ".example.com")

    def test_cookie_secure_off(self):
        with mock.patch.object(mod, "COOKIE_SECURE", False):
            _, headers, _ = self.callback()
        _, _, attrs = parse_set_cookie(self.header(headers, "Set-Cookie"))
        self.assertNotIn("secure", attrs)
        self.assertIn("httponly", attrs)
        self.assertEqual(attrs["samesite"], "Lax")

    def test_cookie_samesite_strict(self):
        with mock.patch.object(mod, "COOKIE_SAMESITE", "Strict"):
            _, headers, _ = self.callback()
        _, _, attrs = parse_set_cookie(self.header(headers, "Set-Cookie"))
        self.assertEqual(attrs["samesite"], "Strict")
        self.assertIn("secure", attrs)

    def test_logout_clear_cookie_carries_same_flags(self):
        _, headers, _ = self.request("/logout", {**REMOTE, "Cookie": session_cookie(payload())})
        name, value, attrs = parse_set_cookie(self.header(headers, "Set-Cookie"))
        self.assertEqual((name, value, attrs["max-age"]), (mod.COOKIE_NAME, "", "0"))
        self.assertIn("httponly", attrs)
        self.assertIn("secure", attrs)
        self.assertEqual(attrs["samesite"], "Lax")
        self.assertEqual(attrs["domain"], ".example.com")

    def test_only_one_set_cookie_header(self):
        _, headers, _ = self.callback()
        self.assertEqual(len(self.headers_named(headers, "Set-Cookie")), 1)


# ------------------------------------------------------------- proxy headers
class ProxyHeaderTrustTests(ServerTestCase):
    def test_forwarded_headers_trusted_by_default(self):
        status, _, _ = self.request("/verify", {"X-Real-IP": "10.0.0.5"})
        self.assertEqual(status, 200)
        status, _, _ = self.request("/verify", {"X-Forwarded-For": "10.0.0.5"})
        self.assertEqual(status, 200)

    def test_forwarded_headers_ignored_when_disabled(self):
        with mock.patch.object(mod, "TRUST_PROXY_HEADERS", False):
            status, _, _ = self.request("/verify", {"X-Real-IP": "10.0.0.5"})
            self.assertEqual(status, 401)
            status, _, _ = self.request("/verify", {"X-Forwarded-For": "10.0.0.5"})
            self.assertEqual(status, 401)
            # the socket peer is what counts now
            with mock.patch.object(mod, "TRUSTED", [mod.ipaddress.ip_network("127.0.0.0/8")]):
                status, _, _ = self.request("/verify", {"X-Real-IP": "203.0.113.9"})
                self.assertEqual(status, 200)

    def test_empty_forwarded_header_falls_back_to_peer(self):
        with mock.patch.object(mod, "TRUSTED", [mod.ipaddress.ip_network("127.0.0.0/8")]):
            status, _, _ = self.request("/verify", {"X-Forwarded-For": ""})
            self.assertEqual(status, 200)


# --------------------------------------------------------------- rate limiter
class RateLimiterUnitTests(unittest.TestCase):
    def make(self, limit=3, window=60):
        clock = mock.Mock(return_value=1000.0)
        return mod.RateLimiter(limit, window, clock=clock), clock

    def test_allows_up_to_limit_then_denies_with_retry_after(self):
        rl, clock = self.make()
        self.assertEqual([rl.check("a") for _ in range(3)], [0, 0, 0])
        self.assertEqual(rl.check("a"), 60)
        clock.return_value = 1000.0 + 59.2
        self.assertEqual(rl.check("a"), 1)   # ceil(0.8) -> 1

    def test_retry_after_is_at_least_one_second(self):
        rl, clock = self.make(limit=1, window=1)
        rl.check("a")
        clock.return_value = 1000.0 + 0.999
        self.assertEqual(rl.check("a"), 1)

    def test_window_slides(self):
        rl, clock = self.make()
        rl.check("a"); clock.return_value = 1010.0
        rl.check("a"); rl.check("a")
        self.assertEqual(rl.check("a"), 50)          # oldest hit at 1000 expires at 1060
        clock.return_value = 1060.5
        self.assertEqual(rl.check("a"), 0)           # one slot freed
        self.assertGreater(rl.check("a"), 0)         # …and only one

    def test_denied_attempts_do_not_extend_the_ban(self):
        rl, clock = self.make(limit=1, window=10)
        rl.check("a")
        for t in (1001, 1005, 1009):
            clock.return_value = float(t)
            self.assertGreater(rl.check("a"), 0)
        clock.return_value = 1010.5
        self.assertEqual(rl.check("a"), 0)

    def test_keys_are_independent(self):
        rl, _ = self.make(limit=1)
        self.assertEqual(rl.check("a"), 0)
        self.assertEqual(rl.check("b"), 0)
        self.assertGreater(rl.check("a"), 0)
        self.assertGreater(rl.check("b"), 0)

    def test_zero_or_negative_limit_disables(self):
        for limit in (0, -1):
            rl, _ = self.make(limit=limit)
            self.assertEqual([rl.check("a") for _ in range(50)], [0] * 50)
            self.assertEqual(rl._hits, {})

    def test_stale_keys_are_swept(self):
        rl, clock = self.make(limit=5, window=10)
        for i in range(1023):
            rl.check(f"k{i}")
        self.assertEqual(len(rl._hits), 1023)
        clock.return_value = 2000.0                  # everything is stale now
        rl.check("fresh")                            # 1024th call triggers the sweep
        self.assertEqual(set(rl._hits), {"fresh"})

    def test_thread_safety_under_contention(self):
        import threading
        rl = mod.RateLimiter(500, 60)
        results = []
        def worker():
            results.append(sum(1 for _ in range(100) if rl.check("shared") == 0))
        ts = [threading.Thread(target=worker) for _ in range(10)]
        for t in ts: t.start()
        for t in ts: t.join()
        self.assertEqual(sum(results), 500)


class RateLimitHttpTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(mod, "LIMITER", mod.RateLimiter(2, 60))
        p.start()
        self.addCleanup(p.stop)

    def login(self, headers=REMOTE):
        with mock.patch.object(mod, "plex_pin", return_value=(1, "CODE")) as pin:
            status, hdrs, body = self.request("/login", headers)
        return status, hdrs, body, pin

    def test_login_limited_per_ip_with_retry_after(self):
        for _ in range(2):
            status, _, _, pin = self.login()
            self.assertEqual(status, 302)
            pin.assert_called_once()
        status, hdrs, body, pin = self.login()
        self.assertEqual(status, 429)
        pin.assert_not_called()
        ra = self.header(hdrs, "Retry-After")
        self.assertTrue(ra and ra.isdigit() and 1 <= int(ra) <= 60, ra)
        self.assertIn(b"Too many", body)
        self.assertIsNone(self.header(hdrs, "Set-Cookie"))
        self.assertEqual(self.header(hdrs, "Cache-Control"), "no-store")

    def test_other_ip_unaffected(self):
        for _ in range(3):
            self.login()
        status, _, _, _ = self.login(OTHER)
        self.assertEqual(status, 302)

    def test_callback_shares_the_login_budget(self):
        self.login(); self.login()
        with mock.patch.object(mod, "plex_poll", return_value="tok") as poll, \
             mock.patch.object(mod, "plex_user", return_value=OWNER):
            status, hdrs, _ = self.request("/callback?pin=1", REMOTE)
        self.assertEqual(status, 429)
        poll.assert_not_called()
        self.assertIsNone(self.header(hdrs, "Set-Cookie"))
        self.assertIsNotNone(self.header(hdrs, "Retry-After"))

    def test_verify_and_other_routes_never_limited(self):
        for _ in range(3):
            self.login()
        for path in ("/verify", "/healthz", "/", "/logout"):
            status, _, _ = self.request(path, {**REMOTE, "Cookie": session_cookie(payload())})
            self.assertNotEqual(status, 429, path)

    def test_disabled_limiter(self):
        with mock.patch.object(mod, "LIMITER", mod.RateLimiter(0, 60)):
            for _ in range(20):
                status, _, _, _ = self.login()
                self.assertEqual(status, 302)

    def test_limiter_keyed_by_socket_peer_when_proxy_headers_untrusted(self):
        with mock.patch.object(mod, "TRUST_PROXY_HEADERS", False):
            self.login(REMOTE); self.login(OTHER)
            status, _, _, _ = self.login({"X-Real-IP": "192.0.2.77"})
        self.assertEqual(status, 429)


if __name__ == "__main__":
    unittest.main()
