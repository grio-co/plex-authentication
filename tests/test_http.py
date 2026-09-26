"""End-to-end HTTP behaviour of the gateway (verify / login / callback / logout)."""
import time
import unittest
import urllib.parse
from unittest import mock

from base import (ServerTestCase, mod, OWNER, STRANGER, MEMBER,
                  session_cookie, fake_urlopen_json, parse_set_cookie)

REMOTE = {"X-Real-IP": "203.0.113.9"}          # outside every TRUSTED CIDR
LAN = {"X-Real-IP": "10.0.0.5"}                # inside TRUSTED


def payload(user=OWNER, adm=True, mbr=True, exp=None):
    return {"sub": str(user["id"]), "name": user["username"], "email": user["email"],
            "adm": adm, "mbr": mbr, "exp": exp or int(time.time()) + 3600}


class VerifyTests(ServerTestCase):
    def test_healthz(self):
        status, _, body = self.request("/healthz")
        self.assertEqual((status, body), (200, b"ok"))

    def test_no_cookie_denied(self):
        status, _, _ = self.request("/verify", REMOTE)
        self.assertEqual(status, 401)

    def test_trusted_ip_bypasses_auth(self):
        status, _, _ = self.request("/verify", LAN)
        self.assertEqual(status, 200)

    def test_trusted_ip_via_x_forwarded_for(self):
        status, _, _ = self.request("/verify", {"X-Forwarded-For": "192.168.1.7, 203.0.113.1"})
        self.assertEqual(status, 200)

    def test_x_real_ip_wins_over_x_forwarded_for(self):
        status, _, _ = self.request("/verify", {"X-Real-IP": "203.0.113.9",
                                                "X-Forwarded-For": "10.0.0.1"})
        self.assertEqual(status, 401)

    def test_socket_address_used_without_proxy_headers(self):
        # 127.0.0.1 is not in TRUSTED, so a direct, header-less request is denied…
        status, _, _ = self.request("/verify")
        self.assertEqual(status, 401)
        # …unless loopback is trusted.
        with mock.patch.object(mod, "TRUSTED", [mod.ipaddress.ip_network("127.0.0.0/8")]):
            status, _, _ = self.request("/verify")
            self.assertEqual(status, 200)

    def test_valid_owner_cookie_allowed(self):
        status, headers, _ = self.request("/verify", {**REMOTE, "Cookie": session_cookie(payload())})
        self.assertEqual(status, 200)
        self.assertEqual(self.header(headers, "X-Auth-User"), "owner")
        self.assertEqual(self.header(headers, "X-Auth-Admin"), "1")

    def test_owner_cookie_among_other_cookies(self):
        cookie = "theme=dark; " + session_cookie(payload()) + "; other=1"
        status, _, _ = self.request("/verify", {**REMOTE, "Cookie": cookie})
        self.assertEqual(status, 200)

    def test_expired_cookie_denied(self):
        cookie = session_cookie(payload(exp=int(time.time()) - 10))
        status, _, _ = self.request("/verify", {**REMOTE, "Cookie": cookie})
        self.assertEqual(status, 401)

    def test_forged_cookie_denied(self):
        cookie = session_cookie(payload(), secret="attacker")
        status, _, _ = self.request("/verify", {**REMOTE, "Cookie": cookie})
        self.assertEqual(status, 401)

    def test_malformed_cookie_denied(self):
        for bad in ("garbage", "a.b", ""):
            status, _, _ = self.request("/verify", {**REMOTE, "Cookie": f"{mod.COOKIE_NAME}={bad}"})
            self.assertEqual(status, 401, bad)

    def test_cookie_under_other_name_ignored(self):
        cookie = "othername=" + mod.sign(payload())
        status, _, _ = self.request("/verify", {**REMOTE, "Cookie": cookie})
        self.assertEqual(status, 401)

    def test_stranger_cookie_denied_on_owner_only_host(self):
        cookie = session_cookie(payload(STRANGER, adm=False, mbr=False))
        status, _, _ = self.request("/verify", {**REMOTE, "Cookie": cookie, "X-Original-Host": "sonarr.example.com"})
        self.assertEqual(status, 401)

    def test_member_cookie_allowed_only_on_member_host(self):
        cookie = session_cookie(payload(MEMBER, adm=False, mbr=True))
        status, _, _ = self.request("/verify", {**REMOTE, "Cookie": cookie, "X-Original-Host": "sonarr.example.com"})
        self.assertEqual(status, 401)
        status, headers, _ = self.request("/verify", {**REMOTE, "Cookie": cookie, "X-Original-Host": "Members.Example.com"})
        self.assertEqual(status, 200)
        self.assertEqual(self.header(headers, "X-Auth-User"), "member")
        self.assertEqual(self.header(headers, "X-Auth-Admin"), "0")

    def test_owner_cookie_allowed_on_member_host(self):
        cookie = session_cookie(payload())
        status, _, _ = self.request("/verify", {**REMOTE, "Cookie": cookie, "X-Original-Host": "members.example.com"})
        self.assertEqual(status, 200)

    def test_owner_promoted_from_allow_list_even_if_cookie_says_not_admin(self):
        # adm flag is re-derived from the current allow-list at verify time.
        cookie = session_cookie(payload(OWNER, adm=False, mbr=False))
        status, headers, _ = self.request("/verify", {**REMOTE, "Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertEqual(self.header(headers, "X-Auth-Admin"), "1")

    def test_verify_does_not_hit_network(self):
        # setUp installs an urlopen that raises; a network call would surface as a 500/exception.
        status, _, _ = self.request("/verify", {**REMOTE, "Cookie": session_cookie(payload())})
        self.assertEqual(status, 200)


class LoginTests(ServerTestCase):
    def test_login_redirects_to_plex_with_return_url(self):
        with mock.patch.object(mod, "plex_pin", return_value=(1234, "ABCD")) as pin:
            status, headers, _ = self.request("/login?rd=" + urllib.parse.quote("https://sonarr.example.com/x", safe=""), REMOTE)
        self.assertEqual(status, 302)
        pin.assert_called_once()
        loc = self.header(headers, "Location")
        self.assertTrue(loc.startswith("https://app.plex.tv/auth#?"), loc)
        q = urllib.parse.parse_qs(loc.split("#?", 1)[1])
        self.assertEqual(q["code"], ["ABCD"])
        self.assertEqual(q["clientID"], [mod.CLIENT_ID])
        fwd = urllib.parse.urlparse(q["forwardUrl"][0])
        self.assertEqual((fwd.scheme, fwd.netloc, fwd.path), ("https", "auth.example.com", "/callback"))
        fq = urllib.parse.parse_qs(fwd.query)
        self.assertEqual(fq["pin"], ["1234"])
        self.assertEqual(fq["rd"], ["https://sonarr.example.com/x"])
        self.assertIsNone(self.header(headers, "Set-Cookie"), "login must not set a session")

    def test_login_without_rd(self):
        with mock.patch.object(mod, "plex_pin", return_value=(1, "C")):
            status, headers, _ = self.request("/login", REMOTE)
        self.assertEqual(status, 302)
        self.assertNotIn("rd=", self.header(headers, "Location"))

    def test_plex_unreachable_is_502(self):
        with mock.patch.object(mod, "plex_pin", side_effect=OSError("boom")):
            status, headers, _ = self.request("/login", REMOTE)
        self.assertEqual(status, 502)
        self.assertIsNone(self.header(headers, "Set-Cookie"))


class CallbackTests(ServerTestCase):
    def callback(self, user, token="tok", rd="https://sonarr.example.com/", poll=None):
        poll = poll if poll is not None else mock.Mock(return_value=token)
        path = "/callback?pin=77" + (("&rd=" + urllib.parse.quote(rd, safe="")) if rd else "")
        with mock.patch.object(mod, "plex_poll", poll), \
             mock.patch.object(mod, "plex_user", return_value=user) as pu, \
             mock.patch.object(mod.time, "sleep", lambda *_: None):
            status, headers, body = self.request(path, REMOTE)
        self.pu = pu
        return status, headers, body

    def test_owner_gets_cookie_and_redirect(self):
        status, headers, _ = self.callback(OWNER)
        self.assertEqual(status, 302)
        self.assertEqual(self.header(headers, "Location"), "https://sonarr.example.com/")
        self.pu.assert_called_once_with("tok")
        sc = self.header(headers, "Set-Cookie")
        self.assertIsNotNone(sc)
        name, value, attrs = parse_set_cookie(sc)
        self.assertEqual(name, mod.COOKIE_NAME)
        self.assertEqual(attrs.get("path"), "/")
        self.assertEqual(attrs.get("domain"), ".example.com")
        self.assertEqual(attrs.get("max-age"), str(30 * 86400))
        self.assertIn("httponly", attrs)
        self.assertIn("secure", attrs)
        self.assertEqual(attrs.get("samesite"), "Lax")
        # The cookie is a valid, signed session describing the owner.
        data = mod.verify_cookie(value)
        self.assertIsNotNone(data)
        self.assertEqual(data["sub"], "1382106")
        self.assertEqual(data["name"], "owner")
        self.assertEqual(data["email"], "owner@example.com")
        self.assertTrue(data["adm"])
        self.assertTrue(data["mbr"])
        self.assertAlmostEqual(data["exp"], time.time() + 30 * 86400, delta=30)
        # …and it is accepted by /verify on a subsequent request.
        status, vh, _ = self.request("/verify", {**REMOTE, "Cookie": f"{name}={value}"})
        self.assertEqual(status, 200)
        self.assertEqual(self.header(vh, "X-Auth-User"), "owner")

    def test_email_is_lowercased_in_cookie(self):
        _, headers, _ = self.callback({**OWNER, "email": "Owner@Example.com"})
        _, value, _ = parse_set_cookie(self.header(headers, "Set-Cookie"))
        self.assertEqual(mod.verify_cookie(value)["email"], "owner@example.com")

    def test_stranger_gets_403_and_no_cookie(self):
        status, headers, body = self.callback(STRANGER)
        self.assertEqual(status, 403)
        self.assertIn(b"stranger", body)
        self.assertIsNone(self.header(headers, "Set-Cookie"))

    def test_member_gets_non_admin_cookie(self):
        users = {"response": {"data": [{"user_id": 555, "email": "member@example.net"}]}}
        with mock.patch.object(mod, "TAUTULLI_URL", "http://tautulli:8181"), \
             mock.patch.object(mod, "TAUTULLI_KEY", "k"), \
             mock.patch.object(mod.urllib.request, "urlopen", fake_urlopen_json(users)):
            status, headers, _ = self.callback(MEMBER)
        self.assertEqual(status, 302)
        _, value, _ = parse_set_cookie(self.header(headers, "Set-Cookie"))
        data = mod.verify_cookie(value)
        self.assertFalse(data["adm"])
        self.assertTrue(data["mbr"])

    def test_poll_timeout_is_408_without_cookie(self):
        status, headers, _ = self.callback(OWNER, poll=mock.Mock(return_value=None))
        self.assertEqual(status, 408)
        self.assertIsNone(self.header(headers, "Set-Cookie"))
        self.pu.assert_not_called()

    def test_plex_error_is_502_without_cookie(self):
        status, headers, _ = self.callback(OWNER, poll=mock.Mock(side_effect=OSError("nope")))
        self.assertEqual(status, 502)
        self.assertIsNone(self.header(headers, "Set-Cookie"))

    def test_open_redirect_guard_on_callback(self):
        status, headers, _ = self.callback(OWNER, rd="https://evil.example.net/")
        self.assertEqual(status, 302)
        self.assertEqual(self.header(headers, "Location"), "https://auth.example.com/")

    def test_no_allow_list_accepts_any_user(self):
        with mock.patch.object(mod, "ALLOWED_IDS", set()), mock.patch.object(mod, "ALLOWED_EMAILS", set()):
            status, headers, _ = self.callback(STRANGER)
        self.assertEqual(status, 302)
        self.assertIsNotNone(self.header(headers, "Set-Cookie"))


class LogoutAndLandingTests(ServerTestCase):
    def test_logout_clears_cookie(self):
        status, headers, _ = self.request("/logout", {**REMOTE, "Cookie": session_cookie(payload())})
        self.assertEqual(status, 302)
        name, value, attrs = parse_set_cookie(self.header(headers, "Set-Cookie"))
        self.assertEqual((name, value), (mod.COOKIE_NAME, ""))
        self.assertEqual(attrs.get("max-age"), "0")
        self.assertEqual(attrs.get("path"), "/")
        self.assertEqual(attrs.get("domain"), ".example.com")

    def test_landing_signed_out(self):
        status, headers, body = self.request("/?rd=" + urllib.parse.quote("https://a.example.com/?x=1&y=\"", safe=""), REMOTE)
        self.assertEqual(status, 200)
        self.assertIn(b"Sign in with Plex", body)
        self.assertIn(b'href="/login?rd=https%3A%2F%2Fa.example.com%2F%3Fx%3D1%26y%3D%22"', body)
        self.assertIsNone(self.header(headers, "Set-Cookie"))

    def test_landing_signed_in(self):
        status, _, body = self.request("/", {**REMOTE, "Cookie": session_cookie(payload())})
        self.assertEqual(status, 200)
        self.assertIn(b"Signed in", body)
        self.assertIn(b"<b>owner</b>", body)

    def test_landing_escapes_name(self):
        cookie = session_cookie(payload({**OWNER, "username": "<img src=x>"}))
        _, _, body = self.request("/", {**REMOTE, "Cookie": cookie})
        self.assertNotIn(b"<img", body)
        self.assertIn(b"&lt;img", body)

    def test_head_has_no_body(self):
        status, headers, body = self.request("/", REMOTE, method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertNotEqual(self.header(headers, "Content-Length"), "0")


if __name__ == "__main__":
    unittest.main()
