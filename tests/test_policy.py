"""Pure policy helpers: allow-list, trusted networks, redirect guard, cookies."""
import unittest
from unittest import mock

from base import mod, OWNER, STRANGER, MEMBER, fake_urlopen_json


class AllowListTests(unittest.TestCase):
    def test_owner_by_id(self):
        self.assertTrue(mod.allowed(OWNER))
        self.assertTrue(mod.allowed({"id": "42"}))

    def test_owner_by_email_is_case_insensitive(self):
        self.assertTrue(mod.allowed({"id": 7, "email": "OWNER@example.COM"}))

    def test_stranger_denied(self):
        self.assertFalse(mod.allowed(STRANGER))
        self.assertFalse(mod.allowed({}))
        self.assertFalse(mod.allowed({"id": None, "email": ""}))

    def test_empty_email_never_matches(self):
        with mock.patch.object(mod, "ALLOWED_EMAILS", {""}):
            self.assertFalse(mod.allowed({"id": 7, "email": ""}))

    def test_no_allow_list_accepts_any_plex_user(self):
        with mock.patch.object(mod, "ALLOWED_IDS", set()), \
             mock.patch.object(mod, "ALLOWED_EMAILS", set()):
            self.assertTrue(mod.allowed(STRANGER))


class MembershipTests(unittest.TestCase):
    def test_owner_is_member_without_tautulli(self):
        self.assertTrue(mod.is_member(OWNER))

    def test_stranger_not_member_without_tautulli(self):
        self.assertFalse(mod.is_member(STRANGER))

    def test_member_matched_against_tautulli(self):
        users = {"response": {"data": [{"user_id": 555, "email": "Member@example.net"}]}}
        with mock.patch.object(mod, "TAUTULLI_URL", "http://tautulli:8181"), \
             mock.patch.object(mod, "TAUTULLI_KEY", "k"), \
             mock.patch.object(mod.urllib.request, "urlopen", fake_urlopen_json(users)):
            self.assertTrue(mod.is_member(MEMBER))
            self.assertTrue(mod.is_member({"id": 1, "email": "member@example.net"}))
            self.assertFalse(mod.is_member(STRANGER))

    def test_tautulli_failure_denies(self):
        with mock.patch.object(mod, "TAUTULLI_URL", "http://tautulli:8181"), \
             mock.patch.object(mod, "TAUTULLI_KEY", "k"), \
             mock.patch.object(mod.urllib.request, "urlopen", side_effect=OSError("down")):
            self.assertFalse(mod.is_member(MEMBER))


class TrustedNetworkTests(unittest.TestCase):
    def test_trusted_cidrs(self):
        self.assertTrue(mod.trusted("10.1.2.3"))
        self.assertTrue(mod.trusted("192.168.1.20"))

    def test_untrusted_and_garbage(self):
        self.assertFalse(mod.trusted("192.168.2.20"))
        self.assertFalse(mod.trusted("8.8.8.8"))
        self.assertFalse(mod.trusted(""))
        self.assertFalse(mod.trusted("not-an-ip"))


class SafeRedirectTests(unittest.TestCase):
    def test_same_suffix_allowed(self):
        self.assertEqual(mod.safe_rd("https://sonarr.example.com/x?y=1"),
                         "https://sonarr.example.com/x?y=1")
        self.assertEqual(mod.safe_rd("https://example.com/"), "https://example.com/")

    def test_foreign_host_falls_back(self):
        self.assertEqual(mod.safe_rd("https://evil.example.net/"), "https://auth.example.com/")
        self.assertEqual(mod.safe_rd("https://notexample.com/"), "https://auth.example.com/")

    def test_bad_scheme_or_empty_falls_back(self):
        self.assertEqual(mod.safe_rd("javascript:alert(1)"), "https://auth.example.com/")
        self.assertEqual(mod.safe_rd("//evil.example.net/"), "https://auth.example.com/")
        self.assertEqual(mod.safe_rd(""), "https://auth.example.com/")

    def test_no_suffix_allows_any_http_host(self):
        with mock.patch.object(mod, "REDIRECT_SUFFIX", ""):
            self.assertEqual(mod.safe_rd("https://anything.test/"), "https://anything.test/")
            self.assertEqual(mod.safe_rd("ftp://anything.test/"), "https://auth.example.com/")


class CookieHeaderParsingTests(unittest.TestCase):
    def parse(self, header):
        h = mod.H.__new__(mod.H)
        h.headers = {"Cookie": header}
        return h._cookies()

    def test_multiple_cookies_and_spacing(self):
        self.assertEqual(self.parse("a=1; plexauth=tok.sig;b=2 ; c=3"),
                         {"a": "1", "plexauth": "tok.sig", "b": "2", "c": "3"})

    def test_value_may_contain_equals(self):
        self.assertEqual(self.parse("plexauth=abc=def==")["plexauth"], "abc=def==")

    def test_missing_or_garbage(self):
        self.assertEqual(self.parse(""), {})
        self.assertEqual(self.parse("novalue; ;"), {})
        h = mod.H.__new__(mod.H)
        h.headers = {}
        self.assertEqual(h._cookies(), {})


if __name__ == "__main__":
    unittest.main()
