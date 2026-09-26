"""Signed session token: sign / verify_cookie round-trips and rejections."""
import json
import time
import unittest
from unittest import mock

from base import mod


class SignAndVerifyTests(unittest.TestCase):
    def payload(self, **over):
        p = {"sub": "1382106", "name": "owner", "email": "owner@example.com",
             "adm": True, "mbr": True, "exp": int(time.time()) + 3600}
        p.update(over)
        return p

    def test_round_trip(self):
        p = self.payload()
        tok = mod.sign(p)
        self.assertEqual(tok.count("."), 1)
        self.assertNotIn("=", tok, "token must be cookie-safe (no base64 padding)")
        self.assertEqual(mod.verify_cookie(tok), p)

    def test_signature_is_deterministic(self):
        p = self.payload()
        self.assertEqual(mod.sign(p), mod.sign(p))

    def test_expired_token_rejected(self):
        tok = mod.sign(self.payload(exp=int(time.time()) - 1))
        self.assertIsNone(mod.verify_cookie(tok))

    def test_missing_exp_rejected(self):
        p = self.payload()
        del p["exp"]
        self.assertIsNone(mod.verify_cookie(mod.sign(p)))

    def test_wrong_secret_rejected(self):
        with mock.patch.object(mod, "SECRET", b"someone-elses-secret"):
            forged = mod.sign(self.payload())
        self.assertIsNone(mod.verify_cookie(forged))

    def test_tampered_payload_rejected(self):
        tok = mod.sign(self.payload(adm=False, sub="999"))
        raw, sig = tok.split(".")
        evil = mod._b64e(json.dumps(
            {**self.payload(adm=True, sub="999")}, separators=(",", ":")).encode()).decode()
        self.assertIsNone(mod.verify_cookie(evil + "." + sig))

    def test_tampered_signature_rejected(self):
        tok = mod.sign(self.payload())
        raw, sig = tok.split(".")
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        self.assertIsNone(mod.verify_cookie(raw + "." + flipped))
        self.assertIsNone(mod.verify_cookie(raw + "." + sig[:-2]))

    def test_malformed_tokens_rejected(self):
        for bad in ("", "no-dot-here", ".", "a.b", "!!!.???", "   ",
                    mod._b64e(b"not json").decode() + ".sig",
                    mod._b64e(b"[1,2,3]").decode() + "." + "x" * 43):
            with self.subTest(token=bad):
                self.assertIsNone(mod.verify_cookie(bad))

    def test_non_object_payload_rejected(self):
        raw = mod._b64e(b"[1,2,3]")
        sig = mod._b64e(mod.hmac.new(mod.SECRET, raw, mod.hashlib.sha256).digest())
        self.assertIsNone(mod.verify_cookie((raw + b"." + sig).decode()))


if __name__ == "__main__":
    unittest.main()
