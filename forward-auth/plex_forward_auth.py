#!/usr/bin/env python3
"""
plex-forward-auth — one Plex login for every service behind your reverse proxy.

A tiny, dependency-free (Python stdlib only) forward-auth / SSO gateway. Point any
reverse proxy's sub-request auth (nginx / Nginx Proxy Manager `auth_request`,
Caddy/Traefik `forward_auth`) at `/verify` and protect every app behind a single
"Sign in with Plex" — no more juggling a separate login per service.

Endpoints
  GET /verify    -> 200 if the caller is allowed, 401 otherwise. (auth_request target)
  GET /login     -> begin Plex PIN OAuth (carries ?rd= return destination)
  GET /callback  -> finish OAuth, set a signed SSO cookie on COOKIE_DOMAIN, 302 -> rd
  GET /logout    -> clear the cookie
  GET /          -> status / "Sign in with Plex" page
  GET /healthz   -> 200 ok

Who gets in
  * Clients inside a TRUSTED CIDR bypass auth entirely (your LAN / Tailscale) — this
    is also your lock-out safety net while rolling auth out.
  * Everyone else must sign in with Plex AND match the allow-list:
      ALLOWED_PLEX_IDS     comma list of Plex account ids   (e.g. "1382106")
      ALLOWED_PLEX_EMAILS  comma list of emails
    With neither set, ANY Plex account is accepted (NOT recommended — set an
    allow-list to mean "only me").
  The session cookie is HMAC-signed (APP_SECRET) and fully stateless, so the
  gateway can restart without logging anyone out, and several replicas share it.

Env (all optional except APP_SECRET in production):
  APP_SECRET COOKIE_DOMAIN COOKIE_NAME ALLOWED_PLEX_IDS ALLOWED_PLEX_EMAILS
  TRUSTED PUBLIC_URL SESSION_DAYS PORT CLIENT_ID PRODUCT REDIRECT_SUFFIX
"""
import os, json, time, hmac, hashlib, base64, secrets, ipaddress
import urllib.request, urllib.parse, html
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

APP_SECRET      = os.environ.get("APP_SECRET", "")
COOKIE_DOMAIN   = os.environ.get("COOKIE_DOMAIN", "")
COOKIE_NAME     = os.environ.get("COOKIE_NAME", "plexauth")
PORT            = int(os.environ.get("PORT", "8056"))
PUBLIC_URL      = os.environ.get("PUBLIC_URL", "https://auth.example.com").rstrip("/")
SESSION_DAYS    = int(os.environ.get("SESSION_DAYS", "30"))
REDIRECT_SUFFIX = os.environ.get("REDIRECT_SUFFIX", "")   # open-redirect guard, e.g. ".grio.co"
ALLOWED_IDS     = {x.strip() for x in os.environ.get("ALLOWED_PLEX_IDS", "").split(",") if x.strip()}
ALLOWED_EMAILS  = {x.strip().lower() for x in os.environ.get("ALLOWED_PLEX_EMAILS", "").split(",") if x.strip()}
TRUSTED         = [ipaddress.ip_network(n.strip()) for n in os.environ.get("TRUSTED", "").split(",") if n.strip()]
CLIENT_ID       = os.environ.get("CLIENT_ID", "plex-forward-auth")
PRODUCT         = os.environ.get("PRODUCT", "Plex Forward Auth")
PLEX_HDR        = {"X-Plex-Client-Identifier": CLIENT_ID, "X-Plex-Product": PRODUCT, "Accept": "application/json"}

if not APP_SECRET:
    APP_SECRET = secrets.token_urlsafe(32)
    print("WARNING: APP_SECRET not set — generated an ephemeral one; sessions will "
          "not survive a restart. Set APP_SECRET in production.", flush=True)
SECRET = APP_SECRET.encode()


# ---------- signed stateless cookie ----------
def _b64e(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def _b64d(b: bytes) -> bytes:
    return base64.urlsafe_b64decode(b + b"=" * (-len(b) % 4))


def sign(payload: dict) -> str:
    raw = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(hmac.new(SECRET, raw, hashlib.sha256).digest())
    return (raw + b"." + sig).decode()


def verify_cookie(tok: str):
    try:
        raw, sig = tok.encode().rsplit(b".", 1)
        good = _b64e(hmac.new(SECRET, raw, hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good):
            return None
        data = json.loads(_b64d(raw))
        return data if data.get("exp", 0) > time.time() else None
    except Exception:
        return None


def allowed(user: dict) -> bool:
    uid = str(user.get("id") or "")
    email = (user.get("email") or "").lower()
    if ALLOWED_IDS or ALLOWED_EMAILS:
        return uid in ALLOWED_IDS or (bool(email) and email in ALLOWED_EMAILS)
    return True  # no allow-list => any authenticated Plex user (set an allow-list!)


# ---------- Plex PIN OAuth ----------
def plex_pin():
    req = urllib.request.Request("https://plex.tv/api/v2/pins?strong=true", data=b"",
                                 headers=PLEX_HDR, method="POST")
    r = json.load(urllib.request.urlopen(req, timeout=10))
    return r["id"], r["code"]


def plex_auth_url(code, pin_id, rd):
    fwd = f"{PUBLIC_URL}/callback?pin={pin_id}"
    if rd:
        fwd += "&rd=" + urllib.parse.quote(rd, safe="")
    q = urllib.parse.urlencode({"clientID": CLIENT_ID, "code": code,
                                "context[device][product]": PRODUCT, "forwardUrl": fwd})
    return "https://app.plex.tv/auth#?" + q


def plex_poll(pin_id):
    req = urllib.request.Request(
        f"https://plex.tv/api/v2/pins/{pin_id}?X-Plex-Client-Identifier={CLIENT_ID}", headers=PLEX_HDR)
    return json.load(urllib.request.urlopen(req, timeout=10)).get("authToken")


def plex_user(token):
    req = urllib.request.Request("https://plex.tv/api/v2/user",
                                 headers={**PLEX_HDR, "X-Plex-Token": token})
    return json.load(urllib.request.urlopen(req, timeout=10))


# ---------- helpers ----------
def trusted(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in TRUSTED)
    except Exception:
        return False


def safe_rd(rd: str) -> str:
    """Only allow redirects back to our own domain(s); else fall back to PUBLIC_URL."""
    if not rd:
        return PUBLIC_URL + "/"
    try:
        u = urllib.parse.urlparse(rd)
        if u.scheme in ("http", "https") and (not REDIRECT_SUFFIX or u.hostname and
                                              (u.hostname == REDIRECT_SUFFIX.lstrip(".") or
                                               u.hostname.endswith(REDIRECT_SUFFIX))):
            return rd
    except Exception:
        pass
    return PUBLIC_URL + "/"


CSS = ("*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e2e8f0;"
       "font:14px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}"
       ".wrap{max-width:460px;margin:16vh auto;text-align:center;padding:0 22px}"
       "h2{margin:.2em 0}.wrap p{color:#94a3b8}"
       "a.btn{display:inline-block;background:#e5a00d;color:#1b1b1b;font-weight:700;"
       "text-decoration:none;padding:11px 20px;border-radius:9px;margin-top:8px}"
       ".m{color:#64748b;font-size:12px;margin-top:18px}")


def login_page(rd):
    href = "/login" + (("?rd=" + urllib.parse.quote(rd, safe="")) if rd else "")
    return ("<!doctype html><meta charset=utf-8><title>Sign in</title><style>%s</style>"
            "<div class=wrap><h2>Sign in</h2>"
            "<p>This area is protected. Sign in with your Plex account to continue.</p>"
            "<p><a class=btn href=\"%s\" target=_top>Sign in with Plex</a></p>"
            "<div class=m>Single sign-on — one login covers every protected service.</div></div>"
            % (CSS, html.escape(href)))


# ---------- HTTP ----------
class H(BaseHTTPRequestHandler):
    server_version = "plex-forward-auth"

    def _cookies(self):
        c = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                c[k] = v
        return c

    def _client_ip(self):
        # The reverse proxy sets X-Real-IP / X-Forwarded-For to the true client.
        return ((self.headers.get("X-Real-IP")
                 or (self.headers.get("X-Forwarded-For") or "").split(",")[0]).strip()
                or self.client_address[0])

    def _session(self):
        return verify_cookie(self._cookies().get(COOKIE_NAME, ""))

    def _send(self, code, body="", ctype="text/html; charset=utf-8", headers=None):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        rd = (qs.get("rd") or [""])[0]

        if u.path == "/healthz":
            return self._send(200, "ok", "text/plain")

        # ---- the auth_request target: cheap, no network ----
        if u.path == "/verify":
            if trusted(self._client_ip()):
                return self._send(200, "", "text/plain")
            s = self._session()
            if s and allowed({"id": s.get("sub"), "email": s.get("email")}):
                return self._send(200, "", "text/plain",
                                  headers=[("X-Auth-User", str(s.get("name") or s.get("sub") or ""))])
            return self._send(401, "", "text/plain")

        if u.path == "/login":
            try:
                pid, code = plex_pin()
                return self._send(302, "", headers=[("Location", plex_auth_url(code, pid, rd))])
            except Exception as e:
                return self._send(502, f"plex login error: {e}", "text/plain")

        if u.path == "/callback":
            pid = (qs.get("pin") or [""])[0]
            try:
                token = None
                for _ in range(10):
                    token = plex_poll(pid)
                    if token:
                        break
                    time.sleep(1)
                if not token:
                    return self._send(408, "Plex authorization timed out — try again.", "text/plain")
                user = plex_user(token)
                if not allowed(user):
                    name = html.escape(user.get("username") or user.get("title") or "that account")
                    return self._send(403, f"Sorry, {name} is not permitted to access this server.",
                                      "text/plain")
                payload = {"sub": str(user.get("id")), "name": user.get("username") or user.get("title"),
                           "email": (user.get("email") or "").lower(),
                           "exp": int(time.time() + SESSION_DAYS * 86400)}
                cookie = (f"{COOKIE_NAME}={sign(payload)}; Path=/; HttpOnly; Secure; SameSite=Lax; "
                          f"Max-Age={SESSION_DAYS*86400}" + (f"; Domain={COOKIE_DOMAIN}" if COOKIE_DOMAIN else ""))
                return self._send(302, "", headers=[("Location", safe_rd(rd)), ("Set-Cookie", cookie)])
            except Exception as e:
                return self._send(502, f"plex callback error: {e}", "text/plain")

        if u.path == "/logout":
            clear = (f"{COOKIE_NAME}=; Path=/; Max-Age=0"
                     + (f"; Domain={COOKIE_DOMAIN}" if COOKIE_DOMAIN else ""))
            return self._send(302, "", headers=[("Location", safe_rd(rd)), ("Set-Cookie", clear)])

        # status / sign-in landing
        s = self._session()
        if s:
            who = html.escape(str(s.get("name") or s.get("sub")))
            return self._send(200, "<!doctype html><meta charset=utf-8><style>%s</style>"
                              "<div class=wrap><h2>Signed in</h2><p>You are signed in as <b>%s</b>.</p>"
                              "<div class=m><a href=/logout style=color:#64748b>log out</a></div></div>"
                              % (CSS, who))
        return self._send(200, login_page(rd))

    def log_message(self, *a):
        pass


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    mode = ("allow-list: ids=%s emails=%s" % (sorted(ALLOWED_IDS), sorted(ALLOWED_EMAILS))
            if (ALLOWED_IDS or ALLOWED_EMAILS) else "OPEN (any Plex user — set an allow-list!)")
    print(f"plex-forward-auth on :{PORT}  domain={COOKIE_DOMAIN or '(host-only)'}  "
          f"trusted={[str(n) for n in TRUSTED]}  {mode}", flush=True)
    Server(("0.0.0.0", PORT), H).serve_forever()
