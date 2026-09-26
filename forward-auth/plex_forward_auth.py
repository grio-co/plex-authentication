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
  COOKIE_SECURE COOKIE_SAMESITE TRUST_PROXY_HEADERS
  LOGIN_RATE_LIMIT LOGIN_RATE_WINDOW
"""
import os, json, time, hmac, hashlib, base64, secrets, ipaddress, math, threading
import urllib.request, urllib.parse, html
from collections import deque
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn



def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name, "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


def _env_samesite(name: str, default: str = "Lax") -> str:
    v = os.environ.get(name, "").strip().lower()
    if not v:
        return default
    if v in ("lax", "strict", "none"):
        return v.capitalize()
    print(f"WARNING: {name}={os.environ.get(name)!r} is not Lax/Strict/None — using {default}.", flush=True)
    return default


APP_SECRET      = os.environ.get("APP_SECRET", "")
COOKIE_DOMAIN   = os.environ.get("COOKIE_DOMAIN", "")
COOKIE_NAME     = os.environ.get("COOKIE_NAME", "plexauth")
# Cookie attributes. HttpOnly is always set. Secure is on by default — only turn it
# off if you really serve the gateway over plain http (e.g. local testing).
COOKIE_SECURE   = _env_bool("COOKIE_SECURE", True)
COOKIE_SAMESITE = _env_samesite("COOKIE_SAMESITE", "Lax")
# The reverse proxy sets X-Real-IP / X-Forwarded-For to the true client. Set to 0
# if the gateway is exposed directly (then the socket peer address is used).
TRUST_PROXY_HEADERS = _env_bool("TRUST_PROXY_HEADERS", True)
# Sign-in rate limit per client IP (sliding window over /login + /callback).
# LOGIN_RATE_LIMIT=0 disables it.
LOGIN_RATE_LIMIT  = int(os.environ.get("LOGIN_RATE_LIMIT", "10"))
LOGIN_RATE_WINDOW = int(os.environ.get("LOGIN_RATE_WINDOW", "60"))
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
# Per-host policy: ALLOWED_PLEX_IDS/EMAILS = owner/admin (allowed everywhere). Hosts
# listed in MEMBER_HOSTS additionally allow ANY Plex server member (checked against
# Tautulli at sign-in and cached in the cookie). Everything else stays owner-only.
TAUTULLI_URL    = os.environ.get("TAUTULLI_URL", "").rstrip("/")
TAUTULLI_KEY    = os.environ.get("TAUTULLI_KEY", "")
MEMBER_HOSTS    = {h.strip().lower() for h in os.environ.get("MEMBER_HOSTS", "").split(",") if h.strip()}

if not APP_SECRET:
    APP_SECRET = secrets.token_urlsafe(32)
    print("WARNING: APP_SECRET not set — generated an ephemeral one; sessions will "
          "not survive a restart. Set APP_SECRET in production.", flush=True)
SECRET = APP_SECRET.encode()
if COOKIE_SAMESITE == "None" and not COOKIE_SECURE:
    print("WARNING: SameSite=None cookies are rejected by browsers unless Secure — "
          "set COOKIE_SECURE=1.", flush=True)


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


def cookie_attrs() -> str:
    """Attributes appended to every Set-Cookie the gateway emits (set and clear)."""
    attrs = "; Path=/; HttpOnly"
    if COOKIE_SECURE:
        attrs += "; Secure"
    attrs += f"; SameSite={COOKIE_SAMESITE}"
    if COOKIE_DOMAIN:
        attrs += f"; Domain={COOKIE_DOMAIN}"
    return attrs


class RateLimiter:
    """Sliding-window limiter: at most `limit` hits per `window` seconds per key.

    In-memory and per-process: it resets on restart and is not shared between
    replicas. Denied attempts are not counted, so a client that keeps retrying
    is let back in as soon as its oldest counted attempt leaves the window.
    """

    def __init__(self, limit: int, window: float, clock=time.monotonic):
        self.limit, self.window, self.clock = int(limit), float(window), clock
        self._hits = {}          # key -> deque[float] of accepted attempt times
        self._lock = threading.Lock()
        self._calls = 0

    def check(self, key: str) -> int:
        """Record an attempt for `key`. Returns 0 if allowed, else the number of
        whole seconds until the next attempt would be allowed (>= 1)."""
        if self.limit <= 0:
            return 0
        now = self.clock()
        cutoff = now - self.window
        with self._lock:
            self._calls += 1
            if self._calls % 1024 == 0:
                self._sweep(cutoff)
            q = self._hits.get(key)
            if q is None:
                q = self._hits[key] = deque()
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.limit:
                return max(1, math.ceil(q[0] + self.window - now))
            q.append(now)
            return 0

    def _sweep(self, cutoff: float):
        for k in [k for k, q in self._hits.items() if not q or q[-1] <= cutoff]:
            del self._hits[k]


LIMITER = RateLimiter(LOGIN_RATE_LIMIT, LOGIN_RATE_WINDOW)


def allowed(user: dict) -> bool:
    uid = str(user.get("id") or "")
    email = (user.get("email") or "").lower()
    if ALLOWED_IDS or ALLOWED_EMAILS:
        return uid in ALLOWED_IDS or (bool(email) and email in ALLOWED_EMAILS)
    return True  # no allow-list => any authenticated Plex user (set an allow-list!)


def is_member(user: dict) -> bool:
    """Owner/admin OR a user of THIS Plex server (matched against Tautulli)."""
    if allowed(user):
        return True
    if not (TAUTULLI_URL and TAUTULLI_KEY):
        return False
    try:
        u = f"{TAUTULLI_URL}/api/v2?apikey={TAUTULLI_KEY}&cmd=get_users"
        users = json.load(urllib.request.urlopen(u, timeout=8))["response"]["data"]
    except Exception:
        return False
    uid, email = str(user.get("id")), (user.get("email") or "").lower()
    return any(str(m.get("user_id")) == uid or (email and (m.get("email") or "").lower() == email)
               for m in users)


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
        if TRUST_PROXY_HEADERS:
            fwd = (self.headers.get("X-Real-IP")
                   or (self.headers.get("X-Forwarded-For") or "").split(",")[0]).strip()
            if fwd:
                return fwd
        return self.client_address[0]

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
            if s:
                sub = str(s.get("sub") or "")
                adm = bool(s.get("adm")) or sub in ALLOWED_IDS or (
                    bool(ALLOWED_EMAILS) and (s.get("email") or "").lower() in ALLOWED_EMAILS)
                mbr = bool(s.get("mbr")) or adm
                host = (self.headers.get("X-Original-Host") or self.headers.get("Host") or "").lower()
                ok = mbr if host in MEMBER_HOSTS else adm
                if ok:
                    return self._send(200, "", "text/plain",
                                      headers=[("X-Auth-User", str(s.get("name") or sub or "")),
                                               ("X-Auth-Admin", "1" if adm else "0")])
            return self._send(401, "", "text/plain")

        # ---- sign-in flow: rate limited per client IP (both legs hit plex.tv) ----
        if u.path in ("/login", "/callback"):
            wait = LIMITER.check(self._client_ip())
            if wait:
                return self._send(429, "Too many sign-in attempts — try again later.", "text/plain",
                                  headers=[("Retry-After", str(wait))])

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
                adm = allowed(user)
                mbr = adm or is_member(user)
                if not mbr:
                    name = html.escape(user.get("username") or user.get("title") or "that account")
                    return self._send(403, f"Sorry, {name} is not a member of this server.", "text/plain")
                payload = {"sub": str(user.get("id")), "name": user.get("username") or user.get("title"),
                           "email": (user.get("email") or "").lower(), "adm": adm, "mbr": mbr,
                           "exp": int(time.time() + SESSION_DAYS * 86400)}
                cookie = f"{COOKIE_NAME}={sign(payload)}; Max-Age={SESSION_DAYS*86400}" + cookie_attrs()
                return self._send(302, "", headers=[("Location", safe_rd(rd)), ("Set-Cookie", cookie)])
            except Exception as e:
                return self._send(502, f"plex callback error: {e}", "text/plain")

        if u.path == "/logout":
            clear = f"{COOKIE_NAME}=; Max-Age=0" + cookie_attrs()
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
    print(f"cookie: Secure={'on' if COOKIE_SECURE else 'OFF'} SameSite={COOKIE_SAMESITE}  "
          f"proxy-headers={'trusted' if TRUST_PROXY_HEADERS else 'ignored'}  "
          f"login-rate-limit={LOGIN_RATE_LIMIT}/{LOGIN_RATE_WINDOW}s"
          + ("" if LOGIN_RATE_LIMIT > 0 else " (disabled)"), flush=True)
    Server(("0.0.0.0", PORT), H).serve_forever()
