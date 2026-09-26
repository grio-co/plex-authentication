# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Stdlib-only `unittest` suite under `tests/` (`python -m unittest discover -s tests`)
  covering token signing/verification, allow/deny policy, cookie handling, the
  `/verify` / `/login` / `/callback` / `/logout` routes, cookie flags and the
  rate limiter. All plex.tv / Tautulli calls are stubbed; nothing hits the network.
- GitHub Actions workflow (`.github/workflows/ci.yml`) running the suite on
  Python 3.11 and 3.12.
- `COOKIE_SECURE` (default `1`) and `COOKIE_SAMESITE` (default `Lax`) to tune the
  session cookie's `Secure` / `SameSite` attributes. `HttpOnly` is always set.
- Per-client-IP sliding-window rate limit on the sign-in flow (`/login` and
  `/callback`): `LOGIN_RATE_LIMIT` attempts per `LOGIN_RATE_WINDOW` seconds
  (default 10 / 60). Over the limit the gateway responds `429 Too Many Requests`
  with a `Retry-After` header and does not contact plex.tv.
- `TRUST_PROXY_HEADERS` (default `1`) to control whether the client IP is read
  from `X-Real-IP` / `X-Forwarded-For` or taken from the socket peer address.
- This changelog.

### Changed

- The `/logout` clearing cookie now carries the same `HttpOnly` / `Secure` /
  `SameSite` / `Domain` attributes as the session cookie it removes.
- Startup banner reports the cookie flags, proxy-header trust and rate-limit
  settings in effect.

### Security model (as of this release)

This section describes what the gateway does today so that later entries can
describe what changed.

**What authenticates a user.** A request to `/verify` (the reverse proxy's
`auth_request` / `forward_auth` sub-request) is allowed when either

1. the client IP is inside a `TRUSTED` CIDR (LAN / Tailscale / docker bridge):
   no cookie is needed and no sign-in ever happens for these clients; or
2. the request carries a valid session cookie **and** the user it names passes
   the per-host policy: owners/admins (`ALLOWED_PLEX_IDS` / `ALLOWED_PLEX_EMAILS`)
   are allowed on every host; on hosts listed in `MEMBER_HOSTS` any Plex server
   member (verified against Tautulli at sign-in) is also allowed. With no
   allow-list configured, any Plex account that completes sign-in is treated as
   an owner.

Sign-in is Plex PIN OAuth: `/login` creates a PIN at plex.tv and redirects the
browser to `app.plex.tv`; `/callback` polls the PIN for an auth token, fetches
the Plex user with it, applies the allow-list / membership check and, on
success, sets the session cookie and redirects to the `rd` destination. The
Plex token itself is never stored. Redirect targets are restricted to hosts
ending in `REDIRECT_SUFFIX` (falling back to `PUBLIC_URL`).

**How sessions are represented.** The session is a single stateless cookie
(`COOKIE_NAME`, default `plexauth`) on `COOKIE_DOMAIN`. Its value is
`base64url(JSON payload) + "." + base64url(HMAC-SHA256(APP_SECRET, payload))`.
The payload is `{"sub": plex account id, "name": username, "email": lowercased
email, "adm": owner/admin?, "mbr": server member?, "exp": unix expiry}`. It is
signed, not encrypted: anyone holding the cookie can read those fields, but
cannot alter them or forge a new one without `APP_SECRET`. Verification uses a
constant-time compare and rejects any token whose `exp` has passed, whose
signature does not match, or which is malformed. Expiry is `SESSION_DAYS`
(default 30) from sign-in, mirrored in the cookie's `Max-Age`. There is no
server-side session store, so a cookie cannot be revoked individually before it
expires; rotating `APP_SECRET` invalidates every session at once. The `adm` flag
is re-derived from the current allow-list on every `/verify`, so removing an id
or email from the allow-list takes effect immediately for owner-only hosts.

**Cookie flags.** `Path=/; HttpOnly; Secure; SameSite=Lax` plus
`Domain=COOKIE_DOMAIN` when set. `Secure` and `SameSite` are configurable
(`COOKIE_SECURE`, `COOKIE_SAMESITE`); `HttpOnly` is not. TLS is expected to be
terminated by the reverse proxy in front of the gateway.

**What the rate limiter protects.** `/login` and `/callback` are the only routes
that perform network I/O (PIN creation and polling at plex.tv, user lookup,
optional Tautulli query). The limiter caps how often a single client IP can
drive that flow, so an unauthenticated caller cannot use the gateway to hammer
plex.tv, exhaust the handler thread pool with 10-second callback polls, or
cheaply enumerate PIN ids. `/verify`, `/logout`, `/` and `/healthz` are not
limited: `/verify` runs on every proxied request and does no I/O.

**Client IP.** The gateway is designed to run behind a reverse proxy and, by
default, takes the client IP from `X-Real-IP`, then the first `X-Forwarded-For`
entry, then the socket peer address. That IP feeds both the `TRUSTED` bypass and
the rate limiter, so the gateway's port must only be reachable from the proxy;
`TRUST_PROXY_HEADERS=0` switches to the socket peer address if it must be
exposed directly.

**Known limitations.**

- The rate limiter is in-memory and per process: it resets on restart and is
  not shared between replicas, so N replicas allow N times the configured rate.
- Rate limiting is keyed by IP only; clients behind a shared NAT share a budget,
  and an attacker with many IPs is not slowed down.
- Sessions cannot be revoked individually; only `APP_SECRET` rotation or expiry
  ends them. Membership (`mbr`) is checked once at sign-in and cached in the
  cookie until it expires.
- The cookie payload is readable by whoever holds it (it is signed, not
  encrypted); it contains Plex id, username and email.
- Clients in a `TRUSTED` network bypass authentication entirely.
- With `TRUST_PROXY_HEADERS=1` (the default) any client that can reach the
  gateway without going through the proxy can spoof its IP.
- An ephemeral `APP_SECRET` is generated when none is configured; every restart
  then logs everyone out and multiple replicas will not share sessions.

## [2026-06-13]

Initial commits (no tagged release yet).

### Added

- Stdlib-only Plex forward-auth / SSO gateway with `/verify`, `/login`,
  `/callback`, `/logout`, status page and `/healthz`; HMAC-signed stateless
  session cookie; `TRUSTED` CIDR bypass; allow-list by Plex id or email;
  open-redirect guard; Nginx Proxy Manager, Traefik, Caddy and plain nginx
  recipes.
- Per-host member mode: hosts in `MEMBER_HOSTS` accept any Plex server member,
  verified against Tautulli (`TAUTULLI_URL` / `TAUTULLI_KEY`); all other hosts
  remain owner-only.
