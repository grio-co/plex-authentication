# plex-authentication

**One Plex login for every self-hosted service.** A tiny, dependency-free
forward-auth / SSO gateway: protect Sonarr, Radarr, Prowlarr, qBittorrent, Nginx
Proxy Manager, Mylar3 — anything behind your reverse proxy — with a single
**"Sign in with Plex"**, and stop keeping a separate login per app.

```
                 ┌──────────────── reverse proxy (NPM / Traefik / Caddy / nginx)
   browser ──▶───┤  every request → auth_request /verify ─▶ plex-forward-auth
                 └──────────────── 200 ⇒ pass to app   ·   401 ⇒ "Sign in with Plex"
```

- **Stdlib-only Python**, ~1 file, runs in a tiny Alpine container. No database,
  no Redis — the session cookie is HMAC-signed and **stateless**, so the gateway
  restarts without logging anyone out.
- **SSO**: one signed cookie on `COOKIE_DOMAIN` covers every protected subdomain.
- **"Only me"**: allow-list by Plex account id and/or email
  (`ALLOWED_PLEX_IDS` / `ALLOWED_PLEX_EMAILS`).
- **Lock-out safety**: `TRUSTED` CIDRs (your LAN / Tailscale) bypass auth entirely,
  so you can always get in to fix things.
- **Proxy-agnostic**: ships an Nginx-Proxy-Manager recipe plus Traefik / Caddy /
  plain-nginx snippets.

## Why a gateway and not a patch per app?

Most self-hosted apps either ship their own auth (Servarr, qBittorrent) and don't
accept third-party-OAuth into core, or have none at all. Patching Plex OAuth into
each one is N integrations to write and maintain — and the maintainers won't merge
them. A forward-auth gateway is **one** integration that protects **all** of them,
which is exactly what reverse proxies are built for. See
[`integrations/`](integrations/) for per-stack recipes and the Servarr "trust the
proxy" setting that removes the second login.

## Quick start

1. **Find your Plex account id** — `https://plex.tv/api/v2/user` with your
   `X-Plex-Token`, or read it from the gateway's log after a sign-in.
2. **Configure** — copy [`.env.example`](.env.example) → `.env`, set `APP_SECRET`
   (`openssl rand -base64 48`), `ALLOWED_PLEX_IDS`, `COOKIE_DOMAIN`, `PUBLIC_URL`,
   and your `TRUSTED` networks.
3. **Run** — [`docker-compose.example.yml`](docker-compose.example.yml) on the same
   network as your proxy. Add a proxy host `auth.example.com → plex-forward-auth:8056`.
4. **Protect a service** — paste
   [`integrations/npm-advanced-snippet.conf`](integrations/npm-advanced-snippet.conf)
   into the service's NPM **Advanced** tab (or use the Traefik/Caddy recipe).
5. *(Recommended)* switch Servarr apps to **External auth** so Plex is the only
   prompt — [`integrations/arr-apps.md`](integrations/arr-apps.md).

## Endpoints

| Route       | Purpose                                                     |
|-------------|-------------------------------------------------------------|
| `/verify`   | auth_request target — `200` allowed, `401` not              |
| `/login`    | begin Plex PIN OAuth (`?rd=` return destination)            |
| `/callback` | finish OAuth, set the SSO cookie, redirect back            |
| `/logout`   | clear the cookie                                            |
| `/`         | status / "Sign in with Plex" page                          |
| `/healthz`  | liveness                                                     |

## Configuration

| Env | Default | Meaning |
|-----|---------|---------|
| `APP_SECRET` | *(random)* | signs the SSO cookie — **set this** and keep it stable |
| `ALLOWED_PLEX_IDS` | — | comma list of Plex account ids allowed remotely |
| `ALLOWED_PLEX_EMAILS` | — | comma list of emails allowed remotely |
| `COOKIE_DOMAIN` | host-only | cookie domain, e.g. `.example.com` for SSO |
| `COOKIE_NAME` | `plexauth` | cookie name |
| `PUBLIC_URL` | — | the gateway's own public URL |
| `REDIRECT_SUFFIX` | — | only redirect back to hosts ending with this (open-redirect guard) |
| `TRUSTED` | — | CIDRs that bypass auth (LAN / Tailscale / docker) |
| `SESSION_DAYS` | `30` | cookie lifetime |
| `PORT` | `8056` | listen port |

> ⚠️ With **no** allow-list set, any Plex account is accepted. Set
> `ALLOWED_PLEX_IDS` / `ALLOWED_PLEX_EMAILS` to mean "only me".

## Security notes

- The cookie is signed (HMAC-SHA256) but not encrypted; it carries only your Plex
  id/username/email + expiry. Treat `APP_SECRET` like a password.
- `/verify` does no network I/O — it's a cheap IP/cookie check, fine to run on
  every request.
- TLS is terminated by your proxy; the cookie is `Secure; HttpOnly; SameSite=Lax`.

MIT licensed. Not affiliated with Plex Inc.
