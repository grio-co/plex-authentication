# Nginx Proxy Manager integration

NPM auto-generates each proxy host's `location /`, so you can't put `auth_request`
*inside* it from the Advanced tab without a duplicate-location error. The trick:
declare `auth_request` at the **server level** (the Advanced block is inside
`server { … }`) and let nginx **inherit** it into the generated `location /`.

## 1. Run the gateway on the same docker network as NPM

See [`../docker-compose.example.yml`](../docker-compose.example.yml). The container
must be reachable from NPM as `plex-forward-auth:8056`.

## 2. Give it its own subdomain

Add a normal NPM proxy host, e.g. `auth.example.com` → `plex-forward-auth:8056`,
with your wildcard/LE cert and **Websockets off**. Do **not** put the snippet on
this host (the gateway must stay reachable to log in).

## 3. Protect a service

On each service's proxy host → **Advanced** tab, paste
[`npm-advanced-snippet.conf`](npm-advanced-snippet.conf) (edit the two
`auth.example.com` / `plex-forward-auth:8056` values). Save.

That's it. From a TRUSTED network (your LAN/Tailscale CIDRs) the gateway returns
200 instantly — no prompt. From anywhere else, the browser is bounced to
"Sign in with Plex", and after sign-in an SSO cookie on `COOKIE_DOMAIN` covers
**every** protected host with no further logins.

## 4. (Recommended) stop the app's own login double-prompting

Apps with their own login (Sonarr/Radarr/Prowlarr, qBittorrent, …) will ask
*again* after Plex. Switch them to trust the proxy — see
[`arr-apps.md`](arr-apps.md) for the *arr family.

## Rollback / lock-out safety

- Keep your LAN/Tailscale ranges in `TRUSTED`. You can always reach NPM admin
  (`:81`) and the apps from there even if the gateway is down.
- To remove protection from a host: clear its Advanced box and Save.
- `nginx -t` inside the NPM container validates config; a bad Advanced block
  fails the reload and nginx keeps serving the previous good config.
