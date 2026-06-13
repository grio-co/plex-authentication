# Traefik & Caddy (the same gateway, different proxy)

The gateway is proxy-agnostic — `/verify` returns `200`/`401`, which is all any
forward-auth implementation needs.

## Traefik (ForwardAuth middleware)

```yaml
http:
  middlewares:
    plex-auth:
      forwardAuth:
        address: "http://plex-forward-auth:8056/verify"
        trustForwardHeader: true
        authResponseHeaders: ["X-Auth-User"]
  routers:
    sonarr:
      rule: "Host(`sonarr.example.com`)"
      middlewares: ["plex-auth"]
      service: sonarr
```

On a 401, redirect unauthenticated browsers to the login. Either add an
`errors` middleware, or front the login with its own router at
`auth.example.com` and point users there. Traefik passes the client IP in
`X-Forwarded-For`; the gateway reads it for the TRUSTED-network bypass.

## Caddy (forward_auth directive)

```caddyfile
sonarr.example.com {
    forward_auth plex-forward-auth:8056 {
        uri /verify
        copy_headers X-Auth-User
    }
    @denied status 401
    redir @denied https://auth.example.com/login?rd={scheme}://{host}{uri}
    reverse_proxy sonarr:8989
}

auth.example.com {
    reverse_proxy plex-forward-auth:8056
}
```

## Plain nginx (no NPM)

```nginx
server {
    server_name sonarr.example.com;
    auth_request /__plexauth;
    error_page 401 = @login;

    location = /__plexauth {
        internal; auth_request off;
        proxy_pass http://plex-forward-auth:8056/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Real-IP $remote_addr;
    }
    location @login { return 302 https://auth.example.com/login?rd=https://$host$request_uri; }
    location / { proxy_pass http://sonarr:8989; }
}
```
