# Servarr (Sonarr / Radarr / Prowlarr / Lidarr / Readarr / Whisparr)

These apps have their own login, so behind the gateway a remote user is prompted
twice (Plex, then the app). To make **Plex the only login**, tell the app to trust
the reverse proxy instead of running its own auth.

> The Servarr team does not accept native third-party-OAuth (Plex/OIDC) into core —
> the supported pattern is exactly this "External / proxy auth" mode. So the
> integration here is configuration, not a code patch.

## Option A — UI
Settings → General → Security:
- **Authentication** → `External` *(older builds: enable "External" / set
  Authentication Required → "Disabled for Local Addresses")*
- Save and restart.

## Option B — config.xml (what the installer/automation edits)
In the app's `config.xml`:

```xml
<AuthenticationMethod>External</AuthenticationMethod>
<AuthenticationRequired>DisabledForLocalAddresses</AuthenticationRequired>
```

Restart the container. The app now trusts whoever the proxy lets through — which
is the gateway (remote = your Plex account only) or your TRUSTED LAN/Tailscale.

## qBittorrent
WebUI → Options → Web UI:
- ✔ **Bypass authentication for clients on localhost**
- ✔ **Bypass authentication for clients in whitelisted IP subnets** → add your
  LAN/Tailscale + the docker bridge so the gateway/proxy isn't challenged.

## Anything else (Mylar3, Tautulli, …)
Either leave the app's own login on as a second factor, or disable it and rely on
the gateway. The gateway doesn't care what's behind it.
