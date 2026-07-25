# zoraxy-anubis-adapter

A [Zoraxy](https://github.com/tobychui/zoraxy) plugin that brings
[Anubis](https://github.com/TecharoHQ/anubis) bot protection to your proxy
routes. No fork, no patching — just a plugin.

Anubis throws a proof-of-work challenge at scrapers and AI crawlers. Real
browsers solve it in a second, bots don't. This adapter wires Anubis into
Zoraxy's forward-auth system so you can toggle protection per route from
the plugin UI.

## How it works

```
Browser hits your site
  → Zoraxy asks the adapter "is this a bot?"
  → Adapter asks Anubis
  → If human: request goes through, done
  → If bot: redirect to challenge page
    → Browser solves the PoW, gets a cookie
    → Next request passes automatically
```

The plugin runs on two ports: a dynamic one for the UI (assigned by Zoraxy)
and a fixed one (9698) for forward-auth and the Anubis proxy. The fixed
port means forward-auth URLs and vdir targets stay the same across restarts.

## Setup

### 1. Run Anubis

Grab the example config and docker-compose from the `examples/` folder:

```bash
cp examples/botPolicies.yaml .
cp examples/docker-compose.yml .
docker compose up -d
```

Anubis runs in subrequest mode (no upstream target). The important thing in
`botPolicies.yaml` is `DENY: 403` — without that, denied bots get a 200 and
slip through the forward-auth check.

`JWT_RESTRICTION_HEADER` is set to empty because Zoraxy's forward-auth
doesn't forward the client IP. Without this, Anubis binds the cookie to
the wrong IP and rejects it on every subsequent request.

### 2. Build and install

```bash
git clone https://github.com/sniffingsugar/zoraxy-anubis-adapter
cd zoraxy-anubis-adapter
go build -o zoraxy-anubis-adapter .
```

Drop the binary into Zoraxy's plugin folder. The folder name must match
the binary name:

```
plugins/zoraxy-anubis-adapter/zoraxy-anubis-adapter
```

Restart Zoraxy. The plugin shows up in the plugin manager.

### 3. Configure

Open the plugin UI in Zoraxy and:

1. Set the **Anubis URL** (e.g. `http://anubis:8923`) → Save
2. Click **Install Global Config** — tells Zoraxy where the forward-auth endpoint is
3. Toggle routes on/off — pick which sites get protection

## Manual config

If the buttons don't work or you prefer doing it by hand:

**Forward-Auth** (Zoraxy → Settings → Auth Provider):
- Address: `http://127.0.0.1:9698/check`
- Enable "Use X-Original Headers"
- Ignored Paths: `/.within.website/`

**Per route** (Zoraxy → HTTP Proxy → rule):
- Authentication → Forward Auth
- Virtual Dirs → Add: path `/.within.website/`, target `127.0.0.1:9698`

**To remove**: clear the forward-auth address in Zoraxy settings, set the
route auth back to None, delete the `/.within.website/` vdir.

## Requirements

- Zoraxy 3.2.0+ (plugin system)
- Anubis running in subrequest mode
- Go 1.23+ to build

## License

MIT
