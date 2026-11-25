# meshwatch

Self-hosted monitor, alerting and remote admin for the [MeshCore](https://github.com/meshcore-dev/MeshCore)
nodes **you** care about. Each person runs their own instance with their own watchlist.

- **Passive monitoring** from any MeshCore MQTT feed (the common observer format,
  `meshcore/<IATA>/<observer>/packets`) and from your companion radio: last heard,
  which observers hear the node directly, SNR/RSSI, paths.
- **Active polling** through one or more companion radios (TCP or USB serial; e.g. one per
  frequency/network): logs in to your
  repeaters/room servers (admin password if known, otherwise guest) and fetches
  battery, uptime, noise floor, airtime, packet counters and telemetry.
- **Alerts** via [ntfy](https://ntfy.sh): node silent, low battery, SNR drop versus its
  7-day baseline, fewer observers hearing it, noise floor rise, and "no data at all".
  A polled node only counts as silent after two failed polls since it was last heard
  (meshwatch polls it early to check). Optional daily summary at a set local time.
- **Dashboard cards** with 24 h battery and SNR sparklines, problems first, and a **map** of
  your nodes and the observers that hear them directly (Leaflet + OpenStreetMap tiles).
- **Fleet view**: once a day meshwatch reads firmware (`ver`) and key settings (`get tx`,
  `get flood.max`, …) from nodes it has the admin password for, flags firmware older than the
  newest MeshCore release on GitHub, and highlights settings that differ between nodes on the
  same network.
- **Remote admin console** with autocomplete for every MeshCore repeater/room/sensor CLI
  command, argument hints, confirmation for disruptive commands, and an audit log. Run a
  command or a saved snippet on several nodes at once; `set` commands show the previous value.
  Passwords in commands are never written to the audit log or history.
- **History**: raw data 30 days, hourly rollups 1 year, charts per node.
- **Passkey login** (single owner), API tokens for scripts and the planned iPhone app,
  JSON API at `/api/v1/…`.

## How node evidence works

| Evidence | Source | Gives |
|---|---|---|
| Advert | signature-checked advert with the node's key | alive; zero-hop adverts give the observer's SNR/RSSI of the node |
| Relay | node's hash is the **last** hop of a flood packet | alive + SNR/RSSI of the node at that observer |
| Earlier hop | node's hash elsewhere in a flood path | alive |
| Poll | status/telemetry reply over the mesh | alive + health data |

Hop hashes are only 1–3 bytes, so relay evidence is used only when no other repeater or
room server seen in the last 14 days shares that prefix. Nodes on 1-byte hashes in busy
areas will mostly rely on adverts and polling.

## Run it

Needs Docker and an HTTPS hostname. Passkeys only work on a secure origin; for testing
on the same machine, `http://localhost` also works.

```bash
git clone https://github.com/kesh33w/meshwatch && cd meshwatch
cp .env.example .env
python3 -c 'import secrets;print(secrets.token_urlsafe(48))'   # paste into MW_SECRET_KEY
$EDITOR .env                                                     # set MW_ORIGIN
chmod 600 .env
docker compose up -d --build
docker compose logs meshwatch | grep setup                      # one-time setup link
```

Open the setup link, create your passkey, then in **Settings**:

1. **Companion radios**: TCP host/port of a WiFi/TCP companion (or an openHop companion
   identity), or a USB serial device (uncomment `devices:` in `compose.yaml`). Add one per
   network if you watch nodes on more than one frequency. Each node uses the radio picked on
   its page, or **Automatic**: the companion that heard it most recently, then a companion whose
   optional *MQTT regions* match where the node was heard, then the one that last polled it. If a poll fails and no companion has heard the node, the next companion is tried.
2. **MQTT feeds**: e.g. `wss://broker.example.org/mqtt` with your credentials.
3. **Notifications**: an ntfy server + topic; subscribe to it in the ntfy phone app.

Then **Add** nodes by searching names seen in adverts (tick several to add them together) or pasting a public key. Add the
admin password to enable polling with full stats and the console, or a guest password for
read-only polling.

### Exposing it

The container listens on `127.0.0.1:8790` only. Put TLS in front, for example:

- **Cloudflare Tunnel**: public hostname → `http://127.0.0.1:8790`. Adding a Cloudflare
  Access application in front (allow only your email) keeps scanners away from the app.
- **Caddy**: `meshwatch.example.org { reverse_proxy 127.0.0.1:8790 }`.

`MW_ORIGIN` must match the URL you open exactly (scheme + host), or passkeys fail.

## Airtime and safety

- One request at a time per companion; per-companion budget (default 20 mesh requests/hour)
  and minimum gap between requests. Different companions poll in parallel. A poll is up to 3 requests (login when needed, status,
  telemetry). A due poll is skipped when the node was heard passively and recently polled.
  Failures back off exponentially (max 6 h).
- Stored passwords (repeaters, MQTT, ntfy) are encrypted with a key derived from
  `MW_SECRET_KEY` and never shown again in the UI or API.
- The console refuses commands MeshCore only accepts over USB serial, asks for confirmation
  for anything that reboots or changes the node, and logs every command and reply.
- State-changing requests require the page's own origin (or an API token).

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
MW_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))') MW_DATA_DIR=./data .venv/bin/meshwatch
```

The CLI catalog (`meshwatch/data/cli_commands.json`) was generated from MeshCore's
`docs/cli_commands.md` and `CommonCLI.cpp` (see its `source` field). Regenerate it when
the firmware adds commands.

## License

MIT
