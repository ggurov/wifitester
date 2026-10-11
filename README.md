# wifitester

Continuous AP health tester for a multi-AP house, running on a Raspberry Pi.
It round-robins the Pi's wifi radio across your access points, probes the
router behind each one, scans and classifies every neighbor network, and
stores everything in a local SQLite datastore with signal/loss graphs.

Built on the [epicwolf](https://github.com/ggurov/epicwolf) template
(`.wolf/` + `.claude/` agent-memory trees are vendored from it).

## What it does

**Probe cycle** (`run`, or per-AP with `probe`): for each configured AP,
associate, wait for DHCP, ping the gateway N times (bound to the test
interface), plus one internet-hop ping. Per visit the datastore captures:
time, SSID, BSSID, channel, signal (dBm), gateway, loss %, RTT stats,
internet reachability.

**Scan + classification** (`scan`): active scan of the neighborhood, then:

| classification | meaning |
|---|---|
| `OURS` | pinned `expected_bssids` or PSK-authenticated by us |
| `ROGUE_SSID` | correct SSID, rejects our PSK — someone cloned your network |
| `KNOWN_UNVERIFIED` | configured AP we couldn't verify (no psk, or probing off) |
| `AUTH_TIMEOUT` | association attempt timed out (ambiguous) |
| `OPEN_FOREIGN` / `OPEN_FOREIGN_REFUSED` | unknown open network, assoc tried |
| `SECURED_FOREIGN` | unknown WPA network (not attempted) |
| `SECURED_8021X` | enterprise network, needs creds we don't have |
| `HIDDEN` | hidden SSID broadcast |

Known-SSID BSSIDs not in `expected_bssids` get a real association attempt
with your PSK (per-BSSID pin) — that's how "is this actually ours" is
answered. Pin verified BSSIDs to skip re-probing them.

**Backhaul detection** (the point of it all): an AP that authenticates fine
but shows **100% probe loss** is broadcasting the right SSID with nothing
behind it — clients associate to it and starve. The report flags these as
`no_backhaul`, along with `dropping` (partial loss) and `failing` (connect
failures), per BSSID, so you know exactly which box to fix.

**Datastore + graphs**: SQLite at `<data>/wifitester.db` (`visits`,
`scan_obs`, `auth_attempts` tables). `report` prints verdict tables in the
terminal; `dashboard` writes a self-contained `dashboard.html` with
signal-strength-over-time, loss-per-visit, and neighbor-signal charts.

## Layout / safety

- One radio = sequential visits; the config's `cycle_interval_s` sets sweep
  cadence (each AP visit needs connect + settle + probe time, ~20 s).
- Tester-managed NetworkManager profiles are all named `wt-*`,
  `autoconnect=no`; your own profiles are never touched, and the original
  connection is restored when the tester stops (SIGINT/SIGTERM safe).
- `require_wired_uplink=true` (default) refuses to start unless a non-wifi
  interface is connected — so cycling the radio can't cut your access to the
  Pi. Only disable this on a console-connected box.
- PSKs live in `psk_file`s (or `psk`), never committed; `/etc/wifitester` is
  root-only.

## Install (Raspberry Pi OS)

```bash
git clone https://github.com/ggurov/wifitester.git
cd wifitester
sudo ./install.sh                       # code -> /opt, unit -> systemd
sudo nano /etc/wifitester/config.toml   # set psk_file per AP
echo "$PSK" | sudo tee /etc/wifitester/psk/77fast5 && sudo chmod 600 /etc/wifitester/psk/77fast5
wifitester validate
sudo systemctl enable --now wifitester
journalctl -u wifitester -f
```

## CLI

```
wifitester validate                 # config + environment check
wifitester run [--once] [--no-scan] # daemon loop (probe cycle + scan passes)
wifitester probe <ssid>             # one visit now, JSON record to stdout
wifitester scan [--json]            # one scan + classification pass
wifitester report [--hours 24]      # suspects / per-BSSID / neighbors / visits
wifitester dashboard [--hours 24]   # writes ./data/dashboard.html
```

Global flags: `-c config.toml` (default `/etc/wifitester/config.toml` then
`./config.toml`), `-d datadir` (default `./data`).
Ad-hoc runs touch the radio: use `sudo` (nmcli device control needs root).

## Datastore schema

```sql
visits(id, ts, epoch, ssid, bssid, chan, freq_mhz, signal_dbm, gateway,
       connect_ok, connect_error, probes_sent, probes_lost, loss_pct,
       avg_rtt_ms, max_rtt_ms, internet_ok)
scan_obs(id, ts, epoch, ssid, bssid, chan, freq_mhz, signal_pct, security,
         classification)
auth_attempts(id, ts, epoch, ssid, bssid, result, classification, duration_ms)
```

Query it directly: `sqlite3 data/wifitester.db 'select ts,ssid,bssid,
signal_dbm,loss_pct from visits order by epoch desc limit 20'`

## Tests

```bash
python3 -m unittest discover -s tests   # parsers, classifier, store, graphs
```

The unit tests never touch the radio; all system calls go through one seam
(`wifitester/nm.run`).

## epicwolf

The `.wolf/` + `.claude/` trees are the epicwolf template (AGPL-3.0, same
license as this repo): project memory, sharded buglog, session handoffs for
coding agents working in this repo. See its `README` sections in
`.wolf/SHARDS.md`.
