# STATUS — wifitester

_Updated 2026-10-11 21:20_

## 🚀 Next quest

- **Router mgmt polling is LIVE for the Aruba** (AP-105 @ .177 via SSH/plink, 5-min cadence →
  `ap_inventory` table → "Physical APs" dashboard section). Still blocked: **Fios .1** (403
  login guard — payload fully known, retry after quiet period; may need the sticker password)
  and **ASUS .220/.207** (admin/admin1 rejected with verified encoding — re-check password).
  Aruba reboot (user, via web) cleared a wedged console.
- **Mesh 2.4 GHz data paths dying** (card-confirmed, backhaul fine): satellite 192.168.1.218
  worst (2.4 = 100% loss, 5 GHz AUTH_TIMEOUT), main-router 2.4 (`73:EF`/`82:67:…`) flaky,
  `BB:xx` ch1 flapping. All 5 GHz clean. Only ONE Aruba exists (.177); the d4:5d:64 units
  (.207/.218) are a different, still-unidentified vendor.
- Standing wifi still down (CUS stick dead on the bus; MAC-pinned profile inert). eth0 is the
  access path.

## Context

- Test pool: **auto mode** (`interfaces = "auto"` since 2026-10-12 12:2x) — wifi radios are
  discovered at runtime: plug in → joins automatically (DHCP once, lease cached by MAC);
  unplug → drops automatically (GONE in the adapter panel). Standing links (non-wt
  connections) are never grabbed. Primary stays wlan0 (.248 static). Currently zero USB
  sticks attached (both TP-LINKs pulled; the two identical EUS sticks RF-jammed each other
  until physically separated on extenders).
- Router inventory creds: /home/pi/.wifitester/creds.json (aruba ssh) + creds.md (reference).
- Live config `/etc/wifitester/config.toml` (root 600); deploy = copy file to /opt/wifitester +
  restart wifitester; db /var/lib/wifitester/wifitester.db (history wiped 20:55, backup
  `wifitester.db.bak-20261011`); web :8787.
- No `node` on this Pi: .wolf JS tools unusable; buglog/cerebrum by hand (shard format).
