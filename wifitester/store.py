"""Local SQLite datastore: every probe visit, scan observation and auth
attempt lands here on the Pi. Schema v1."""

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,             -- ISO8601 UTC
  epoch REAL NOT NULL,
  ssid TEXT NOT NULL,
  iface TEXT,                   -- radio that made the visit
  bssid TEXT,
  chan INTEGER,
  freq_mhz INTEGER,
  signal_dbm INTEGER,
  gateway TEXT,
  connect_ok INTEGER NOT NULL,
  connect_error TEXT,
  probes_sent INTEGER,
  probes_lost INTEGER,
  loss_pct REAL,
  avg_rtt_ms REAL,
  max_rtt_ms REAL,
  internet_ok INTEGER
);
CREATE TABLE IF NOT EXISTS scan_obs (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  epoch REAL NOT NULL,
  ssid TEXT NOT NULL,           -- '' for hidden
  bssid TEXT NOT NULL,
  chan INTEGER,
  freq_mhz INTEGER,
  signal_pct INTEGER,           -- nmcli quality 0-100
  security TEXT,
  classification TEXT
);
CREATE TABLE IF NOT EXISTS auth_attempts (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  epoch REAL NOT NULL,
  ssid TEXT NOT NULL,
  bssid TEXT NOT NULL,
  result TEXT NOT NULL,         -- success|auth_fail|assoc_ok|assoc_fail|timeout|no_psk
  classification TEXT,
  duration_ms INTEGER
);
CREATE TABLE IF NOT EXISTS lan_neigh (
  mac TEXT PRIMARY KEY,
  ip TEXT NOT NULL,
  epoch REAL NOT NULL,
  ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS radio_stats (
  iface TEXT PRIMARY KEY,
  first_seen REAL,              -- epoch first used as a test radio
  last_seen REAL,               -- last sweep heartbeat
  present INTEGER,              -- interface currently exists
  visits INTEGER DEFAULT 0,
  connect_ok INTEGER DEFAULT 0,
  connect_fail INTEGER DEFAULT 0,
  consec_fail INTEGER DEFAULT 0,
  last_ok REAL,
  last_fail REAL,
  last_error TEXT,
  last_scan_bss INTEGER,        -- BSSIDs seen in the last scan pass (primary)
  last_scan REAL
);
CREATE TABLE IF NOT EXISTS ap_inventory (
  unit_key TEXT PRIMARY KEY,    -- collector-unique unit id (source-ip)
  source TEXT NOT NULL,         -- collector: aruba-ssh, fios-ui, ...
  name TEXT, model TEXT, ip TEXT, wired_mac TEXT,
  uptime TEXT, clients INTEGER,
  radios_json TEXT,             -- [{band, chan, util}, ...]
  last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS switch_ports (
  mac TEXT PRIMARY KEY,         -- lowercase learned MAC
  port TEXT NOT NULL,           -- Junos interface, e.g. ge-0/0/36
  vlan TEXT,
  lldp_port TEXT,
  lldp_system TEXT,
  last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS port_traffic (
  port TEXT PRIMARY KEY,        -- Junos interface, e.g. ge-0/0/36
  link TEXT,
  in_bps INTEGER,
  out_bps INTEGER,
  in_bytes INTEGER,
  out_bytes INTEGER,
  last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS radio_leases (
  mac TEXT PRIMARY KEY,         -- radio MAC (survives ifname renames)
  ip TEXT NOT NULL,
  expires REAL NOT NULL,        -- epoch
  last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sweep_perf (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  epoch REAL NOT NULL,
  radios INTEGER NOT NULL,
  items_total INTEGER NOT NULL,
  items_done INTEGER NOT NULL,
  duration_s REAL NOT NULL,
  visits_time_s REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS fios_leases (
  mac TEXT PRIMARY KEY,         -- lowercase lease MAC
  hostname TEXT, ip TEXT,
  expires_raw TEXT,
  last_seen REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_visits_bssid ON visits(bssid, epoch);
CREATE INDEX IF NOT EXISTS idx_visits_ssid ON visits(ssid, epoch);
CREATE INDEX IF NOT EXISTS idx_scan_bssid ON scan_obs(bssid, epoch);
CREATE INDEX IF NOT EXISTS idx_auth_bssid ON auth_attempts(bssid, epoch);
"""


def now_pair():
    t = time.time()
    return t, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


class Store:
    def __init__(self, data_dir):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "wifitester.db"
        # web server answers from worker threads; serialize all db use
        self._lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        # busy_timeout must precede journal_mode: WAL switch needs a brief
        # exclusive lock, and the web unit may start concurrently
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute("PRAGMA journal_mode=WAL")   # web readers + probe writer
        self.db.executescript(SCHEMA)
        try:  # dbs created before radio attribution
            self.db.execute("ALTER TABLE visits ADD COLUMN iface TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:  # dbs created before sweep-perf timing
            self.db.execute("ALTER TABLE sweep_perf ADD COLUMN visits_time_s REAL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # column already exists
        self.db.commit()

    def close(self):
        self.db.close()

    # -- writers ----------------------------------------------------------

    def insert_visit(self, rec):
        epoch, ts = now_pair()
        with self._lock:
            self.db.execute(
                "INSERT INTO visits(ts,epoch,ssid,iface,bssid,chan,freq_mhz,"
                "signal_dbm,gateway,connect_ok,connect_error,probes_sent,"
                "probes_lost,loss_pct,avg_rtt_ms,max_rtt_ms,internet_ok) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts, epoch, rec.get("ssid"), rec.get("iface"),
                 rec.get("bssid"),
                 rec.get("chan"), rec.get("freq_mhz"), rec.get("signal_dbm"),
                 rec.get("gateway"), 1 if rec.get("connect_ok") else 0,
                 rec.get("connect_error"), rec.get("sent"), rec.get("lost"),
                 rec.get("loss_pct"), rec.get("avg_rtt_ms"),
                 rec.get("max_rtt_ms"),
                 None if rec.get("internet_ok") is None
                 else 1 if rec.get("internet_ok") else 0))
            self.db.commit()

    def insert_scan_pass(self, nets):
        """nets: dicts with ssid,bssid,chan,freq_mhz,signal,security,classification."""
        epoch, ts = now_pair()
        with self._lock:
            self.db.executemany(
                "INSERT INTO scan_obs(ts,epoch,ssid,bssid,chan,freq_mhz,"
                "signal_pct,security,classification) VALUES (?,?,?,?,?,?,?,?,?)",
                [(ts, epoch, n.get("ssid", ""), n["bssid"], n.get("chan"),
                  n.get("freq_mhz"), n.get("signal"), n.get("security"),
                  n.get("classification")) for n in nets])
            self.db.commit()
        return ts

    def insert_auth(self, ssid, bssid, result, classification, duration_ms):
        epoch, ts = now_pair()
        with self._lock:
            self.db.execute(
                "INSERT INTO auth_attempts(ts,epoch,ssid,bssid,result,"
                "classification,duration_ms) VALUES (?,?,?,?,?,?,?)",
                (ts, epoch, ssid, bssid, result, classification, duration_ms))
            self.db.commit()

    # -- readers ----------------------------------------------------------

    def radio_heartbeat(self, iface, present, scan_bss=None):
        """Sweep heartbeat: radio still in the pool and present; optionally
        record the BSSID count of the last scan pass (primary only)."""
        epoch, _ = now_pair()
        with self._lock:
            self.db.execute(
                "INSERT INTO radio_stats(iface,first_seen,last_seen,present,"
                "last_scan_bss,last_scan) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(iface) DO UPDATE SET "
                "last_seen=excluded.last_seen, present=excluded.present, "
                "last_scan_bss=COALESCE(excluded.last_scan_bss, "
                "radio_stats.last_scan_bss), "
                "last_scan=COALESCE(excluded.last_scan, radio_stats.last_scan)",
                (iface, epoch, epoch, 1 if present else 0,
                 scan_bss, epoch if scan_bss is not None else None))
            self.db.commit()

    def radio_visit(self, iface, ok, error=None):
        """Account one visit attempt made on radio `iface`."""
        epoch, _ = now_pair()
        with self._lock:
            self.db.execute(
                "INSERT INTO radio_stats(iface,first_seen,last_seen,present,"
                "visits,connect_ok,connect_fail,consec_fail,last_ok,"
                "last_fail,last_error) VALUES (?,?,?,1,1,?,0,?,?,?,?) "
                "ON CONFLICT(iface) DO UPDATE SET "
                "last_seen=excluded.last_seen, visits=visits+1, "
                "connect_ok=connect_ok+excluded.connect_ok, "
                "connect_fail=connect_fail+(1-excluded.connect_ok), "
                "consec_fail=CASE WHEN excluded.connect_ok=1 THEN 0 "
                "ELSE consec_fail+1 END, "
                "last_ok=CASE WHEN excluded.connect_ok=1 THEN excluded.last_ok "
                "ELSE last_ok END, "
                "last_fail=CASE WHEN excluded.connect_ok=1 THEN last_fail "
                "ELSE excluded.last_fail END, "
                "last_error=excluded.last_error",
                (iface, epoch, epoch, 1 if ok else 0, 0 if ok else 1,
                 epoch if ok else None, epoch if not ok else None,
                 (error or "")[:300] if not ok else None))
            self.db.commit()

    def radio_stats(self):
        return self._rows("SELECT * FROM radio_stats ORDER BY iface")

    def upsert_ap_inventory(self, rows):
        epoch, _ = now_pair()
        with self._lock:
            for r in rows:
                self.db.execute(
                    "INSERT INTO ap_inventory(unit_key,source,name,model,ip,"
                    "wired_mac,uptime,clients,radios_json,last_seen) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(unit_key) DO UPDATE SET "
                    "source=excluded.source, name=excluded.name, "
                    "model=excluded.model, ip=excluded.ip, "
                    "wired_mac=excluded.wired_mac, uptime=excluded.uptime, "
                    "clients=excluded.clients, "
                    "radios_json=excluded.radios_json, "
                    "last_seen=excluded.last_seen",
                    (r["unit_key"], r["source"], r.get("name"),
                     r.get("model"), r.get("ip"), r.get("wired_mac"),
                     r.get("uptime"), r.get("clients"),
                     json.dumps(r.get("radios", [])), epoch))
            self.db.commit()

    def ap_inventory(self):
        return self._rows("SELECT * FROM ap_inventory ORDER BY ip")

    def upsert_switch_ports(self, rows):
        epoch, _ = now_pair()
        with self._lock:
            for r in rows:
                self.db.execute(
                    "INSERT INTO switch_ports(mac,port,vlan,lldp_port,"
                    "lldp_system,last_seen) VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(mac) DO UPDATE SET port=excluded.port, "
                    "vlan=excluded.vlan, lldp_port=excluded.lldp_port, "
                    "lldp_system=excluded.lldp_system, "
                    "last_seen=excluded.last_seen",
                    (r["mac"], r["port"], r.get("vlan"),
                     r.get("lldp_port"), r.get("lldp_system"), epoch))
            self.db.commit()

    def switch_ports(self):
        return self._rows("SELECT * FROM switch_ports ORDER BY port, mac")

    def upsert_port_traffic(self, rows):
        epoch, _ = now_pair()
        with self._lock:
            for r in rows:
                self.db.execute(
                    "INSERT INTO port_traffic(port,link,in_bps,out_bps,"
                    "in_bytes,out_bytes,last_seen) VALUES (?,?,?,?,?,?,?) "
                    "ON CONFLICT(port) DO UPDATE SET link=excluded.link, "
                    "in_bps=excluded.in_bps, out_bps=excluded.out_bps, "
                    "in_bytes=excluded.in_bytes, out_bytes=excluded.out_bytes, "
                    "last_seen=excluded.last_seen",
                    (r["port"], r.get("link"), r.get("in_bps"),
                     r.get("out_bps"), r.get("in_bytes"), r.get("out_bytes"),
                     epoch))
            self.db.commit()

    def port_traffic(self):
        return self._rows("SELECT * FROM port_traffic ORDER BY port")

    def upsert_fios_leases(self, rows):
        epoch, _ = now_pair()
        with self._lock:
            for r in rows:
                self.db.execute(
                    "INSERT INTO fios_leases(mac,hostname,ip,expires_raw,"
                    "last_seen) VALUES (?,?,?,?,?) "
                    "ON CONFLICT(mac) DO UPDATE SET hostname=excluded.hostname,"
                    "ip=excluded.ip, expires_raw=excluded.expires_raw, "
                    "last_seen=excluded.last_seen",
                    (r["mac"], r.get("hostname"), r.get("ip"),
                     r.get("expires_raw"), epoch))
            self.db.commit()

    def fios_leases(self):
        return self._rows("SELECT * FROM fios_leases ORDER BY ip")

    def radio_lease_get(self, mac):
        """Cached DHCP lease for a radio MAC: (ip, expires) or None."""
        rows = self._rows(
            "SELECT ip, expires FROM radio_leases WHERE mac = ?", (mac,))
        return (rows[0]["ip"], rows[0]["expires"]) if rows else None

    def radio_lease_set(self, mac, ip, expires):
        epoch, _ = now_pair()
        with self._lock:
            self.db.execute(
                "INSERT INTO radio_leases(mac,ip,expires,last_seen) "
                "VALUES (?,?,?,?) ON CONFLICT(mac) DO UPDATE SET "
                "ip=excluded.ip, expires=excluded.expires, "
                "last_seen=excluded.last_seen",
                (mac, ip, expires, epoch))
            self.db.commit()

    def insert_sweep_perf(self, radios, items_total, items_done, duration_s,
                          visits_time_s=0.0):
        epoch, ts = now_pair()
        with self._lock:
            self.db.execute(
                "INSERT INTO sweep_perf(ts,epoch,radios,items_total,"
                "items_done,duration_s,visits_time_s) "
                "VALUES (?,?,?,?,?,?,?)",
                (ts, epoch, radios, items_total, items_done, duration_s,
                 visits_time_s))
            self.db.commit()

    def sweep_perf(self, limit=20):
        return self._rows(
            "SELECT * FROM sweep_perf ORDER BY epoch DESC LIMIT ?", (limit,))

    def radio_fail_triage(self, iface, since_epoch):
        """Split a radio's recent connect failures into (solo, shared-blame).
        A failure is shared-blame when some OTHER radio reached the same
        BSSID fine within +/-1h -- the target was sick, not the adapter."""
        rows = self._rows(
            """SELECT EXISTS(
                 SELECT 1 FROM visits v2
                 WHERE v2.bssid = v1.bssid AND v2.connect_ok = 1
                   AND v2.iface IS NOT NULL AND v2.iface != v1.iface
                   AND v2.epoch BETWEEN v1.epoch - 3600 AND v1.epoch + 3600
               ) AS blamed
               FROM visits v1
               WHERE v1.iface = ? AND v1.connect_ok = 0 AND v1.epoch >= ?""",
            (iface, since_epoch))
        solo = sum(1 for r in rows if not r["blamed"])
        return solo, len(rows) - solo

    def hour_fail_attributed(self, since_epoch):
        """Per-BSSID hourly connection-failure accounting, split by blame:
        {bssid: {"radio_fails": n, "solo_fails": n}}. A failed association
        is radio_fails only when some OTHER radio reached the same BSSID
        within ~5 min of the failure (the target demonstrably worked then).
        Stale successes (window ±1h) wrongly excused failures of targets
        that died mid-hour -- the exact skew that kept dead APs green."""
        rows = self._rows(
            """SELECT v1.bssid,
                      SUM(CASE WHEN EXISTS(
                            SELECT 1 FROM visits v2
                            WHERE v2.bssid = v1.bssid AND v2.connect_ok = 1
                              AND v2.iface IS NOT NULL
                              AND v2.iface != v1.iface
                              AND v2.epoch BETWEEN v1.epoch - 300
                                              AND v1.epoch + 90
                          ) THEN 1 ELSE 0 END) AS radio_fails,
                      COUNT(*) AS total
               FROM visits v1
               WHERE v1.epoch >= ? AND v1.connect_ok = 0
                 AND v1.bssid IS NOT NULL
               GROUP BY v1.bssid""",
            (since_epoch,))
        return {r["bssid"]: {"radio_fails": r["radio_fails"],
                             "solo_fails": r["total"] - r["radio_fails"]}
                for r in rows}

    def bssid_streaks(self, since_epoch):
        """{bssid: consecutive failed visits} counting backwards from the
        most recent visit per BSSID (a success resets the count)."""
        rows = self._rows(
            """SELECT bssid, connect_ok FROM visits
               WHERE epoch >= ? AND bssid IS NOT NULL
               ORDER BY epoch DESC""",
            (since_epoch,))
        streaks = {}
        for r in rows:
            b = r["bssid"]
            if b not in streaks:
                streaks[b] = 0 if r["connect_ok"] else 1
            elif streaks[b] and not r["connect_ok"]:
                streaks[b] += 1
        return streaks

    def _rows(self, sql, args=()):
        with self._lock:
            return self.db.execute(sql, args).fetchall()

    def last_scan_epoch(self):
        with self._lock:
            row = self.db.execute("SELECT MAX(epoch) AS m FROM scan_obs").fetchone()
        return row["m"] if row else None

    def signal_series(self, since_epoch):
        """Signal strength (dBm) per visit: (epoch, bssid, ssid, signal_dbm)."""
        return self._rows(
            "SELECT epoch,bssid,ssid,signal_dbm FROM visits "
            "WHERE epoch>=? AND bssid IS NOT NULL AND signal_dbm IS NOT NULL "
            "ORDER BY epoch", (since_epoch,))

    def neighbor_series(self, since_epoch):
        """Scan-observed signal% per BSSID: (epoch,bssid,ssid,signal_pct)."""
        return self._rows(
            "SELECT epoch,bssid,ssid,signal_pct FROM scan_obs "
            "WHERE epoch>=? ORDER BY epoch", (since_epoch,))

    def loss_series(self, since_epoch):
        return self._rows(
            "SELECT epoch,bssid,ssid,loss_pct FROM visits "
            "WHERE epoch>=? AND connect_ok=1 AND loss_pct IS NOT NULL "
            "ORDER BY epoch", (since_epoch,))

    def bssid_summary(self, since_epoch):
        """One row per BSSID: activity, signal, loss, verdict flags."""
        return self._rows(
            """
            WITH recent AS (SELECT * FROM visits WHERE epoch>=?)
            SELECT v.ssid, v.bssid,
                   COUNT(*) AS visits,
                   SUM(v.connect_ok) AS connects,
                   ROUND(AVG(v.signal_dbm),1) AS avg_signal_dbm,
                   MAX(v.signal_dbm) AS best_signal_dbm,
                   ROUND(AVG(v.loss_pct),1) AS avg_loss_pct,
                   MAX(v.loss_pct) AS max_loss_pct,
                   ROUND(AVG(v.avg_rtt_ms),1) AS avg_rtt_ms,
                   MAX(v.epoch) AS last_epoch
            FROM recent v
            WHERE v.bssid IS NOT NULL
            GROUP BY v.bssid
            """, (since_epoch,))

    def latest_classification(self, since_epoch):
        """Latest scan classification per BSSID."""
        return self._rows(
            """
            SELECT s.bssid, s.ssid, s.chan, s.signal_pct, s.security,
                   s.classification, MAX(s.epoch) AS last_epoch
            FROM scan_obs s WHERE s.epoch>=?
            GROUP BY s.bssid
            ORDER BY s.signal_pct DESC
            """, (since_epoch,))

    def visit_log(self, since_epoch, limit=50):
        return self._rows(
            "SELECT * FROM visits WHERE epoch>=? ORDER BY epoch DESC LIMIT ?",
            (since_epoch, limit))

    def latest_visit_per_ssid(self, since_epoch):
        """Most recent visit row for each SSID (for status tables)."""
        return self._rows(
            """
            SELECT v.* FROM visits v
            JOIN (SELECT ssid, MAX(epoch) AS m FROM visits
                  WHERE epoch>=? GROUP BY ssid) t
              ON v.ssid=t.ssid AND v.epoch=t.m
            ORDER BY v.ssid
            """, (since_epoch,))

    def latest_visit_per_bssid(self, since_epoch):
        """Most recent visit row for each BSSID: one card per physical AP."""
        return self._rows(
            """
            SELECT v.* FROM visits v
            JOIN (SELECT bssid, MAX(epoch) AS m FROM visits
                  WHERE epoch>=? AND bssid IS NOT NULL GROUP BY bssid) t
              ON v.bssid=t.bssid AND v.epoch=t.m
            ORDER BY v.bssid
            """, (since_epoch,))

    def hour_loss(self, since_epoch):
        """Per-BSSID probe accounting in a window:
        {bssid: {'sent':int,'lost':int,'conn_fails':int}}."""
        rows = self._rows(
            """
            SELECT bssid,
                   SUM(CASE WHEN connect_ok=1 THEN probes_sent ELSE 0 END) AS sent,
                   SUM(CASE WHEN connect_ok=1 THEN probes_lost ELSE 0 END) AS lost,
                   SUM(CASE WHEN connect_ok=0 THEN 1 ELSE 0 END) AS conn_fails
            FROM visits
            WHERE epoch>=? AND bssid IS NOT NULL
            GROUP BY bssid
            """, (since_epoch,))
        return {r["bssid"]: {"sent": r["sent"] or 0, "lost": r["lost"] or 0,
                             "conn_fails": r["conn_fails"] or 0}
                for r in rows}

    def replace_neighbors(self, pairs):
        """Replace the LAN neighbor snapshot (mac, ip) from the last sweep."""
        epoch, ts = now_pair()
        with self._lock:
            self.db.execute("DELETE FROM lan_neigh")
            self.db.executemany(
                "INSERT INTO lan_neigh(mac,ip,epoch,ts) VALUES (?,?,?,?)",
                [(mac, ip, epoch, ts) for mac, ip in pairs])
            self.db.commit()
        return ts

    def neighbors(self):
        """{mac: ip} from the most recent LAN sweep."""
        rows = self._rows("SELECT mac,ip FROM lan_neigh")
        return {r["mac"].upper(): r["ip"] for r in rows}

    def neighbors_age_s(self, now):
        with self._lock:
            row = self.db.execute(
                "SELECT MAX(epoch) AS m FROM lan_neigh").fetchone()
        return round(now - row["m"]) if row and row["m"] else None

    def event_feed(self, since_epoch, limit=30):
        """Recent anomalies: connect failures, loss, internet misses."""
        return self._rows(
            """
            SELECT ts, epoch, ssid, bssid, signal_dbm, connect_ok,
                   connect_error, loss_pct, avg_rtt_ms, internet_ok
            FROM visits
            WHERE epoch>=? AND (connect_ok=0
                                OR (loss_pct IS NOT NULL AND loss_pct>0)
                                OR internet_ok=0)
            ORDER BY epoch DESC LIMIT ?
            """, (since_epoch, limit))

    def suspects(self, since_epoch):
        """BSSIDs that look like they are dropping data or have no backhaul.

        no_backhaul : authenticated fine, 100% probe loss (nothing behind it)
        dropping    : authenticated fine, avg loss > 0
        failing     : connect failures recorded
        """
        return self._rows(
            """
            SELECT ssid, bssid,
                   CASE WHEN MAX(loss_pct)>=100 THEN 'no_backhaul'
                        WHEN AVG(loss_pct)>0    THEN 'dropping'
                        ELSE 'failing' END AS verdict,
                   COUNT(*) AS visits,
                   ROUND(AVG(loss_pct),1) AS avg_loss_pct,
                   SUM(connect_ok) AS connects,
                   MAX(ts) AS last_ts
            FROM visits
            WHERE epoch>=? AND (connect_ok=0 OR loss_pct IS NOT NULL
                                AND loss_pct>0)
            GROUP BY bssid
            ORDER BY avg_loss_pct DESC, last_ts DESC
            """, (since_epoch,))
