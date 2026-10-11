"""Local SQLite datastore: every probe visit, scan observation and auth
attempt lands here on the Pi. Schema v1."""

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
        self.db.execute("PRAGMA journal_mode=WAL")   # web readers + probe writer
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self):
        self.db.close()

    # -- writers ----------------------------------------------------------

    def insert_visit(self, rec):
        epoch, ts = now_pair()
        with self._lock:
            self.db.execute(
                "INSERT INTO visits(ts,epoch,ssid,bssid,chan,freq_mhz,"
                "signal_dbm,gateway,connect_ok,connect_error,probes_sent,"
                "probes_lost,loss_pct,avg_rtt_ms,max_rtt_ms,internet_ok) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts, epoch, rec.get("ssid"), rec.get("bssid"),
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
