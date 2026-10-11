import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from wifitester import config, webserver
from wifitester.store import Store


def visit(ssid, bssid, **kw):
    rec = {"ssid": ssid, "bssid": bssid, "chan": 11, "freq_mhz": 2462,
           "signal_dbm": -55, "gateway": "192.168.1.1", "connect_ok": True,
           "connect_error": None, "sent": 3, "lost": 0, "loss_pct": 0.0,
           "avg_rtt_ms": 9.0, "max_rtt_ms": 11.0, "internet_ok": True}
    rec.update(kw)
    return rec


class TestApiPayloads(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.st = Store(self.dir)
        self.st.insert_visit(visit("home", "AA:00"))
        self.st.insert_visit(visit("ghost", "BB:00", loss_pct=100.0, lost=3))
        self.st.insert_scan_pass([
            {"ssid": "home", "bssid": "AA:00", "chan": 11, "freq_mhz": 2462,
             "signal": 80, "security": "WPA2", "classification": "OURS"}])
        self.cfg, _ = config.load(_cfgfile())

    def tearDown(self):
        self.st.close()

    def test_state_shape(self):
        s = webserver.api_state(self.st, self.cfg, started=time.time() - 5)
        for key in ("now", "uptime_s", "live", "aps", "events", "suspects",
                    "cycle", "last_scan_age_s"):
            self.assertIn(key, s)
        by_ssid = {a["ssid"]: a for a in s["aps"]}
        self.assertEqual(by_ssid["ghost"]["loss_pct"], 100.0)
        kinds = {e["kind"] for e in s["events"]}
        self.assertIn("no_backhaul", kinds)
        self.assertEqual(s["last_scan_age_s"], 0)

    def test_series_shape(self):
        s = webserver.api_series(self.st, hours=1)
        self.assertEqual(len(s["signal"]), 2)
        self.assertEqual([r["pct"] for r in s["loss"]], [0.0, 100.0])
        self.assertEqual(set(s["loss"][0]), {"ssid", "bssid", "epoch", "pct"})


def _cfgfile():
    d = Path(tempfile.mkdtemp())
    p = d / "c.toml"
    p.write_text('[[ap]]\nssid = "home"\npsk = "x"\n', encoding="utf-8")
    return p


class TestServeHttp(unittest.TestCase):
    def test_endpoints(self):
        st = Store(Path(tempfile.mkdtemp()))
        st.insert_visit(visit("home", "AA:00"))
        cfg, _ = config.load(_cfgfile())
        port = 18899
        httpd_started = threading.Event()

        import http.server
        handler = webserver.make_handler(st, cfg, started=time.time())
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            for path, expect in [("/", "wifitester live"),
                                 ("/api/state", '"aps"'),
                                 ("/api/series?hours=1", '"signal"')]:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}{path}", timeout=5) as r:
                    self.assertEqual(r.status, 200)
                    self.assertIn(expect, r.read().decode())
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/nope",
                                       timeout=5)
                self.fail("expected 404")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 404)
        finally:
            httpd.shutdown()
            st.close()


class TestWalConcurrency(unittest.TestCase):
    def test_writer_and_reader(self):
        d = Path(tempfile.mkdtemp())
        writer = Store(d)
        reader = Store(d)  # second connection on same db
        writer.insert_visit(visit("home", "AA:00"))
        rows = reader.db.execute("SELECT ssid FROM visits").fetchall()
        self.assertEqual([r["ssid"] for r in rows], ["home"])
        mode = reader.db.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode.lower(), "wal")
        writer.close()
        reader.close()


if __name__ == "__main__":
    unittest.main()
