import tempfile
import time
import unittest
from pathlib import Path

from wifitester.store import Store


def visit(ssid, bssid, **kw):
    rec = {"ssid": ssid, "bssid": bssid, "chan": 11, "freq_mhz": 2462,
           "signal_dbm": -55, "gateway": "192.168.1.1", "connect_ok": True,
           "connect_error": None, "sent": 5, "lost": 0, "loss_pct": 0.0,
           "avg_rtt_ms": 10.0, "max_rtt_ms": 12.0, "internet_ok": True}
    rec.update(kw)
    return rec


class TestStore(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp()
        self.st = Store(self.dir)

    def tearDown(self):
        self.st.close()

    def test_visit_roundtrip_and_summary(self):
        self.st.insert_visit(visit("home", "AA:00"))
        self.st.insert_visit(visit("home", "AA:00", signal_dbm=-60,
                                   loss_pct=20.0, lost=1, avg_rtt_ms=11.0))
        rows = self.st.bssid_summary(0)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["visits"], 2)
        self.assertEqual(r["connects"], 2)
        self.assertEqual(r["avg_signal_dbm"], -57.5)
        self.assertEqual(r["avg_loss_pct"], 10.0)
        sig = list(self.st.signal_series(0))
        self.assertEqual([s["signal_dbm"] for s in sig], [-55, -60])

    def test_connect_fail_record(self):
        self.st.insert_visit(visit("home", None, connect_ok=False,
                                   connect_error="no route"))
        rows = list(self.st.visit_log(0))
        self.assertEqual(rows[0]["connect_ok"], 0)
        self.assertIn("no route", rows[0]["connect_error"])

    def test_scan_and_classification(self):
        ts = self.st.insert_scan_pass([
            {"ssid": "home", "bssid": "AA:00", "chan": 11, "freq_mhz": 2462,
             "signal": 80, "security": "WPA2", "classification": "OURS"},
            {"ssid": "", "bssid": "BB:00", "chan": 1, "freq_mhz": 2412,
             "signal": 30, "security": "", "classification": "HIDDEN"},
        ])
        self.assertTrue(ts)
        rows = list(self.st.latest_classification(0))
        cls = {r["bssid"]: r["classification"] for r in rows}
        self.assertEqual(cls["AA:00"], "OURS")
        self.assertEqual(cls["BB:00"], "HIDDEN")

    def test_suspects_verdicts(self):
        # ok AP (not a suspect)
        self.st.insert_visit(visit("home", "AA:00"))
        # nothing behind it: auth ok, 100% loss
        self.st.insert_visit(visit("ghost", "BB:00", loss_pct=100.0, lost=5))
        # dropping data
        self.st.insert_visit(visit("home", "CC:00", loss_pct=25.0, lost=1))
        # cannot connect at all
        self.st.insert_visit(visit("gone", None, connect_ok=False,
                                   connect_error="timeout"))
        sus = {r["bssid"]: r["verdict"] for r in self.st.suspects(0)}
        self.assertNotIn("AA:00", sus)
        self.assertEqual(sus["BB:00"], "no_backhaul")
        self.assertEqual(sus["CC:00"], "dropping")
        self.assertEqual(sus[None], "failing")

    def test_auth_attempts_stored(self):
        self.st.insert_auth("home", "AA:01", "success", "OURS", 3200)
        row = self.st.db.execute(
            "SELECT * FROM auth_attempts").fetchone()
        self.assertEqual(row["result"], "success")
        self.assertEqual(row["duration_ms"], 3200)


class TestRadioStats(unittest.TestCase):
    """Per-adapter health accounting: the dying-stick detector's data."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.st = Store(self.dir)

    def tearDown(self):
        self.st.close()

    def test_visit_accounting(self):
        self.st.radio_visit("wlan2", True)
        self.st.radio_visit("wlan2", False, "timeout: x")
        self.st.radio_visit("wlan2", False, "timeout: y")
        r = self.st.radio_stats()[0]
        self.assertEqual(r["iface"], "wlan2")
        self.assertEqual(r["visits"], 3)
        self.assertEqual(r["connect_ok"], 1)
        self.assertEqual(r["connect_fail"], 2)
        self.assertEqual(r["consec_fail"], 2)
        self.assertIsNotNone(r["last_ok"])
        self.assertIsNotNone(r["last_fail"])
        self.assertEqual(r["last_error"], "timeout: y")

    def test_success_resets_streak(self):
        self.st.radio_visit("wlan4", False, "timeout")
        self.st.radio_visit("wlan4", True)
        r = self.st.radio_stats()[0]
        self.assertEqual(r["consec_fail"], 0)
        self.assertEqual(r["last_ok"], r["last_seen"])

    def test_heartbeat_keeps_first_seen_updates_scan(self):
        self.st.radio_heartbeat("wlan0", True, scan_bss=12)
        first = self.st.radio_stats()[0]["first_seen"]
        self.st.radio_heartbeat("wlan0", True, scan_bss=15)
        r = self.st.radio_stats()[0]
        self.assertEqual(r["first_seen"], first)
        self.assertEqual(r["last_scan_bss"], 15)
        self.assertEqual(r["present"], 1)

    def test_extra_heartbeat_preserves_scan_fields(self):
        self.st.radio_heartbeat("wlan2", True, scan_bss=9)
        self.st.radio_heartbeat("wlan2", True)  # extras carry no scan data
        r = self.st.radio_stats()[0]
        self.assertEqual(r["last_scan_bss"], 9)
        self.assertEqual(r["present"], 1)

    def test_visit_iface_recorded(self):
        self.st.insert_visit({"ssid": "m", "iface": "wlan2",
                              "connect_ok": True})
        row = self.st.db.execute(
            "SELECT iface FROM visits").fetchone()
        self.assertEqual(row["iface"], "wlan2")


class TestSweepPerf(unittest.TestCase):
    def setUp(self):
        self.st = Store(Path(tempfile.mkdtemp()))

    def tearDown(self):
        self.st.close()

    def test_roundtrip_and_order(self):
        self.st.insert_sweep_perf(1, 12, 8, 96.0)
        self.st.insert_sweep_perf(3, 12, 12, 40.0)
        rows = self.st.sweep_perf()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["radios"], 3)   # newest first
        self.assertEqual(rows[0]["duration_s"], 40.0)
        self.assertEqual(rows[1]["items_done"], 8)

    def test_hour_fail_attributed(self):
        import time
        now = time.time()
        # B1: fail now, another radio succeeded 60s earlier -> radio's fault
        # B2: fail now, no cross-radio success -> AP's fault (solo)
        # B3: fail 2h ago only -> outside the 1h window -> not counted
        def v(bssid, iface, ok, epoch):
            self.st.db.execute(
                "INSERT INTO visits(ts,epoch,ssid,bssid,iface,connect_ok) "
                "VALUES (?,?,?,?,?,?)",
                ("t", epoch, "m", bssid, iface, 1 if ok else 0))
        v("B1", "wlan0", 0, now)
        v("B1", "wlan1", 1, now - 60)
        v("B2", "wlan0", 0, now)
        v("B3", "wlan0", 0, now - 7200)
        self.st.db.commit()
        a = self.st.hour_fail_attributed(now - 3600)
        self.assertEqual(a["B1"], {"radio_fails": 1, "solo_fails": 0})
        self.assertEqual(a["B2"], {"radio_fails": 0, "solo_fails": 1})
        self.assertNotIn("B3", a)

    def test_fail_triage(self):
        self.st.insert_visit({"ssid": "m", "bssid": "AA", "iface": "wlan2",
                              "connect_ok": False,
                              "connect_error": "timeout"})          # solo
        self.st.insert_visit({"ssid": "m", "bssid": "BB", "iface": "wlan2",
                              "connect_ok": False,
                              "connect_error": "timeout"})
        self.st.insert_visit({"ssid": "m", "bssid": "BB", "iface": "wlan0",
                              "connect_ok": True})                   # blames BB
        solo, shared = self.st.radio_fail_triage("wlan2", 0)
        self.assertEqual((solo, shared), (1, 1))


if __name__ == "__main__":
    unittest.main()
