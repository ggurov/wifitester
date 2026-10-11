import time
import unittest

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


if __name__ == "__main__":
    unittest.main()
