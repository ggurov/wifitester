import tempfile
import unittest
from pathlib import Path

from wifitester import graph
from wifitester.store import Store


class TestLineChart(unittest.TestCase):
    def test_svg_with_two_series(self):
        t0 = 1_700_000_000
        svg = graph.line_chart(
            {"a": [(t0, -50), (t0 + 60, -60)],
             "b": [(t0, -70), (t0 + 60, -65)]},
            "Signal", "dBm", y_invert=True)
        self.assertIn("<svg", svg)
        self.assertEqual(svg.count("<polyline"), 2)
        self.assertEqual(svg.count("<circle"), 4)
        self.assertIn("Signal", svg)

    def test_empty_series_placeholder(self):
        svg = graph.line_chart({}, "Nothing", "dBm")
        self.assertIn("no data", svg)


class TestDashboard(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.st = Store(self.dir)
        t0 = 1_700_000_000
        # visits need real epoch near now for since-window; use now-based
        now = __import__("time").time()
        self.st.insert_visit({"ssid": "home", "bssid": "AA:00", "chan": 11,
                              "freq_mhz": 2462, "signal_dbm": -55,
                              "gateway": "192.168.1.1", "connect_ok": True,
                              "sent": 5, "lost": 0, "loss_pct": 0.0,
                              "avg_rtt_ms": 9.0, "max_rtt_ms": 11.0,
                              "internet_ok": True})
        self.st.db.execute("UPDATE visits SET epoch=?", (now - 120,))
        self.st.insert_visit({"ssid": "home", "bssid": "AA:00", "chan": 11,
                              "freq_mhz": 2462, "signal_dbm": -62,
                              "gateway": "192.168.1.1", "connect_ok": True,
                              "sent": 5, "lost": 5, "loss_pct": 100.0,
                              "avg_rtt_ms": None, "max_rtt_ms": None,
                              "internet_ok": False})
        self.st.db.execute("UPDATE visits SET epoch=?", (now - 60,))
        self.st.insert_scan_pass([
            {"ssid": "home", "bssid": "AA:00", "chan": 11, "freq_mhz": 2462,
             "signal": 82, "security": "WPA2", "classification": "OURS"}])
        self.st.db.execute("UPDATE scan_obs SET epoch=?", (now - 60,))
        self.st.db.commit()

    def tearDown(self):
        self.st.close()

    def test_dashboard_written(self):
        out = graph.build_dashboard(self.st, __import__("time").time() - 3600,
                                    self.dir / "dashboard.html")
        text = out.read_text(encoding="utf-8")
        self.assertIn("Signal strength per visit", text)
        self.assertIn("no_backhaul", text)
        self.assertEqual(text.count("<svg"), 3)
        self.assertIn("AA:00", text)


if __name__ == "__main__":
    unittest.main()
