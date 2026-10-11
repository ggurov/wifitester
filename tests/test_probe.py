import unittest

from wifitester import probe


class TestSummarize(unittest.TestCase):
    def test_all_ok(self):
        probes = [{"ok": True, "rtt_ms": 10.0}, {"ok": True, "rtt_ms": 12.0},
                  {"ok": True, "rtt_ms": 14.0}]
        s = probe.summarize(probes)
        self.assertEqual(s["sent"], 3)
        self.assertEqual(s["lost"], 0)
        self.assertEqual(s["loss_pct"], 0.0)
        self.assertEqual(s["avg_rtt_ms"], 12.0)
        self.assertEqual(s["max_rtt_ms"], 14.0)

    def test_mixed(self):
        probes = [{"ok": True, "rtt_ms": 10.0}, {"ok": False, "rtt_ms": None},
                  {"ok": False, "rtt_ms": None}]
        s = probe.summarize(probes)
        self.assertEqual(s["lost"], 2)
        self.assertEqual(s["loss_pct"], 66.7)
        self.assertEqual(s["avg_rtt_ms"], 10.0)
        self.assertEqual(s["max_rtt_ms"], 10.0)

    def test_empty(self):
        s = probe.summarize([])
        self.assertEqual(s["loss_pct"], 0.0)
        self.assertIsNone(s["avg_rtt_ms"])


if __name__ == "__main__":
    unittest.main()
