import unittest

from wifitester import probe


class TestSummarize(unittest.TestCase):
    @staticmethod
    def p(ok, rtt=10.0):
        return {"ok": ok, "rtt_ms": rtt if ok else None}

    def test_all_ok(self):
        s = probe.summarize([self.p(True), self.p(True), self.p(True)])
        self.assertEqual(s["sent"], 3)
        self.assertEqual(s["lost"], 0)
        self.assertEqual(s["loss_pct"], 0.0)
        self.assertEqual(s["avg_rtt_ms"], 10.0)
        self.assertEqual(s["max_rtt_ms"], 10.0)

    def test_isolated_miss_excused(self):
        # single failure between successes is noise, not loss
        s = probe.summarize([self.p(True), self.p(False), self.p(True)])
        self.assertEqual(s["lost"], 0)
        self.assertEqual(s["loss_pct"], 0.0)

    def test_leading_isolated_miss_excused(self):
        s = probe.summarize([self.p(False), self.p(True), self.p(True)])
        self.assertEqual(s["lost"], 0)

    def test_two_consecutive_count(self):
        s = probe.summarize([self.p(True), self.p(False), self.p(False)])
        self.assertEqual(s["lost"], 2)
        self.assertEqual(s["loss_pct"], 66.7)
        self.assertEqual(s["avg_rtt_ms"], 10.0)

    def test_all_lost(self):
        s = probe.summarize([self.p(False), self.p(False), self.p(False)])
        self.assertEqual(s["lost"], 3)
        self.assertEqual(s["loss_pct"], 100.0)
        self.assertIsNone(s["avg_rtt_ms"])

    def test_alternating_runs(self):
        # fail fail ok fail fail -> two runs of 2 -> 4 lost
        s = probe.summarize([self.p(False), self.p(False), self.p(True),
                             self.p(False), self.p(False)])
        self.assertEqual(s["lost"], 4)
        self.assertEqual(s["loss_pct"], 80.0)

    def test_empty(self):
        s = probe.summarize([])
        self.assertEqual(s["loss_pct"], 0.0)
        self.assertIsNone(s["avg_rtt_ms"])


if __name__ == "__main__":
    unittest.main()
