import unittest

from wifitester import config, nm, runner


def _cfg(text):
    import tempfile
    from pathlib import Path
    p = Path(tempfile.mkdtemp()) / "c.toml"
    p.write_text(text, encoding="utf-8")
    return p


class TestInterfacesConfig(unittest.TestCase):
    def test_default_single(self):
        cfg, _ = config.load(_cfg("[[ap]]\nssid='x'\npsk='p'\n"))
        self.assertEqual(cfg.interfaces, ["wlan0"])

    def test_multi(self):
        cfg, _ = config.load(_cfg(
            "[tester]\ninterfaces=['wlan0','wlan1','wlan2']\n"
            "[[ap]]\nssid='x'\npsk='p'\n"))
        self.assertEqual(cfg.interfaces, ["wlan0", "wlan1", "wlan2"])

    def test_primary_always_included_and_first(self):
        cfg, _ = config.load(_cfg(
            "[tester]\ninterface='wlan0'\n"
            "interfaces=['wlan2','wlan1']\n[[ap]]\nssid='x'\npsk='p'\n"))
        self.assertEqual(cfg.interfaces, ["wlan0", "wlan2", "wlan1"])

    def test_dupes_removed(self):
        cfg, _ = config.load(_cfg(
            "[tester]\ninterfaces=['wlan0','wlan0','wlan1']\n"
            "[[ap]]\nssid='x'\npsk='p'\n"))
        self.assertEqual(cfg.interfaces, ["wlan0", "wlan1"])


class TestShiftIp(unittest.TestCase):
    def test_shift(self):
        self.assertEqual(runner._shift_ip("192.168.1.248/24", 1),
                         "192.168.1.247/24")
        self.assertEqual(runner._shift_ip("192.168.1.248/24", 4),
                         "192.168.1.244/24")

    def test_underflow(self):
        with self.assertRaises(runner.PreflightError):
            runner._shift_ip("192.168.1.1/24", 3)


class TestNextFreeCidr(unittest.TestCase):
    """The allocator must walk past addresses answered on the LAN or
    claimed by another radio instead of dropping the radio entirely."""


    def _free(self, busy=(), local=()):
        import unittest.mock as mock
        return (mock.patch.object(runner.nm, "addr_assigned",
                                  side_effect=lambda ip: ip in local),
                mock.patch.object(runner.nm, "ip_in_use",
                                  side_effect=lambda ip, i, **k: ip in busy))

    def test_natural_slot_free(self):
        p1, p2 = self._free()
        with p1, p2:
            self.assertEqual(
                runner._next_free_cidr("192.168.1.248/24", 0,
                                       {"192.168.1.248"}, "eth0"),
                "192.168.1.247/24")

    def test_walks_past_in_use(self):
        p1, p2 = self._free(busy={"192.168.1.245"})
        with p1, p2:
            self.assertEqual(
                runner._next_free_cidr("192.168.1.248/24", 2,
                                       {"192.168.1.248"}, "eth0"),
                "192.168.1.244/24")

    def test_skips_claimed_and_local(self):
        p1, p2 = self._free(local={"192.168.1.247"})
        with p1, p2:
            self.assertEqual(
                runner._next_free_cidr("192.168.1.248/24", 0,
                                       {"192.168.1.248", "192.168.1.246"},
                                       "eth0"),
                "192.168.1.245/24")

    def test_exhausted(self):
        p1, p2 = self._free(busy=set(f"192.168.1.{o}" for o in range(239, 249)))
        with p1, p2:
            self.assertIsNone(
                runner._next_free_cidr("192.168.1.248/24", 0,
                                       {"192.168.1.248"}, "eth0"))


class TestBackoffWindow(unittest.TestCase):
    def test_growth_and_cap(self):
        self.assertEqual(runner._backoff_window(2), 0)   # second fail: free retry
        self.assertEqual(runner._backoff_window(3), 4)
        self.assertEqual(runner._backoff_window(4), 8)
        self.assertEqual(runner._backoff_window(5), 16)
        self.assertEqual(runner._backoff_window(9), 64)  # capped


class TestFailureBackoff(unittest.TestCase):
    """A BSSID that keeps failing to connect must drop out of the sweep
    for a bounded window and return automatically afterwards."""

    def _runner(self):
        r = runner.Runner.__new__(runner.Runner)
        r._cycle_no = 10
        r._fail_streak = {}
        r._skip_until = {}
        r.store = type("S", (), {
            "insert_visit": staticmethod(lambda rec: None),
            "radio_visit": staticmethod(lambda *a, **k: None)})()
        return r

    class _AP:
        def __init__(self, ssid):
            self.ssid = ssid

    def test_three_failures_trigger_backoff_then_recovery(self):
        r = self._runner()
        ap = self._AP("m")
        r.visit_ap = lambda *a, **k: {"ssid": "m", "bssid": "aa",
                                      "connect_ok": False,
                                      "connect_error": "timeout"}
        r._visit_item_worker("wlan2", ap, "aa")
        self.assertNotIn(("m", "aa"), r._skip_until)  # 1st fail: free retry
        r._visit_item_worker("wlan2", ap, "aa")
        self.assertNotIn(("m", "aa"), r._skip_until)  # 2nd fail: still free
        r._visit_item_worker("wlan2", ap, "aa")
        due_at = r._skip_until[("m", "aa")]
        self.assertEqual(due_at, 10 + 4)
        r._visit_items = lambda: [(ap, "aa")]
        # due again once the window has passed
        r._cycle_no = due_at
        self.assertEqual(r._due_items(), [(ap, "aa")])
        r._cycle_no = due_at - 1
        self.assertEqual(r._due_items(), [])

    def test_success_resets(self):
        r = self._runner()
        ap = self._AP("m")
        r.visit_ap = lambda *a, **k: {"ssid": "m", "bssid": "aa",
                                      "connect_ok": True, "loss_pct": 0}
        r._skip_until[("m", "aa")] = 99
        r._fail_streak[("m", "aa")] = 5
        r._visit_item_worker("wlan2", ap, "aa")
        self.assertNotIn(("m", "aa"), r._fail_streak)
        self.assertNotIn(("m", "aa"), r._skip_until)


class TestAssignItems(unittest.TestCase):
    def _ap(self, ssid="m"):
        return ssid

    F24 = {2412, 2437, 2452, 2462}
    F5 = {5180, 5240, 5500, 5500, 5745, 5765}

    def test_band_routing(self):
        caps = {"wlan0": {2412, 2462, 5745, 5500},
                "wlan1": {2412, 2462}}
        items = [("a", "B1"), ("b", "B2"), ("c", "B3"), ("d", "B4")]
        chan = {"B1": 1, "B2": 11, "B3": 100, "B4": 149}
        out = runner.assign_items(items, caps, chan)
        # 5 GHz items (B3, B4) must land on wlan0 only
        bssids0 = {b for _, b in out["wlan0"]}
        self.assertIn("B3", bssids0)
        self.assertIn("B4", bssids0)
        self.assertNotIn("B3", {b for _, b in out["wlan1"]})
        # balanced: all 4 items placed; wlan0 must absorb both 5 GHz items
        self.assertEqual(len(out["wlan0"]) + len(out["wlan1"]), 4)
        self.assertEqual(len(out["wlan0"]), 3)
        self.assertEqual(len(out["wlan1"]), 1)

    def test_unknown_chan_anywhere(self):
        caps = {"wlan0": {2412, 5745}, "wlan1": {2412}}
        out = runner.assign_items([("a", "B9")], caps, {})
        # unknown chan -> balanced to fewest items, tie -> config order
        self.assertEqual(out["wlan0"], [("a", "B9")])

    def test_no_capable_goes_to_primary(self):
        caps = {"wlan0": {2412}, "wlan1": {2412}}
        out = runner.assign_items([("a", "B5")], caps, {"B5": 149})
        self.assertEqual(out["wlan0"], [("a", "B5")])
        self.assertEqual(out["wlan1"], [])


class TestProfileNames(unittest.TestCase):
    def test_primary_legacy(self):
        self.assertEqual(nm.profile_name("77fast5", "wlan0", "wlan0"),
                         "wt-77fast5")

    def test_extra_suffixed(self):
        self.assertEqual(nm.profile_name("77fast5", "wlan1", "wlan0"),
                         "wt-77fast5-wlan1")
        self.assertEqual(nm.profile_name("77fast5"), "wt-77fast5")

    def test_ssid_sanitized(self):
        self.assertEqual(nm.profile_name("a b/c", "wlan2", "wlan0"),
                         "wt-a-b-c-wlan2")


class TestChanFreq(unittest.TestCase):
    def test_roundtrip(self):
        for c in (1, 6, 11, 36, 100, 149):
            self.assertEqual(nm.freq_to_chan(nm.chan_to_freq(c)), c)


if __name__ == "__main__":
    unittest.main()
