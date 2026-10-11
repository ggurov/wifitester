import unittest

from wifitester import scanner


def net(ssid, bssid, signal=50, security="WPA2"):
    return {"ssid": ssid, "bssid": bssid, "chan": 1, "freq_mhz": 2412,
            "signal": signal, "security": security}


KNOWN = {
    "home": {"psk": "secret", "expected_bssids": ["AA:AA:AA:AA:AA:01"]},
    "nopsk": {"psk": None, "expected_bssids": []},
}


def plan_nets(nets, **kw):
    return scanner.plan(scanner.group_networks(nets), KNOWN, **kw)


class TestGroup(unittest.TestCase):
    def test_dedupe_keeps_strongest(self):
        nets = [net("x", "AA:00", signal=30), net("x", "AA:00", signal=80),
                net("x", "AA:01", signal=40)]
        groups = scanner.group_networks(nets)
        self.assertEqual(len(groups["x"]), 2)
        kept = {n["bssid"]: n["signal"] for n in groups["x"]}
        self.assertEqual(kept, {"AA:00": 80, "AA:01": 40})


class TestPlan(unittest.TestCase):
    def test_pinned_bssid_trusted(self):
        items = plan_nets([net("home", "AA:AA:AA:AA:AA:01")])
        self.assertEqual(items[0][1], scanner.PLAN_RECORD)
        self.assertEqual(items[0][2], "OURS")

    def test_unpinned_known_ssid_auth_probe(self):
        items = plan_nets([net("home", "AA:AA:AA:AA:AA:02")])
        self.assertEqual(items[0][1], scanner.PLAN_AUTH)

    def test_auth_probe_never(self):
        items = plan_nets([net("home", "AA:AA:AA:AA:AA:02")],
                          auth_probe="never")
        self.assertEqual(items[0][1], scanner.PLAN_RECORD)
        self.assertEqual(items[0][2], "KNOWN_UNVERIFIED")

    def test_known_without_psk(self):
        items = plan_nets([net("nopsk", "AA:AA:AA:AA:AA:03")])
        self.assertEqual(items[0][1], scanner.PLAN_RECORD)
        self.assertEqual(items[0][2], "KNOWN_UNVERIFIED")

    def test_unknown_secured(self):
        items = plan_nets([net("neighbor", "BB:00")])
        self.assertEqual(items[0][1], scanner.PLAN_RECORD)
        self.assertEqual(items[0][2], "SECURED_FOREIGN")

    def test_unknown_open_assoc(self):
        items = plan_nets([net("cafe", "BB:01", security="")])
        self.assertEqual(items[0][1], scanner.PLAN_ASSOC)
        items = plan_nets([net("cafe", "BB:01", security="")],
                          open_assoc=False)
        self.assertEqual(items[0][2], "OPEN_FOREIGN")

    def test_enterprise(self):
        items = plan_nets([net("corp", "BB:02", security="WPA2 802.1X")])
        self.assertEqual(items[0][2], "SECURED_8021X")

    def test_hidden(self):
        items = plan_nets([net("", "BB:03")])
        self.assertEqual(items[0][2], scanner.HIDDEN)


class TestOutcomes(unittest.TestCase):
    def test_auth_outcome(self):
        self.assertEqual(
            scanner.auth_outcome_to_classification(True, False), "OURS")
        self.assertEqual(
            scanner.auth_outcome_to_classification(False, False), "ROGUE_SSID")
        self.assertEqual(
            scanner.auth_outcome_to_classification(False, True), "AUTH_TIMEOUT")

    def test_assoc_outcome(self):
        self.assertEqual(scanner.assoc_outcome_to_classification(True),
                         "OPEN_FOREIGN")
        self.assertEqual(scanner.assoc_outcome_to_classification(False),
                         "OPEN_FOREIGN_REFUSED")

    def test_classify_all_fills_results(self):
        items = plan_nets([net("home", "AA:AA:AA:AA:AA:02"),
                           net("cafe", "BB:01", security="")])
        results = {("AA:AA:AA:AA:AA:02", scanner.PLAN_AUTH): "OURS",
                   ("BB:01", scanner.PLAN_ASSOC): "OPEN_FOREIGN"}
        nets = scanner.classify_all(items, results)
        by_bssid = {n["bssid"]: n["classification"] for n in nets}
        self.assertEqual(by_bssid["AA:AA:AA:AA:AA:02"], "OURS")
        self.assertEqual(by_bssid["BB:01"], "OPEN_FOREIGN")


if __name__ == "__main__":
    unittest.main()
