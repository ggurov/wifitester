import unittest

from wifitester import nm


class TestSplitNmcli(unittest.TestCase):
    def test_escaped_bssid(self):
        line = r" :77fast5:78\:67\:0E\:58\:73\:EF:11:2462 MHz:82:WPA2"
        parts = nm.split_nmcli(line.strip())
        self.assertEqual(parts[0], "")
        self.assertEqual(parts[1], "77fast5")
        self.assertEqual(parts[2], "78:67:0E:58:73:EF")
        self.assertEqual(parts[4], "2462 MHz")

    def test_escaped_backslash_then_colon_is_separator(self):
        # literal backslash (escaped) followed by a real separator
        parts = nm.split_nmcli(r"a\\:b")
        self.assertEqual(parts, ["a\\", "b"])

    def test_empty_fields(self):
        parts = nm.split_nmcli("::x:")
        self.assertEqual(parts, ["", "", "x", ""])


class TestParseTsv(unittest.TestCase):
    def test_scan_row(self):
        out = (r"77fast5:D4\:5D\:64\:10\:43\:FC:149:5745 MHz:100:WPA2\n"
               r":B0\:39\:56\:92\:6F\:CD:157:5785 MHz:27:WPA2").replace(r"\n", "\n")
        fields = ["SSID", "BSSID", "CHAN", "FREQ", "SIGNAL", "SECURITY"]
        rows = nm.parse_nmcli_tsv(out, fields)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["SSID"], "77fast5")
        self.assertEqual(rows[0]["BSSID"], r"D4\:5D\:64\:10\:43\:FC".replace("\\", ""))
        self.assertEqual(rows[0]["CHAN"], "149")
        self.assertEqual(rows[1]["SSID"], "")  # hidden


class TestUplinkRoute(unittest.TestCase):
    """The guard must re-install the wired uplink's connected /24 when it
    vanishes (the link-loss failure mode) and never throw."""

    def _patch(self, wired, addrs, routes):
        import unittest.mock as mock
        calls = []

        def fake_run(cmd, **k):
            calls.append(cmd)
            if cmd[:3] == ["ip", "-j", "-4"]:
                out = addrs
            elif cmd[:2] == ["ip", "route"] and len(cmd) == 2:
                out = routes
            else:
                out = ""
            return type("R", (), {"stdout": out})()

        return (mock.patch.object(nm, "wired_iface", return_value=wired),
                mock.patch.object(nm, "run", side_effect=fake_run), calls)

    def test_route_present_is_noop(self):
        p1, p2, calls = self._patch(
            "eth0",
            '[{"ifname":"eth0","addr_info":[{"local":"192.168.1.252",'
            '"prefixlen":24}]}]',
            "default via 192.168.1.1 dev eth0 metric 100\n"
            "192.168.1.0/24 dev eth0 proto kernel src 192.168.1.252\n")
        with p1, p2:
            self.assertTrue(nm.ensure_uplink_route())
        self.assertEqual([c for c in calls if "replace" in c], [])

    def test_missing_route_is_reinstalled(self):
        p1, p2, calls = self._patch(
            "eth0",
            '[{"ifname":"eth0","addr_info":[{"local":"192.168.1.252",'
            '"prefixlen":24}]}]',
            "default via 192.168.1.1 dev eth0 metric 100\n")
        with p1, p2:
            self.assertFalse(nm.ensure_uplink_route())
        replace = [c for c in calls if "replace" in c]
        self.assertEqual(
            replace,
            [["ip", "route", "replace", "192.168.1.0/24", "dev", "eth0",
              "proto", "kernel", "src", "192.168.1.252"]])

    def test_no_wired_uplink_is_noop(self):
        p1, p2, calls = self._patch(None, "[]", "")
        with p1, p2:
            self.assertTrue(nm.ensure_uplink_route())
        self.assertEqual(calls, [])


class TestFreqChan(unittest.TestCase):
    def test_2g(self):
        self.assertEqual(nm.freq_to_chan(2412), 1)
        self.assertEqual(nm.freq_to_chan(2462), 11)
        self.assertEqual(nm.freq_to_chan(2484), 14)

    def test_5g(self):
        self.assertEqual(nm.freq_to_chan(5745), 149)
        self.assertEqual(nm.freq_to_chan(5500), 100)

    def test_6g_and_junk(self):
        self.assertEqual(nm.freq_to_chan(5955), 1)
        self.assertIsNone(nm.freq_to_chan(900))
        self.assertIsNone(nm.freq_to_chan(None))


class TestKeyMgmt(unittest.TestCase):
    def test_map(self):
        self.assertEqual(nm.key_mgmt_for(""), "none")
        self.assertEqual(nm.key_mgmt_for("WPA2"), "wpa-psk")
        self.assertEqual(nm.key_mgmt_for("WPA1 WPA2"), "wpa-psk")
        self.assertEqual(nm.key_mgmt_for("SAE"), "sae")
        self.assertEqual(nm.key_mgmt_for("WPA2 802.1X"), "wpa-eap")


if __name__ == "__main__":
    unittest.main()
