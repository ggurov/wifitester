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
