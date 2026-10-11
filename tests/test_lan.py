import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wifitester import ethmatch, nm
from wifitester.store import Store


class TestEthMatch(unittest.TestCase):
    N = {"24:DE:C6:BD:BB:A3": "192.168.1.113",
         "D4:5D:64:0D:B2:01": "192.168.1.104",
         "AA:BB:CC:00:00:01": "192.168.1.9"}

    def test_exact(self):
        mac, ip, conf = ethmatch.match_eth("24:DE:C6:BD:BB:A3", self.N)
        self.assertEqual((mac, ip, conf),
                         ("24:DE:C6:BD:BB:A3", "192.168.1.113", "exact"))

    def test_near_plus(self):
        mac, ip, conf = ethmatch.match_eth("24:DE:C6:BD:BB:A1", self.N)
        self.assertEqual(mac, "24:DE:C6:BD:BB:A3")
        self.assertEqual(conf, "near+2")

    def test_near_minus(self):
        mac, ip, conf = ethmatch.match_eth("D4:5D:64:0D:B2:02", self.N)
        self.assertEqual(conf, "near-1")

    def test_picks_closest(self):
        n = dict(self.N)
        n["24:DE:C6:BD:BB:A5"] = "192.168.1.115"
        mac, _, conf = ethmatch.match_eth("24:DE:C6:BD:BB:A4", n)
        self.assertEqual(mac, "24:DE:C6:BD:BB:A3")  # tie -> lower mac
        self.assertEqual(conf, "near-1")

    def test_delta_17_no_match(self):
        n = {"24:DE:C6:BD:BB:B2": "192.168.1.200"}  # +0x11 = 17
        self.assertEqual(ethmatch.match_eth("24:DE:C6:BD:BB:A1", n),
                         (None, None, None))

    def test_other_oui_no_match(self):
        self.assertEqual(ethmatch.match_eth("11:22:33:44:55:66", self.N),
                         (None, None, None))

    def test_empty_and_none(self):
        self.assertEqual(ethmatch.match_eth("24:DE:C6:BD:BB:A1", {}),
                         (None, None, None))
        self.assertEqual(ethmatch.match_eth(None, self.N),
                         (None, None, None))


class TestNeighborTable(unittest.TestCase):
    def test_parse(self):
        fake = mock.Mock()
        fake.stdout = ('[{"dst":"192.168.1.113","lladdr":"24:de:c6:bd:bb:a3",'
                       '"state":["STALE"]},{"dst":"192.168.1.9","state":'
                       '["FAILED"]},{"dst":"192.168.1.104",'
                       '"lladdr":"d4:5d:64:0d:b2:01","state":["REACHABLE"]}]')
        with mock.patch.object(nm, "run", return_value=fake):
            t = nm.neighbor_table("eth0")
        self.assertEqual(t, {"24:DE:C6:BD:BB:A3": "192.168.1.113",
                             "D4:5D:64:0D:B2:01": "192.168.1.104"})

    def test_lan_hosts(self):
        hosts = nm.lan_hosts("192.168.1.248/24")
        self.assertIn("192.168.1.1", hosts)
        self.assertIn("192.168.1.254", hosts)
        self.assertNotIn("192.168.1.0", hosts)
        self.assertEqual(len(hosts), 254)


class TestHourLoss(unittest.TestCase):
    def test_aggregate(self):
        st = Store(Path(tempfile.mkdtemp()))
        try:
            st.insert_visit({"ssid": "m", "bssid": "AA:00", "connect_ok": True,
                             "sent": 3, "lost": 1, "loss_pct": 33.3})
            st.insert_visit({"ssid": "m", "bssid": "AA:00", "connect_ok": True,
                             "sent": 3, "lost": 0, "loss_pct": 0.0})
            st.insert_visit({"ssid": "m", "bssid": "AA:00", "connect_ok": False,
                             "connect_error": "x"})
            h = st.hour_loss(0)
            self.assertEqual(h["AA:00"],
                             {"sent": 6, "lost": 1, "conn_fails": 1})
        finally:
            st.close()

    def test_neighbors_roundtrip(self):
        st = Store(Path(tempfile.mkdtemp()))
        try:
            st.replace_neighbors([("AA:00", "1.2.3.4")])
            self.assertEqual(st.neighbors(), {"AA:00": "1.2.3.4"})
            self.assertIsNotNone(st.neighbors_age_s(__import__("time").time()))
        finally:
            st.close()


if __name__ == "__main__":
    unittest.main()


class TestVapMatch(unittest.TestCase):
    N = {"78:67:0E:58:73:EE": "192.168.1.1"}

    def test_vap_near(self):
        mac, ip, conf = ethmatch.match_eth("82:67:0E:58:73:EF", self.N)
        self.assertEqual((mac, ip), ("78:67:0E:58:73:EE", "192.168.1.1"))
        self.assertEqual(conf, "near-1~vap")

    def test_vap_exact_tail(self):
        n = {"78:67:0E:58:73:EF": "192.168.1.1"}
        mac, _, conf = ethmatch.match_eth("82:67:0E:58:73:EF", n)
        self.assertEqual(conf, "exact~vap")

    def test_vap_no_false_positive(self):
        n = {"AA:BB:CC:58:73:EE": "192.168.1.5"}  # different tail-2 prefix? same
        mac, _, conf = ethmatch.match_eth("82:67:0E:58:73:EF", n)
        self.assertEqual((mac, conf), ("AA:BB:CC:58:73:EE", "near-1~vap"))
