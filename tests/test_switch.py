import tempfile
import unittest
from pathlib import Path

from wifitester import switch
from wifitester.store import Store

SWITCHING = """aruba# show ethernet-switching table | no-more

Ethernet-switching table: 2 unicast entries
Vlan           MAC address        Type         Age Interfaces
default           24:4b:fe:62:70:35 Learn          0 ge-0/0/24.0
default           24:de:c6:c3:db:ba Learn          0 ge-0/0/36.0
default           78:67:0e:58:73:ee Learn          0 ge-0/0/2.0
default           ff:ff:ff:ff:ff:ff Flood          - ge-0/0/2.0
aruba# show clients"""

LLDP = """Local Interface    Parent Interface    Chassis Id          Port info          System Name
ge-0/0/24.0        -                   24:4b:fe:62:70:35   eth3               RT-AX89U
ge-0/0/36.0        -                   24:de:c6:c3:db:ba   bond0              aruba
ge-0/0/39.0        -                   d4:5d:64:0d:b2:00   eth0               RT-AC86U
ge-0/0/8.0         -                   8c:c1:21:a3:42:1e   8c:c1:21:a3:42:1e
ge-0/0/2.0         -                   DESKTOP-SSGA38O     04:42:1a:2c:0f:7a
{master:0}
root@switch2>"""


class TestSwitchParsers(unittest.TestCase):
    def test_parse_switching_table(self):
        m = switch._parse_switching_table(SWITCHING)
        self.assertEqual(m["24:4b:fe:62:70:35"]["port"], "ge-0/0/24.0")
        self.assertEqual(m["24:de:c6:c3:db:ba"]["vlan"], "default")
        self.assertNotIn("ff:ff:ff:ff:ff:ff", m)  # flood rows skipped

    def test_parse_lldp_neighbors(self):
        m = switch._parse_lldp_neighbors(LLDP)
        self.assertEqual(m["24:4b:fe:62:70:35"]["system_name"], "RT-AX89U")
        self.assertEqual(m["24:de:c6:c3:db:ba"]["local_port"], "ge-0/0/36.0")
        self.assertEqual(m["24:de:c6:c3:db:ba"]["lldp_port"], "bond0")
        self.assertIsNone(m["8c:c1:21:a3:42:1e"]["system_name"])
        # non-MAC chassis id (host name) still captured
        self.assertIn("desktop-ssga38o", m)

    def test_creds_missing(self):
        import unittest.mock as mock
        with mock.patch.object(switch, "CREDS_FILE", "/nonexistent"):
            self.assertEqual(switch.load_switch_creds(), {})


class TestSwitchStore(unittest.TestCase):
    def setUp(self):
        self.st = Store(Path(tempfile.mkdtemp()))

    def tearDown(self):
        self.st.close()

    def test_upsert_roundtrip(self):
        self.st.upsert_switch_ports([
            {"mac": "24:de:c6:c3:db:ba", "port": "ge-0/0/36.0",
             "vlan": "default", "lldp_port": "bond0",
             "lldp_system": "aruba"}])
        self.st.upsert_switch_ports([
            {"mac": "24:de:c6:c3:db:ba", "port": "ge-0/0/36.0",
             "vlan": "default", "lldp_port": "bond0.100",
             "lldp_system": "aruba"}])
        rows = self.st.switch_ports()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["port"], "ge-0/0/36.0")
        self.assertEqual(r["lldp_port"], "bond0.100")
        self.assertEqual(r["lldp_system"], "aruba")


MEDIA = """Physical interface: ge-0/0/36, Enabled, Physical link is Up
  Input rate     : 504 bps (0 pps)
  Output rate    : 5168 bps (9 pps)
  Input bytes: 88091653, Input packets: 824359, Output bytes: 1123332400,
  Output packets: 5313888
Physical interface: ge-0/0/39, Enabled, Physical link is Down
  Input rate     : 0 bps (0 pps)
  Output rate    : 0 bps (0 pps)
  Input bytes: 12,345,678, Output packets: 42
{master:0}"""


class TestPortMediaParser(unittest.TestCase):
    def test_parse_port_media(self):
        t = switch._parse_port_media(MEDIA)
        self.assertEqual(set(t), {"ge-0/0/36", "ge-0/0/39"})
        p36 = t["ge-0/0/36"]
        self.assertEqual(p36["link"], "Up")
        self.assertEqual(p36["in_bps"], 504)
        self.assertEqual(p36["out_bps"], 5168)
        self.assertEqual(p36["in_bytes"], 88091653)
        self.assertEqual(p36["out_bytes"], 1123332400)
        p39 = t["ge-0/0/39"]
        self.assertEqual(p39["link"], "Down")
        self.assertEqual(p39["in_bytes"], 12345678)  # commas stripped


if __name__ == "__main__":
    unittest.main()
