import tempfile
import unittest
from pathlib import Path

from wifitester import routers
from wifitester.store import Store

SHOW_APS = """aruba# show aps

1 Access Point
--------------
Name   IP Address      Mode    Spectrum  Clients  Type  Mesh Role  Zone  2.4 Channel  2.4 Power (dB)  2.4 Utilization (%)  2.4 Noise Floor (dBm)  5.0 Channel  5.0 Power (dB)  5.0 Utilization (%)  5.0 Noise Floor (dBm)  Need Antenna Config  From Port  Config Id  Config Csum  Ext SSID Active  Age
----   ----------      ----    --------  -------  ----  ---------  ----  -----------  --------------  -------------------  ---------------------  -----------  --------------  -------------------  ---------------------  -------------------  ---------  ---------  -----------  ---------------  ---
aruba  192.168.1.177*  access  disable   3        105   N/A        -     1+           22              28(good)             -93(good)              100+         22              0(good)              -93(good)              No                   none       0          49241        enable           4d:11h:36m:22s
aruba# show clients"""

SHOW_CLIENTS = """aruba# show clients
Client List
-----------
Name                  IP Address     MAC Address        OS  Network      Access Point  Channel  Type  Role         Signal    Speed (mbps)
----                  ----------     -----------        --  ----------   ------------  -------  ----  ----         ------    ------------
                      192.168.1.248  dc:a6:32:b6:8a:9f      77fast5      aruba         1+       GN    77fast5      21(good)  6(poor)
Nest-Thermostat-97EF  192.168.1.186  20:1f:3b:dd:97:ef      Cisco144454  aruba         1+       GN    Cisco144454  36(good)  65(good)
                      192.168.1.156  44:3d:54:d1:31:e8      77fast5      aruba         1+       GN    77fast5      25(good)  52(good)
Number of Clients   :3
Info timestamp      :387471
aruba#"""


class TestArubaParsers(unittest.TestCase):
    def test_parse_show_aps(self):
        aps = routers.parse_show_aps(SHOW_APS)
        self.assertEqual(len(aps), 1)
        ap = aps[0]
        self.assertEqual(ap["name"], "aruba")
        self.assertEqual(ap["ip"], "192.168.1.177")
        self.assertEqual(ap["clients"], 3)
        self.assertEqual(ap["type"], "105")
        self.assertEqual(ap["chan_24"], "1+")
        self.assertEqual(ap["chan_50"], "100+")
        self.assertEqual(ap["util_24"], "28")
        self.assertEqual(ap["age"], "4d:11h:36m:22s")

    def test_parse_show_clients(self):
        c = routers.parse_show_clients(SHOW_CLIENTS)
        self.assertEqual(c["total"], 3)
        self.assertEqual(c["per_ssid"], {"77fast5": 2, "Cisco144454": 1})

    def test_parse_empty(self):
        self.assertEqual(routers.parse_show_aps("aruba#"), [])
        c = routers.parse_show_clients("aruba#")
        self.assertEqual(c["total"], 0)
        self.assertEqual(c["per_ssid"], {})

    def test_band_label(self):
        self.assertEqual(routers.band_label(None, 1), "2.4 GHz")
        self.assertEqual(routers.band_label(None, 11), "2.4 GHz")
        self.assertEqual(routers.band_label(None, 100), "5 GHz")
        self.assertEqual(routers.band_label(2462), "2.4 GHz")
        self.assertEqual(routers.band_label(6180), "6 GHz")
        self.assertIsNone(routers.band_label(None, None))

    def test_model_for(self):
        self.assertEqual(routers.model_for("78:67:0E:58:73:EE"),
                         "Verizon Fios CR1000A")
        self.assertIsNone(routers.model_for("00:00:5e:00:53:aa"))
        self.assertIsNone(routers.model_for(None))


class TestApInventoryStore(unittest.TestCase):
    def setUp(self):
        self.st = Store(Path(tempfile.mkdtemp()))

    def tearDown(self):
        self.st.close()

    def test_upsert_roundtrip(self):
        row = {"unit_key": "aruba-192.168.1.177", "source": "aruba-ssh",
               "name": "aruba", "model": "Aruba AP-105",
               "ip": "192.168.1.177", "wired_mac": None,
               "uptime": "4d", "clients": 3,
               "radios": [{"band": "2.4 GHz", "chan": "1+", "util": "28"}]}
        self.st.upsert_ap_inventory([row])
        self.st.upsert_ap_inventory([dict(row, clients=5, uptime="5d")])
        rows = self.st.ap_inventory()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["clients"], 5)
        self.assertEqual(r["uptime"], "5d")
        self.assertEqual(r["model"], "Aruba AP-105")
        import json
        self.assertEqual(json.loads(r["radios_json"])[0]["chan"], "1+")


class TestAsusInventory(unittest.TestCase):
    def test_compact_uptime(self):
        self.assertEqual(routers.compact_uptime(0), "-")
        self.assertEqual(routers.compact_uptime(3600 * 4 * 24 + 7200),
                         "4d 2h")
        self.assertEqual(routers.compact_uptime(3600), "1h 0m")
        self.assertEqual(routers.compact_uptime("4d:11h:36m:22s"),
                         "4d 11h 36m")
        self.assertEqual(routers.compact_uptime("3h:22m:38s"), "3h 22m")
        self.assertEqual(routers.compact_uptime(None), "-")

    def test_asus_ssh_inventory_parse(self):
        import unittest.mock as mock
        text = ("P=RT-AC86U\nO=RT-AC86U\nF=3.0.0.4.386\nU=424580\n"
                "R0=1,77fast5,D4:5D:64:0D:B2:00,8,eth5,3\n"
                "R1=1,77fast5,D4:5D:64:0D:B2:04,157,eth6,0\n"
                "R2=,,\nR3=,,\n")

        class FakeClient:
            def set_missing_host_key_policy(self, p): pass
            def connect(self, *a, **k): pass
            def exec_command(self, cmd, timeout=None):
                out = type("O", (), {"read": lambda s: text.encode()})()
                return None, out, None
            def close(self): pass

        with mock.patch.object(paramiko_stub(), "SSHClient", FakeClient), \
             mock.patch.object(paramiko_stub(), "AutoAddPolicy", lambda: None):
            inv = routers.asus_ssh_inventory("h", "admin", "pw")
        self.assertEqual(inv["model"], "RT-AC86U")
        self.assertEqual(inv["firmware"], "3.0.0.4.386")
        self.assertEqual(len(inv["radios"]), 2)
        r0 = inv["radios"][0]
        self.assertEqual(r0["bssid"], "D4:5D:64:0D:B2:00")
        self.assertEqual(r0["chan"], 8)
        self.assertTrue(r0["on"])
        self.assertEqual(r0["ifname"], "eth5")
        self.assertEqual(r0["clients"], 3)
        self.assertEqual(inv["radios"][1]["clients"], 0)
        self.assertEqual(len(inv["radios"]), 2)  # empty radios skipped


def paramiko_stub():
    import paramiko
    return paramiko


FIOS_LEASES = """addROD("dump_dhcp_leases", [ ['LAPTOP-F4GRCRIT','192.168.1.232','50:7B:9D:D4:43:AF','72536'],['wifitester','192.168.1.248','DC:A6:32:B6:8A:9F','8198'],['aruba','192.168.1.177','24:DE:C6:C3:DB:BA','6341'],['','','',''] ]);"""


class TestFiosLeases(unittest.TestCase):
    def test_parse(self):
        rows = routers.fios_leases_parse(FIOS_LEASES)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["hostname"], "LAPTOP-F4GRCRIT")
        self.assertEqual(rows[0]["ip"], "192.168.1.232")
        self.assertEqual(rows[1]["hostname"], "wifitester")
        self.assertEqual(rows[2]["mac"], "24:de:c6:c3:db:ba".lower())


class TestMissingPins(unittest.TestCase):
    """Every radio a unit reports ON for a configured SSID must have its
    BSSID pinned in that SSID's expected_bssids -- unpinned radios are
    invisible to the probe sweep (the .220's 2.4 GHz gap)."""

    def test_all_on_air_bssids_pinned(self):
        # live fixture: the RT-AX89X at .220 reports BOTH radios on
        radios = [
            {"radio": 0, "on": True, "ssid": "77fast5",
             "bssid": "24:4B:FE:62:70:30"},   # 2.4 GHz
            {"radio": 1, "on": True, "ssid": "77fast5",
             "bssid": "24:4B:FE:62:70:34"},   # 5 GHz
        ]
        pins = {"77fast5": [
            "D4:5D:64:10:43:FC", "78:67:0E:58:73:EF", "78:67:0E:58:73:F0",
            "D4:5D:64:0D:B2:00", "24:4B:FE:62:70:34", "D4:5D:64:0D:B2:04"],
            "Cisco144454": [
            "D4:5D:64:10:43:F8", "82:67:0E:58:73:EF",
            "24:DE:C6:BD:BB:A1", "24:DE:C6:BD:BB:A9",
            "24:DE:C6:BD:BB:A0", "24:DE:C6:BD:BB:A8"]}
        missing = routers.missing_pins(pins, radios)
        # red state: detects the unpinned 2.4 GHz radio of the .220
        self.assertEqual(missing, {"77fast5": ["24:4B:FE:62:70:30"]})
        # after pinning, coverage is complete
        pins["77fast5"].append("24:4B:FE:62:70:30")
        self.assertEqual(routers.missing_pins(pins, radios), {})


if __name__ == "__main__":
    unittest.main()
