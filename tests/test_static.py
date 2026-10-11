import unittest
from unittest import mock

from wifitester import config, nm
from wifitester.store import Store


class TestStaticConfig(unittest.TestCase):
    def test_static_defaults_empty(self):
        cfg, warns = config.load(_cfg("[[ap]]\nssid='x'\npsk='p'\n"))
        self.assertEqual(cfg.static_ipv4, "")
        self.assertEqual(cfg.static_gateway, "")
        self.assertEqual(warns, [])

    def test_static_valid(self):
        cfg, warns = config.load(_cfg(
            "[tester]\nstatic_ipv4='192.168.1.248/24'\n"
            "static_gateway='192.168.1.1'\n[[ap]]\nssid='x'\npsk='p'\n"))
        self.assertEqual(cfg.static_ipv4, "192.168.1.248/24")
        self.assertEqual(warns, [])

    def test_static_bad_cidr(self):
        with self.assertRaises(config.ConfigError):
            config.load(_cfg("[tester]\nstatic_ipv4='192.168.1.248'\n"))

    def test_static_bad_gateway(self):
        with self.assertRaises(config.ConfigError):
            config.load(_cfg("[tester]\nstatic_gateway='gateway'\n"))


def _cfg(text):
    import tempfile
    from pathlib import Path
    p = Path(tempfile.mkdtemp()) / "c.toml"
    p.write_text(text, encoding="utf-8")
    return p


class TestEnsureProfileMods(unittest.TestCase):
    def _capture(self):
        calls = []

        def fake_run(cmd, timeout=30, check=True):
            calls.append(cmd)

            class R:
                stdout = ""

            return R()

        return calls, fake_run

    def test_static_mods(self):
        calls, fake = self._capture()
        with mock.patch.object(nm, "run", fake), \
                mock.patch.object(nm, "list_profiles", lambda: ["wt-x"]):
            nm.ensure_profile("wlan0", "x", "psk", "wpa-psk",
                              "192.168.1.248/24", "192.168.1.1")
        mods = calls[-1]
        for expect in ("ipv4.method", "manual", "ipv4.addresses",
                       "192.168.1.248/24", "ipv4.gateway", "192.168.1.1",
                       "ipv6.method", "ignore"):
            self.assertIn(expect, mods)

    def test_dhcp_mods(self):
        calls, fake = self._capture()
        with mock.patch.object(nm, "run", fake), \
                mock.patch.object(nm, "list_profiles", lambda: ["wt-x"]):
            nm.ensure_profile("wlan0", "x", "psk", "wpa-psk")
        mods = calls[-1]
        self.assertIn("auto", mods)
        self.assertNotIn("manual", mods)


class TestLatestPerBssid(unittest.TestCase):
    def test_one_row_per_bssid(self):
        import tempfile
        from pathlib import Path
        st = Store(Path(tempfile.mkdtemp()))
        try:
            st.insert_visit({"ssid": "m", "bssid": "AA:00", "connect_ok": True,
                             "loss_pct": 0.0})
            st.insert_visit({"ssid": "m", "bssid": "AA:01", "connect_ok": True,
                             "loss_pct": 100.0})
            st.insert_visit({"ssid": "m", "bssid": "AA:00", "connect_ok": True,
                             "loss_pct": 50.0})
            rows = st.latest_visit_per_bssid(0)
            got = {r["bssid"]: r["loss_pct"] for r in rows}
            self.assertEqual(got, {"AA:00": 50.0, "AA:01": 100.0})
        finally:
            st.close()


if __name__ == "__main__":
    unittest.main()
