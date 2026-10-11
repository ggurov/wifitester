import tempfile
import unittest
from pathlib import Path

from wifitester import config


def write_cfg(text):
    d = Path(tempfile.mkdtemp())
    p = d / "config.toml"
    p.write_text(text, encoding="utf-8")
    return p


VALID = """
[tester]
interface = "wlan1"

[probe]
count = 3

[[ap]]
ssid = "home"
psk = "secret"
expected_bssids = ["aa:aa:aa:aa:aa:01"]

[[ap]]
ssid = "open"
open = true
"""


class TestConfig(unittest.TestCase):
    def test_valid(self):
        cfg, warns = config.load(write_cfg(VALID))
        self.assertEqual(cfg.interface, "wlan1")
        self.assertEqual(cfg.probe_count, 3)
        self.assertEqual(len(cfg.aps), 2)
        self.assertEqual(cfg.aps[0].expected_bssids,
                         ["AA:AA:AA:AA:AA:01"])  # normalized upper
        self.assertEqual(warns, [])

    def test_missing_file(self):
        with self.assertRaises(config.ConfigError):
            config.load("/nonexistent/config.toml")

    def test_no_aps(self):
        with self.assertRaises(config.ConfigError):
            config.load(write_cfg("[tester]\ninterface='wlan0'\n"))

    def test_bad_auth_probe(self):
        with self.assertRaises(config.ConfigError):
            config.load(write_cfg(VALID + '\n[scan]\nauth_probe = "wild"\n'))

    def test_bad_bssid(self):
        with self.assertRaises(config.ConfigError):
            config.load(write_cfg(VALID.replace(
                '"aa:aa:aa:aa:aa:01"', '"not-a-mac"')))

    def test_missing_psk_warns(self):
        cfg, warns = config.load(write_cfg(
            '[[ap]]\nssid = "home"\n'))
        self.assertEqual(len(cfg.aps), 1)
        self.assertTrue(any("no psk" in w for w in warns))

    def test_bad_toml(self):
        with self.assertRaises(config.ConfigError):
            config.load(write_cfg("this is not toml ]["))

    def test_psk_file_read(self):
        d = Path(tempfile.mkdtemp())
        pf = d / "psk"
        pf.write_text("hunter2\n", encoding="utf-8")
        cfg, _ = config.load(write_cfg(
            f'[[ap]]\nssid = "home"\npsk_file = "{pf}"\n'))
        self.assertEqual(config._read_psk(cfg.aps[0]), "hunter2")


if __name__ == "__main__":
    unittest.main()
