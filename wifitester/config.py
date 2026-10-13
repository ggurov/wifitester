"""TOML config loading + validation (stdlib tomllib, read-only)."""

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


class ConfigError(ValueError):
    pass


@dataclass
class APConfig:
    ssid: str
    psk: str | None = None
    psk_file: str | None = None
    expected_bssids: list[str] = field(default_factory=list)
    open: bool = False
    enabled: bool = True


@dataclass
class Config:
    interface: str = "wlan0"       # primary radio: scans + legacy profile names
    interfaces: list[str] = field(default_factory=lambda: ["wlan0"])
    # auto_radios: interfaces = "auto" -> hot-plug discovery of wifi radios
    # (join on plug-in, leave on removal); extras grab a DHCP lease once and
    # reuse the cached address until the lease expires.
    auto_radios: bool = False
    # extra radios probe nodes in parallel; 2.4 GHz-only sticks must not be
    # listed as the primary (scans need band coverage)
    cycle_interval_s: float = 5
    settle_s: float = 1.5
    connect_timeout_s: float = 15
    restore_connection: bool = True
    require_wired_uplink: bool = True
    # All APs bridge to the same LAN: static addressing skips DHCP entirely.
    static_ipv4: str = ""          # e.g. "192.168.1.248/24"; "" = DHCP
    static_gateway: str = ""       # optional default route for the test iface
    lan_sweep_interval_s: float = 300   # ARP/ping sweep for LAN MACs; 0=off

    probe_count: int = 3
    probe_interval_s: float = 0.4
    probe_timeout_s: float = 1.0
    internet_target: str = "1.1.1.1"

    scan_interval_s: float = 600
    scan_rescan: bool = True
    auth_probe: str = "mismatch_only"  # never | mismatch_only | all
    open_assoc: bool = True
    auth_timeout_s: float = 25

    web_host: str = "0.0.0.0"
    web_port: int = 8787

    aps: list[APConfig] = field(default_factory=list)


def _read_psk(ap: APConfig) -> str | None:
    if ap.psk is not None:
        return ap.psk
    if ap.psk_file:
        return Path(ap.psk_file).read_text(encoding="utf-8").splitlines()[0].strip()
    return None


def _get(d, key, cast, err, default=None, required=False):
    if key not in d:
        if required:
            err.append(f"missing required key: {key}")
        return default
    try:
        return cast(d[key])
    except (TypeError, ValueError):
        err.append(f"{key}: expected {cast.__name__}, got {d[key]!r}")
        return default


def load(path) -> tuple[Config, list[str]]:
    """Returns (config, warnings). Raises ConfigError on fatal problems."""
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"config not found: {path}")
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

    errors, warns = [], []
    cfg = Config()

    t = raw.get("tester", {})
    cfg.interface = str(_get(t, "interface", str, errors, cfg.interface))
    raw_ifaces = raw.get("tester", {}).get("interfaces")
    if isinstance(raw_ifaces, str) and raw_ifaces.strip().lower() == "auto":
        cfg.auto_radios = True
        cfg.interfaces = [cfg.interface]
    else:
        ifaces = _get(t, "interfaces", lambda v: [str(x) for x in v], errors,
                      None)
        if ifaces:
            cfg.interfaces = ifaces
    if cfg.interface not in cfg.interfaces:
        cfg.interfaces.insert(0, cfg.interface)
    seen_i = []
    for i in cfg.interfaces:
        if i not in seen_i:
            seen_i.append(i)
    cfg.interfaces = seen_i
    cfg.cycle_interval_s = float(_get(t, "cycle_interval_s", float, errors, cfg.cycle_interval_s))
    cfg.settle_s = float(_get(t, "settle_s", float, errors, cfg.settle_s))
    cfg.connect_timeout_s = float(_get(t, "connect_timeout_s", float, errors, cfg.connect_timeout_s))
    cfg.restore_connection = bool(_get(t, "restore_connection", bool, errors, cfg.restore_connection))
    cfg.require_wired_uplink = bool(_get(t, "require_wired_uplink", bool, errors, cfg.require_wired_uplink))
    cfg.static_ipv4 = str(_get(t, "static_ipv4", str, errors, cfg.static_ipv4))
    cfg.static_gateway = str(_get(t, "static_gateway", str, errors, cfg.static_gateway))
    cfg.lan_sweep_interval_s = float(_get(t, "lan_sweep_interval_s", float, errors, cfg.lan_sweep_interval_s))
    if cfg.lan_sweep_interval_s < 0:
        errors.append("tester.lan_sweep_interval_s must be >= 0 (0 disables)")
    if cfg.static_ipv4 and not re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$",
                                        cfg.static_ipv4):
        errors.append(f"tester.static_ipv4 must be ip/prefix, "
                      f"got {cfg.static_ipv4!r}")
    if cfg.static_gateway and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$",
                                           cfg.static_gateway):
        errors.append(f"tester.static_gateway must be an IPv4 address, "
                      f"got {cfg.static_gateway!r}")

    p = raw.get("probe", {})
    cfg.probe_count = int(_get(p, "count", int, errors, cfg.probe_count))
    cfg.probe_interval_s = float(_get(p, "interval_s", float, errors, cfg.probe_interval_s))
    cfg.probe_timeout_s = float(_get(p, "timeout_s", float, errors, cfg.probe_timeout_s))
    cfg.internet_target = str(_get(p, "internet_target", str, errors, cfg.internet_target))

    s = raw.get("scan", {})
    cfg.scan_interval_s = float(_get(s, "interval_s", float, errors, cfg.scan_interval_s))
    cfg.scan_rescan = bool(_get(s, "rescan", bool, errors, cfg.scan_rescan))
    cfg.auth_probe = str(_get(s, "auth_probe", str, errors, cfg.auth_probe))
    cfg.open_assoc = bool(_get(s, "open_assoc", bool, errors, cfg.open_assoc))
    cfg.auth_timeout_s = float(_get(s, "auth_timeout_s", float, errors, cfg.auth_timeout_s))

    aps_raw = raw.get("ap", [])
    if not isinstance(aps_raw, list) or not aps_raw:
        errors.append("at least one [[ap]] block is required")
        aps_raw = []
    seen = set()
    for i, a in enumerate(aps_raw):
        ssid = str(_get(a, "ssid", str, errors, "", True))
        if not ssid:
            continue
        if ssid in seen:
            errors.append(f"[[ap]] #{i}: duplicate ssid {ssid!r}")
            continue
        seen.add(ssid)
        ap = APConfig(
            ssid=ssid,
            psk=a.get("psk"),
            psk_file=a.get("psk_file"),
            open=bool(a.get("open", False)),
            enabled=bool(a.get("enabled", True)),
        )
        bssids = a.get("expected_bssids", [])
        if not isinstance(bssids, list):
            errors.append(f"[[ap]] {ssid}: expected_bssids must be a list")
            bssids = []
        for b in bssids:
            if not MAC_RE.match(str(b)):
                errors.append(f"[[ap]] {ssid}: bad bssid {b!r}")
            else:
                ap.expected_bssids.append(str(b).upper())
        if ap.enabled and not ap.open:
            if ap.psk is None and ap.psk_file is None:
                warns.append(f"[[ap]] {ssid}: no psk/psk_file -- probe visits will "
                             "skip it and scans mark it KNOWN_UNVERIFIED")
            else:
                try:
                    _read_psk(ap)
                except OSError as exc:
                    warns.append(f"[[ap]] {ssid}: psk unreadable ({exc})")
        cfg.aps.append(ap)

    w = raw.get("web", {})
    cfg.web_host = str(_get(w, "host", str, errors, cfg.web_host))
    cfg.web_port = int(_get(w, "port", int, errors, cfg.web_port))

    if cfg.auth_probe not in ("never", "mismatch_only", "all"):
        errors.append(f"scan.auth_probe must be never|mismatch_only|all, "
                      f"got {cfg.auth_probe!r}")
    if cfg.cycle_interval_s < 2:
        warns.append(f"cycle_interval_s={cfg.cycle_interval_s} leaves no gap "
                     "between sweeps; association time alone paces the cycle")
    if cfg.probe_count < 1:
        errors.append("probe.count must be >= 1")

    if errors:
        raise ConfigError("; ".join(errors))
    return cfg, warns
