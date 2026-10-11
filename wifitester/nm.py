"""Thin wrappers around nmcli / iw / ip. Every external call funnels through
run() so tests can monkeypatch one seam."""

import json
import logging
import re
import subprocess

log = logging.getLogger("wifitester.nm")


class CommandError(RuntimeError):
    """External command failed."""

    def __init__(self, cmd, returncode, stderr, timeout=False):
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = (stderr or "").strip()
        self.timeout = timeout
        super().__init__(f"{'timeout: ' if timeout else ''}{' '.join(cmd)} "
                         f"(rc={returncode}): {self.stderr[:200]}")


def run(cmd, timeout=30, check=True):
    """Run cmd (argv list), return CompletedProcess. Raises CommandError."""
    log.debug("exec: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise CommandError(cmd, -1, exc.stderr or "", timeout=True) from exc
    if check and proc.returncode != 0:
        raise CommandError(cmd, proc.returncode, proc.stderr)
    return proc


def split_nmcli(line):
    """Split one nmcli -t row on unescaped colons; \\ escapes any char."""
    parts, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def parse_nmcli_tsv(out, fields):
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        values = split_nmcli(line)
        rows.append({f: (values[i] if i < len(values) else "")
                     for i, f in enumerate(fields)})
    return rows


# --------------------------------------------------------------------------
# nmcli: device / connection state

def nmcli_version():
    return run(["nmcli", "--version"], timeout=10).stdout.strip()


def list_devices():
    out = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "dev",
               "status"], timeout=15).stdout
    return parse_nmcli_tsv(out, ["device", "type", "state", "connection"])


def wifi_interface_present(iface):
    return any(d["device"] == iface and d["type"] == "wifi"
               for d in list_devices())


def wired_uplink_present():
    """True if some non-wireless, non-loopback device is connected."""
    for d in list_devices():
        if d["type"] in ("loopback", "wifi", "wifi-p2p"):
            continue
        if d["state"].startswith("connected"):
            return True
    return False


def wired_iface():
    """First connected non-wireless device name, or None."""
    for d in list_devices():
        if d["type"] in ("loopback", "wifi", "wifi-p2p"):
            continue
        if d["state"].startswith("connected"):
            return d["device"]
    return None


def addr_assigned(ip):
    """True if ip is configured on any local interface."""
    out = run(["ip", "-j", "-4", "addr"], timeout=10, check=False).stdout
    try:
        for ifc in json.loads(out):
            for a in ifc.get("addr_info", []):
                if a.get("local") == ip:
                    return True
    except json.JSONDecodeError:
        pass
    return False


def ip_in_use(ip, iface, timeout_s=3):
    """True if something on the L2 segment answers ARP for ip (conflict check)."""
    proc = run(["arping", "-c", "2", "-w", str(max(1, int(timeout_s))),
                "-I", iface, ip],
               timeout=timeout_s + 5, check=False)
    return proc.returncode == 0


def device_connected(iface):
    out = run(["nmcli", "-t", "-f", "GENERAL.STATE", "dev", "show", iface],
              timeout=15).stdout
    state = out.strip().split(":", 1)[-1]
    return state.startswith("100")


def current_connection(iface):
    """Active connection name on iface, or '' if none."""
    out = run(["nmcli", "-t", "-f", "GENERAL.CONNECTION", "dev", "show",
               iface], timeout=15).stdout
    return out.strip().split(":", 1)[-1] if out.strip() else ""


def list_profiles():
    out = run(["nmcli", "-t", "-f", "NAME", "con", "show"], timeout=15).stdout
    return [line for line in out.splitlines() if line.strip()]


# --------------------------------------------------------------------------
# nmcli: scanning

def scan_networks(iface, rescan=True):
    """Return dicts: ssid, bssid, chan, freq_mhz, signal, security."""
    fields = ["SSID", "BSSID", "CHAN", "FREQ", "SIGNAL", "SECURITY"]
    args = ["nmcli", "-t", "-f", ",".join(fields), "dev", "wifi", "list",
            "ifname", iface]
    if rescan:
        try:
            out = run(args + ["--rescan", "yes"], timeout=45).stdout
        except CommandError as exc:  # rescan not authorized / busy: stale list
            log.warning("rescan failed (%s); using cached scan", exc.stderr[:80])
            out = run(args, timeout=45).stdout
    else:
        out = run(args, timeout=45).stdout

    nets = []
    for row in parse_nmcli_tsv(out, fields):
        freq = re.match(r"(\d+)", row["FREQ"])
        nets.append({
            "ssid": row["SSID"],
            "bssid": row["BSSID"].upper(),
            "chan": int(row["CHAN"]) if row["CHAN"].isdigit() else None,
            "freq_mhz": int(freq.group(1)) if freq else None,
            "signal": int(row["SIGNAL"]) if row["SIGNAL"].lstrip("-").isdigit() else None,
            "security": row["SECURITY"].strip(),
        })
    return nets


# --------------------------------------------------------------------------
# nmcli: profile management (all tester profiles are prefixed wt-)

PROFILE_PREFIX = "wt-"


def profile_name(ssid):
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", ssid)
    return f"{PROFILE_PREFIX}{safe}"


def ensure_profile(iface, ssid, psk, key_mgmt, static_ipv4="", static_gateway=""):
    """Create or refresh profile <prefix><safe(ssid)>; autoconnect off.
    static_ipv4 "a.b.c.d/prefix" switches the profile to manual IPv4 (no
    DHCP); IPv6 is ignored either way. Returns profile name."""
    name = profile_name(ssid)
    if name not in list_profiles():
        run(["nmcli", "con", "add", "type", "wifi", "con-name", name,
             "ifname", iface, "ssid", ssid, "autoconnect", "no"], timeout=30)
    mods = ["nmcli", "con", "mod", name,
            "802-11-wireless.bssid", "",  # clear any leftover pin
            "ipv6.method", "ignore"]
    if static_ipv4:
        mods += ["ipv4.method", "manual",
                 "ipv4.addresses", static_ipv4,
                 "ipv4.gateway", static_gateway,
                 "ipv4.dns", ""]
    else:
        mods += ["ipv4.method", "auto",
                 "ipv4.addresses", "",
                 "ipv4.gateway", ""]
    if key_mgmt != "none":
        mods += ["802-11-wireless-security.key-mgmt", key_mgmt]
        if psk is not None:
            mods += ["802-11-wireless-security.psk", psk]
    run(mods, timeout=30)
    return name


def set_profile_bssid(name, bssid):
    run(["nmcli", "con", "mod", name, "802-11-wireless.bssid", bssid],
        timeout=15)


def up_profile(name, timeout_s=45):
    """Activate profile; raises CommandError on failure/timeout."""
    run(["nmcli", "con", "up", name], timeout=timeout_s)


def down_profile(name):
    try:
        run(["nmcli", "con", "down", name], timeout=20, check=False)
    except CommandError as exc:
        log.debug("down %s: %s", name, exc)


def disconnect_device(iface):
    run(["nmcli", "dev", "disconnect", iface], timeout=20, check=False)


def up_connection(name, timeout_s=60):
    run(["nmcli", "con", "up", name], timeout=timeout_s)


# --------------------------------------------------------------------------
# iw / ip

def iw_link(iface):
    """{'bssid':..., 'signal_dbm':...} for the current association, else {}."""
    out = run(["iw", "dev", iface, "link"], timeout=15, check=False).stdout
    res = {}
    m = re.search(r"Connected to ([0-9a-fA-F:]{17})", out)
    if m:
        res["bssid"] = m.group(1).upper()
    m = re.search(r"signal:\s*(-?\d+)\s*dBm", out)
    if m:
        res["signal_dbm"] = int(m.group(1))
    m = re.search(r"freq:\s*(\d+)", out)
    if m:
        res["freq_mhz"] = int(m.group(1))
        res["chan"] = freq_to_chan(res["freq_mhz"])
    return res


def freq_to_chan(freq_mhz):
    if not freq_mhz:
        return None
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if freq_mhz >= 5925:  # 6 GHz: ch1=5955, step 5
        return (freq_mhz - 5950) // 5
    if 5000 < freq_mhz < 6000:
        return (freq_mhz - 5000) // 5
    return None


def default_gateway(iface):
    out = run(["ip", "-j", "route", "show", "default", "dev", iface],
              timeout=15, check=False).stdout
    try:
        routes = json.loads(out)
    except json.JSONDecodeError:
        return None
    return routes[0].get("gateway") if routes else None


def key_mgmt_for(security):
    """Map an nmcli SECURITY string to a key-mgmt value."""
    sec = (security or "").upper()
    if not sec:
        return "none"
    if "SAE" in sec:
        return "sae"
    if "802.1X" in sec or "8021X" in sec:
        return "wpa-eap"
    return "wpa-psk"
