"""Thin wrappers around nmcli / iw / ip. Every external call funnels through
run() so tests can monkeypatch one seam."""

import ipaddress
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


def wifi_interfaces():
    """All wlan interface names currently present (sysfs enumeration)."""
    import glob
    return sorted(p.rsplit("/", 1)[-1]
                  for p in glob.glob("/sys/class/net/wlan*"))


def wifi_connection_map():
    """{wifi device: active connection profile name} (empty/"" when
    disconnected). One `nmcli dev status` call for all devices."""
    out = run(["nmcli", "-t", "-f", "DEVICE,TYPE,CONNECTION", "dev",
               "status"], timeout=15, check=False).stdout or ""
    devs = {}
    for line in out.splitlines():
        f = line.split(":", 2)
        if len(f) == 3 and f[1] == "wifi" and f[0]:
            devs[f[0]] = f[2]
    return devs


def iface_mac(iface):
    """Lowercase MAC of an interface, or None."""
    out = run(["cat", f"/sys/class/net/{iface}/address"], timeout=10,
              check=False).stdout
    mac = (out or "").strip().lower()
    return mac if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac) else None


def usb_reset_radio(iface):
    """Power-cycle a USB wifi adapter by de-authorizing and re-authorizing
    its USB device (forces driver + firmware re-init). The interface name
    may change after this; callers must re-enumerate."""
    dev = run(["readlink", "-f", f"/sys/class/net/{iface}/device"],
              timeout=10, check=False).stdout.strip()
    if "/usb" not in dev or not re.search(r":\d+\.\d+$", dev):
        raise RuntimeError(f"{iface} is not a USB device ({dev or 'gone'})")
    parent = re.sub(r":\d+\.\d+$", "", dev)
    auth = f"{parent}/authorized"
    run(["sh", "-c", f"echo 0 > '{auth}' && sleep 2 && echo 1 > '{auth}'"],
        timeout=20, check=False)
    time.sleep(4)


def dhcp4_info(iface):
    """Parsed DHCP4 lease info for an interface:
    {"ip", "lease_time", "expires"} (best effort; {} when absent)."""
    out = run(["nmcli", "-f", "DHCP4", "dev", "show", iface],
              timeout=15, check=False).stdout or ""
    info = {}
    m = re.search(r"dhcp_lease_time\s*=\s*(\d+)", out)
    if m:
        info["lease_time"] = int(m.group(1))
    m = re.search(r"expiry\s*=\s*(\d+)", out)
    if m:
        info["expires"] = int(m.group(1))
    m = re.search(r"ip_address\s*=\s*(\d+\.\d+\.\d+\.\d+)", out)
    if m:
        info["ip"] = m.group(1)
    return info


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


def iface_cidr(iface):
    """First IPv4 address/prefix on iface, e.g. '192.168.1.252/24'."""
    out = run(["ip", "-j", "-4", "addr", "show", "dev", iface],
              timeout=10, check=False).stdout
    try:
        for ifc in json.loads(out):
            for a in ifc.get("addr_info", []):
                return f"{a['local']}/{a['prefixlen']}"
    except json.JSONDecodeError:
        pass
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


def ensure_uplink_route():
    """True if the wired uplink has its connected subnet route, re-installing
    it when something removed it (a vanished /24 route blackholes LAN
    replies). Also True when there is no wired uplink or state is unreadable
    -- the guard must never fail its caller."""
    iface = wired_iface()
    if not iface:
        return True
    out = run(["ip", "-j", "-4", "addr", "show", "dev", iface],
              timeout=10, check=False).stdout
    try:
        infos = json.loads(out or "[]")
    except ValueError:
        return True
    info = next((a for d in infos for a in d.get("addr_info", [])), None)
    if not info or not info.get("local"):
        return True
    net = ipaddress.ip_network(f"{info['local']}/{info['prefixlen']}",
                               strict=False)
    if f"{net} dev {iface}" in (run(["ip", "route"], timeout=10,
                                    check=False).stdout or ""):
        return True
    run(["ip", "route", "replace", str(net), "dev", iface,
         "proto", "kernel", "src", info["local"]], timeout=10, check=False)
    log.warning("uplink %s was missing its %s route; re-installed",
                iface, net)
    return False


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


def profile_name(ssid, iface=None, primary_iface=None):
    """Profile for (ssid, iface). The primary interface keeps the legacy
    wt-<ssid> name; extra radios get wt-<ssid>-<iface>."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", ssid)
    if iface and primary_iface and iface != primary_iface:
        return f"{PROFILE_PREFIX}{safe}-{iface}"
    return f"{PROFILE_PREFIX}{safe}"


def ensure_profile(iface, ssid, psk, key_mgmt, static_ipv4="",
                   static_gateway="", primary_iface=None, route_metric=None,
                   band=None, never_default=False):
    """Create or refresh this iface's profile for ssid; autoconnect off.
    static_ipv4 "a.b.c.d/prefix" switches the profile to manual IPv4 (no
    DHCP); IPv6 is ignored either way. band "a"/"bg" pins the band so the
    pre-associate scan sweeps half the channels. never_default=yes keeps a
    default route OFF the interface (test radios must not carry traffic).
    Returns profile name."""
    name = profile_name(ssid, iface, primary_iface)
    if name not in list_profiles():
        run(["nmcli", "con", "add", "type", "wifi", "con-name", name,
             "ifname", iface, "ssid", ssid, "autoconnect", "no"], timeout=30)
    mods = ["nmcli", "con", "mod", name,
            "802-11-wireless.bssid", "",  # clear any leftover pin
            "802-11-wireless.band", band or "",  # "" = both bands
            "ipv6.method", "ignore",
            "ipv4.never-default", "yes" if never_default else "no"]
    if static_ipv4:
        mods += ["ipv4.method", "manual",
                 "ipv4.addresses", static_ipv4,
                 "ipv4.gateway", static_gateway,
                 "ipv4.dns", ""]
        if route_metric is not None:
            mods += ["ipv4.route-metric", str(route_metric)]
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


def chan_to_freq(chan):
    if not chan:
        return None
    if chan == 14:
        return 2484
    if chan < 14:
        return 2407 + 5 * chan
    if chan < 15:
        return None
    if chan < 190:
        return 5000 + 5 * chan
    return 5950 + 5 * chan


def iface_bands():
    """{iface: set(freq_mhz)} of enabled channels per wifi interface.
    Multiple interfaces can share a phy; each maps to its phy's set."""
    out = run(["iw", "dev"], timeout=15).stdout
    iface_phy = {}
    phy = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("phy#"):
            phy = s[4:]
        elif s.startswith("Interface "):
            iface_phy[s[10:].strip()] = phy
    out = run(["iw", "list"], timeout=30).stdout
    phy_freqs = {}
    cur = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Wiphy phy"):
            cur = s[9:]
        elif cur and s.startswith("* ") and "MHz" in s:
            if "(disabled" in s:
                continue
            m = re.match(r"\*\s*(\d+(?:\.\d+)?)\s*MHz", s)
            if m:
                phy_freqs.setdefault(cur, set()).add(int(float(m.group(1))))
    res = {}
    for iface, phy in iface_phy.items():
        res[iface] = phy_freqs.get(phy, set())
    return res


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


# --------------------------------------------------------------------------
# LAN neighbor discovery (ethernet side, does not touch the test radio)

def lan_hosts(cidr):
    """All usable host IPs of a network like 192.168.1.248/24."""
    import ipaddress
    net = ipaddress.ip_interface(cidr).network
    hosts = [str(h) for h in net.hosts()]
    if not hosts:  # /32 or /31 edge cases
        hosts = [str(net.network_address)]
    return hosts


def lan_sweep(hosts, iface, timeout_s=1.0, workers=64):
    """Ping each host in parallel through iface, then read the kernel ARP
    table. Returns {mac: ip} for hosts that answered. Does not touch wifi."""
    from concurrent.futures import ThreadPoolExecutor

    def ping(ip):
        try:
            subprocess.run(["ping", "-n", "-c", "1", "-W", "1",
                            "-I", iface, ip],
                           capture_output=True, timeout=timeout_s + 2)
        except subprocess.TimeoutExpired:
            pass

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(ping, hosts))
    return neighbor_table(iface)


def neighbor_table(iface):
    """{mac: ip} currently in the kernel neighbor table for iface."""
    out = run(["ip", "-j", "neigh", "show", "dev", iface],
              timeout=10, check=False).stdout
    res = {}
    try:
        for e in json.loads(out):
            if e.get("lladdr"):
                res[e["lladdr"].upper()] = e["dst"]
    except json.JSONDecodeError:
        pass
    return res
