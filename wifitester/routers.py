"""Router/AP inventory knowledge shared by the web UI and the router poller.

Models are keyed by the first 3 MAC octets (OUI) of a unit's wired address --
the same address ethmatch resolves for each BSSID. Units broadcast both SSIDs
as VAPs, so one physical unit appears under several BSSIDs.
"""

import json
import re

MODEL_BY_OUI = {
    "78:67:0e": "Verizon Fios CR1000A",
    "24:4b:fe": "ASUS RT-AX89X",
    "24:de:c6": "Aruba AP-105",  # the single Aruba, 192.168.1.177
    "d4:5d:64": "ASUS RT-AC68U",  # .207/.218 mesh units (user-confirmed;
    #                                note: OUI registry says Aruba-HPE, but the
    #                                .207 box serves asuswrt and self-IDs RT-AC68U)
}


def model_for(mac):
    """Model string for a wired MAC (or None when unknown)."""
    if not mac:
        return None
    return MODEL_BY_OUI.get(mac[:8].lower())


def band_label(freq_mhz=None, chan=None):
    """Human band for a frequency or channel number ('2.4 GHz' etc.)."""
    f = freq_mhz
    if not f and chan:
        from . import nm
        f = nm.chan_to_freq(chan)
    if not f:
        return None
    f = int(f)
    if 5925 <= f <= 7125:
        return "6 GHz"
    if 4900 <= f < 5925:
        return "5 GHz"
    if 2400 <= f < 2500:
        return "2.4 GHz"
    return f"{f} MHz"


CREDS_FILE = "/home/pi/.wifitester/creds.json"


def asus_ssh_inventory(host, user, password, timeout=20):
    """Inventory from an ASUS (asuswrt) unit over SSH. Busybox ash with
    nvram; returns {"model", "firmware", "uptime_s", "radios": [
    {"radio", "on", "ssid", "bssid", "chan"}]}."""
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, username=user, password=password,
                look_for_keys=False, allow_agent=False, timeout=10)
    script = ("echo P=$(nvram get productid); echo O=$(nvram get odmpid); "
              "echo F=$(nvram get firmver).$(nvram get buildno); "
              "echo U=$(cut -d ' ' -f1 /proc/uptime); "
              "for r in 0 1 2 3; do echo R$r=$(nvram get wl$r\\_radio),"
              "$(nvram get wl$r\\_ssid),$(nvram get wl$r\\_hwaddr),"
              "$(nvram get wl$r\\_channel),$(nvram get wl$r\\_ifname),"
              "$(wl -i $(nvram get wl$r\\_ifname) assoclist 2>/dev/null "
              "| grep -c ^assoclist); done")
    _, stdout, _ = cli.exec_command(script, timeout=timeout)
    text = stdout.read().decode(errors="ignore")
    cli.close()

    vals = dict(re.findall(r"^([A-Z][0-9]*)=(.*)$", text, re.M))
    radios = []
    for r in (0, 1, 2, 3):
        f = vals.get(f"R{r}", "").split(",")
        if len(f) < 4 or not f[1]:
            continue
        clients = int(f[5]) if len(f) > 5 and f[5].isdigit() else None
        radios.append({"radio": r, "on": f[0] == "1", "ssid": f[1],
                       "bssid": f[2].upper() or None,
                       "chan": int(f[3]) if f[3].isdigit() else None,
                       "ifname": f[4] if len(f) > 4 else None,
                       "clients": clients})
    model = (vals.get("O") or vals.get("P") or "").strip()
    return {"model": model,
            "firmware": (vals.get("F") or "").strip(),
            "uptime_s": int(float(vals.get("U") or 0)),
            "radios": radios}


def missing_pins(pins, radios):
    """BSSIDs that a unit reports ON for a configured SSID but which are
    NOT pinned in that SSID's expected_bssids. pins: {ssid: [bssids]}.
    radios: [{on, ssid, bssid}] (asus_ssh_inventory format).
    Returns {ssid: [unpinned bssids]}; empty = full coverage."""
    out = {}
    for r in radios or []:
        if not r.get("on") or not r.get("bssid") or r.get("ssid") not in pins:
            continue
        if r["bssid"].upper() not in [b.upper() for b in pins[r["ssid"]]]:
            out.setdefault(r["ssid"], []).append(r["bssid"].upper())
    return out


def compact_uptime(value):
    """Normalize uptime to '4d 11h 36m' style. Accepts seconds (asuswrt)
    or Aruba's colon text ('4d:11h:36m:22s')."""
    if value in (None, "", "-"):
        return "-"
    if isinstance(value, (int, float)):
        s = int(value)
        if s <= 0:
            return "-"
        d, s = divmod(s, 86400)
        h, s = divmod(s, 3600)
        m, s = divmod(s, 60)
        parts = []
        if d:
            parts.append(f"{d}d")
        if h or d:
            parts.append(f"{h}h")
        if m or not d:
            parts.append(f"{m}m")
        return " ".join(parts)
    m = re.match(r"(?:(\d+)d:)?(\d+)h:(\d+)m(?::(\d+)s)?",
                 str(value).strip())
    if not m:
        return str(value)
    d, h, mn = int(m.group(1) or 0), int(m.group(2)), int(m.group(3))
    parts = []
    if d:
        parts.append(f"{d}d")
    if h or d:
        parts.append(f"{h}h")
    if mn or not d:
        parts.append(f"{mn}m")
    return " ".join(parts)


def parse_asus_uptime(seconds):
    """Back-compat alias."""
    return compact_uptime(seconds)


def fios_leases(host, cookie, timeout=15):
    """DHCP lease table from the Fios main router (Luci-derived UI).
    cookie: 'sysauth=...' session value from a logged-in browser session."""
    import urllib.request
    url = f"https://{host}/cgi/cgi_ip_distribution.js"
    req = urllib.request.Request(url, headers={
        "Cookie": cookie, "Referer": f"https://{host}/",
        "User-Agent": "Mozilla/5.0"})
    r = urllib.request.urlopen(req, timeout=timeout)
    text = r.read().decode(errors="ignore")
    return fios_leases_parse(text)


def fios_leases_parse(text):
    """Parse `addROD("dump_dhcp_leases", [...])` rows (testable form)."""
    rows = re.findall(r"\['([^']*)','([^']*)','([^']*)','([^']*)'\]", text)
    return [{"hostname": h, "ip": ip, "mac": mac.lower(), "expires_raw": e}
            for h, ip, mac, e in rows if mac]


def load_router_creds():
    """Optional per-router mgmt credentials, kept OUTSIDE the repo:
    {"aruba": {"host": ..., "user": ..., "password": ...},
     "asus":  [{"host": ..., "user": ..., "password": ...}, ...]}"""
    try:
        with open(CREDS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def aruba_ssh_inventory(host, user, password, timeout=25):
    """AP + client inventory from an Aruba Instant unit over SSH.

    Instant's dropbear only speaks legacy SSH (3des/group1) and closes
    exec channels without a PTY, so this drives `plink -t` interactively
    (pexpect) with the OPENSSL legacy-renegotiation config for any TLS.
    Returns {"aps": [..], "clients": {"total": n, "per_ssid": {..}}}.
    """
    import os
    import pexpect
    env = dict(os.environ, OPENSSL_CONF="/tmp/openssl_legacy.cnf")
    last_err = None
    for attempt in (1, 2):  # the AP's pty occasionally drops command echo
        child = pexpect.spawn("plink", ["-t", "-ssh", "-pw", password,
                                        f"{user}@{host}"],
                              encoding="utf-8", timeout=timeout, env=env)
        data = {}
        try:
            i = child.expect(["Store key in cache", "Access granted",
                              r"\S+#", pexpect.TIMEOUT, pexpect.EOF])
            if i == 0:
                child.sendline("y")
                child.expect(["Access granted", r"\S+#", pexpect.TIMEOUT])
            # Instant holds the session until a Return ("Press Return to
            # begin session"). Send it unconditionally -- an extra Return at
            # a fresh prompt is a harmless empty command.
            child.sendline("")
            child.expect([r"\S+#", pexpect.TIMEOUT, pexpect.EOF])
            for cmd in ("show aps", "show clients"):
                child.sendline(cmd)
                # the pty echoes the command INCLUDING the prompt prefix, so
                # sync on the echo first or the prompt match races output
                idx = child.expect_exact([cmd, r"\S+#", pexpect.TIMEOUT,
                                          pexpect.EOF])
                if idx != 0:  # echo never came -- retry with a fresh session
                    raise pexpect.exceptions.TIMEOUT(f"no echo for {cmd}")
                child.expect([r"\S+#", pexpect.TIMEOUT, pexpect.EOF])
                data[cmd] = child.before or ""
            child.sendline("exit")
            return {"aps": parse_show_aps(data.get("show aps", "")),
                    "clients": parse_show_clients(
                        data.get("show clients", ""))}
        except pexpect.exceptions.TIMEOUT as exc:
            last_err = exc
        finally:
            child.close()
    raise last_err


def parse_show_aps(text):
    """Rows of Instant's `show aps` (22 whitespace-separated columns)."""
    aps = []
    for line in text.splitlines():
        f = line.split()
        if len(f) != 22 or f[1].count(".") != 3:
            continue
        clean = lambda s: re.sub(r"\([^)]*\)", "", s).strip()
        aps.append({"name": f[0], "ip": f[1].rstrip("*"), "clients": int(f[4]),
                    "type": f[5], "chan_24": None if f[8] == "-" else f[8],
                    "util_24": clean(f[10]) or None,
                    "chan_50": None if f[12] == "-" else f[12],
                    "util_50": clean(f[14]) or None, "age": f[21]})
    return aps


def parse_show_clients(text):
    """`show clients` → {"total": n, "per_ssid": {ssid: count}}."""
    per_ssid, total = {}, None
    for line in text.splitlines():
        m = re.match(r"Number of Clients\s*:\s*(\d+)", line)
        if m:
            total = int(m.group(1))
            continue
        f = line.split()
        if not f:
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", f[0]):
            name, rest = "", f
        elif len(f) > 1 and re.match(r"^\d+\.\d+\.\d+\.\d+$", f[1]):
            name, rest = f[0], f[1:]
        else:
            continue
        if len(rest) < 3:
            continue
        ssid = rest[2]
        per_ssid[ssid] = per_ssid.get(ssid, 0) + 1
    return {"total": total if total is not None else sum(per_ssid.values()),
            "per_ssid": per_ssid}
