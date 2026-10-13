"""Juniper switch collector: maps unit MACs to physical switch ports.

Credentials live OUTSIDE the repo in /home/pi/.wifitester/creds.json:
  {"juniper": {"host": "192.168.1.2", "user": "root", "password": "..."}}

The switch runs Junos; we SSH as root, drop into `cli`, and read
`show ethernet-switching table` (MAC -> port) plus `show lldp neighbors`
(port -> device self-identification).
"""

import json
import re
import time

CREDS_FILE = "/home/pi/.wifitester/creds.json"


def load_switch_creds():
    try:
        with open(CREDS_FILE, encoding="utf-8") as f:
            return json.load(f).get("juniper") or {}
    except Exception:
        return {}


def switch_port_traffic(host, user, password, timeout=25):
    """Per-port traffic from `show interfaces ge-0/0/* media` (the switch
    computes input/output rates over its own load interval).
    Returns {port: {"in_bps", "out_bps", "in_bytes", "out_bytes", "link"}}."""
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, username=user, password=password,
                look_for_keys=False, allow_agent=False, timeout=10)
    chan = cli.invoke_shell()
    chan.settimeout(8)
    time.sleep(1.0)
    try:
        chan.recv(8000)
    except Exception:
        pass
    chan.send("cli\n")
    time.sleep(2.0)
    try:
        chan.recv(8000)
    except Exception:
        pass

    def run(command, wait=12.0):
        chan.send(command + "\n")
        time.sleep(wait)
        out = b""
        chan.settimeout(1.0)
        try:
            while len(out) < 120000:
                try:
                    chunk = chan.recv(16384)
                except Exception:
                    break
                if not chunk:
                    break
                out += chunk
        except Exception:
            pass
        return _strip_ansi(out.decode(errors="ignore"))

    try:
        text = run('show interfaces ge-0/0/* media | match '
                   '"Physical interface|Input rate|Output rate|Input bytes|'
                   'Output bytes" | no-more', 12.0)
    finally:
        cli.close()
    return _parse_port_media(text)


def _parse_port_media(text):
    """Parse the match-filtered media output into per-port traffic."""
    out = {}
    port = None
    entry = {}
    for line in text.splitlines():
        m = re.match(r"Physical interface: (\S+),.*link is (\S+)", line)
        if m:
            if port and entry:
                out[port] = entry
            port, entry = m.group(1), {"link": m.group(2).rstrip(",")}
            continue
        if not port:
            continue
        m = re.search(r"Input rate\s*:\s*([\d,]+) bps", line)
        if m:
            entry["in_bps"] = int(m.group(1).replace(",", ""))
            continue
        m = re.search(r"Output rate\s*:\s*([\d,]+) bps", line)
        if m:
            entry["out_bps"] = int(m.group(1).replace(",", ""))
            continue
        m = re.search(r"Input bytes:\s*([\d,]+)", line)
        if m:
            entry["in_bytes"] = int(m.group(1).replace(",", ""))
        m = re.search(r"Output bytes:\s*([\d,]+)", line)
        if m:
            entry["out_bytes"] = int(m.group(1).replace(",", ""))
    if port and entry:
        out[port] = entry
    return out


def _strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)


def _parse_switching_table(text):
    """`show ethernet-switching table` rows -> {mac_lower: {"vlan", "port"}}."""
    out = {}
    for line in text.splitlines():
        f = line.split()
        # unicast learned/static rows only: [vlan, mac, type, age, interface]
        if len(f) >= 5 and f[2] in ("Learn", "Static") and \
                re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", f[1]):
            out[f[1].lower()] = {"vlan": f[0], "port": f[4]}
    return out


def _parse_lldp_neighbors(text):
    """`show lldp neighbors` rows -> {chassis_id_lower: {...}}."""
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) < 4 or f[1] != "-":
            continue
        if not re.match(r"^[0-9a-fA-F:]{14,17}$", f[2]) and \
                not re.match(r"^[A-Za-z0-9-]+$", f[2]):
            continue
        chassis = f[2].lower()
        out[chassis] = {"local_port": f[0],
                        "lldp_port": f[3],
                        "system_name": " ".join(f[4:]) or None}
    return out


def switch_inventory(host, user, password, timeout=25):
    """Collector: opens the Junos CLI over SSH and returns
    {"mac_ports": {mac: {"port", "vlan"}},
     "lldp": {chassis: {"local_port", "lldp_port", "system_name"}}}."""
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, username=user, password=password,
                look_for_keys=False, allow_agent=False, timeout=10)
    chan = cli.invoke_shell()
    chan.settimeout(8)
    time.sleep(1.0)
    try:
        chan.recv(8000)
    except Exception:
        pass
    chan.send("cli\n")
    time.sleep(2.0)
    try:
        chan.recv(8000)
    except Exception:
        pass

    def run(command, wait=8.0):
        chan.send(command + "\n")
        time.sleep(wait)
        out = b""
        chan.settimeout(1.0)
        try:
            while len(out) < 80000:
                try:
                    chunk = chan.recv(16384)
                except Exception:
                    break
                if not chunk:
                    break
                out += chunk
        except Exception:
            pass
        return _strip_ansi(out.decode(errors="ignore"))

    try:
        table = run("show ethernet-switching table | no-more")
        lldp = run("show lldp neighbors | no-more")
    finally:
        cli.close()
    mac_ports = _parse_switching_table(table)
    lldp_map = _parse_lldp_neighbors(lldp)
    # enrich MAC rows with the LLDP identity of their port
    port_lldp = {v["local_port"].split(".")[0]: v for v in lldp_map.values()}
    for mac, entry in mac_ports.items():
        p = entry["port"].split(".")[0]
        if p in port_lldp:
            entry["lldp_port"] = port_lldp[p]["lldp_port"]
            entry["lldp_system"] = port_lldp[p]["system_name"]
    return {"mac_ports": mac_ports, "lldp": lldp_map}
