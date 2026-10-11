"""Connectivity probes: ICMP to the gateway over the test interface, plus an
optional internet-hop probe. Each probe returns a dict record."""

import logging
import re
import subprocess
import time

from . import nm

log = logging.getLogger("wifitester.probe")

_RTT = re.compile(r"time[=<]([\d.]+)\s*ms")


def ping_once(target, iface, timeout_s, deadline_ts=None):
    """One ICMP echo. Returns {'ok': bool, 'rtt_ms': float|None}."""
    cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, int(timeout_s))),
           "-I", iface, target]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_s + 2)
    except subprocess.TimeoutExpired:
        return {"ok": False, "rtt_ms": None}
    ok = proc.returncode == 0
    rtt = None
    if ok:
        m = _RTT.search(proc.stdout)
        rtt = float(m.group(1)) if m else round((time.monotonic() - t0) * 1000, 1)
    return {"ok": ok, "rtt_ms": rtt}


def probe_series(target, iface, count, interval_s, timeout_s, stop_event=None):
    """Run `count` pings spaced by interval; returns list of probe records."""
    probes = []
    for i in range(count):
        rec = ping_once(target, iface, timeout_s)
        rec["target"] = target
        probes.append(rec)
        if i < count - 1 and stop_event is not None:
            if stop_event.wait(interval_s):
                break
    return probes


def summarize(probes):
    sent = len(probes)
    lost = sum(1 for p in probes if not p["ok"])
    rtts = [p["rtt_ms"] for p in probes if p["ok"] and p["rtt_ms"] is not None]
    return {
        "sent": sent,
        "lost": lost,
        "loss_pct": round(lost * 100.0 / sent, 1) if sent else 0.0,
        "avg_rtt_ms": round(sum(rtts) / len(rtts), 1) if rtts else None,
        "max_rtt_ms": round(max(rtts), 1) if rtts else None,
    }
