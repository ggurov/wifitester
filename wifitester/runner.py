"""Daemon: round-robin AP visits with gateway probes + periodic scan passes."""

import logging
import threading
import time

from . import nm, probe, scanner
from .config import _read_psk

log = logging.getLogger("wifitester.runner")


class PreflightError(RuntimeError):
    pass


class Runner:
    def __init__(self, cfg, store):
        self.cfg = cfg
        self.store = store
        self.stop = threading.Event()
        self._orig_connection = None

    # -- preflight --------------------------------------------------------

    def preflight(self):
        nm.nmcli_version()
        if not nm.wifi_interface_present(self.cfg.interface):
            raise PreflightError(
                f"wifi interface {self.cfg.interface} not found "
                f"(nmcli dev status to inspect)")
        if self.cfg.require_wired_uplink and not nm.wired_uplink_present():
            raise PreflightError(
                "no wired uplink detected -- cycling the only wifi link would "
                "cut your access to this Pi; set require_wired_uplink=false in "
                "config to override")
        if self.cfg.static_ipv4:
            ip = self.cfg.static_ipv4.split("/")[0]
            if not nm.addr_assigned(ip):
                arp_iface = nm.wired_iface() or self.cfg.interface
                if nm.ip_in_use(ip, arp_iface):
                    raise PreflightError(
                        f"static_ipv4 {ip} is answered by another device on "
                        f"the LAN (arping via {arp_iface}) -- pick a free "
                        "address outside the DHCP pool")

    # -- cycle ------------------------------------------------------------

    def _visit_items(self):
        """Expand configured APs into per-BSSID visit items so every mesh
        node gets probed, not just the one NM roams to."""
        items = []
        for ap in self.cfg.aps:
            if not ap.enabled:
                continue
            if ap.expected_bssids:
                items.extend((ap, b) for b in ap.expected_bssids)
            else:
                items.append((ap, None))
        return items

    def cycle(self):
        for ap, bssid in self._visit_items():
            if self.stop.is_set():
                return
            try:
                rec = self.visit_ap(ap, bssid)
            except nm.CommandError as exc:
                rec = {"ssid": ap.ssid, "bssid": bssid, "connect_ok": False,
                       "connect_error": str(exc)[:300]}
                log.error("visit %s failed: %s", ap.ssid, exc)
            self.store.insert_visit(rec)
            label = f"{ap.ssid}@{bssid}" if bssid else ap.ssid
            if not rec.get("connect_ok"):
                log.warning("%s: connect failed (%s)",
                            label, rec.get("connect_error", "?"))
            else:
                log.info("%s: bssid=%s sig=%sdBm loss=%s%% avg=%sms gw=%s",
                         label, rec.get("bssid"), rec.get("signal_dbm"),
                         rec.get("loss_pct"), rec.get("avg_rtt_ms"),
                         rec.get("gateway"))

    def visit_ap(self, ap, bssid=None):
        """Associate (optionally pinned to one BSSID), probe the gateway,
        return a visit record."""
        try:
            psk = None if ap.open else _read_psk(ap)
        except OSError as exc:
            return {"ssid": ap.ssid, "bssid": bssid, "connect_ok": False,
                    "connect_error": f"psk unreadable: {exc}"}
        key_mgmt = "none" if ap.open else "wpa-psk"
        name = nm.ensure_profile(self.cfg.interface, ap.ssid, psk, key_mgmt,
                                 self.cfg.static_ipv4, self.cfg.static_gateway)

        rec = {"ssid": ap.ssid, "bssid": bssid, "connect_ok": False}
        try:
            if bssid:
                nm.set_profile_bssid(name, bssid)
            t0 = time.monotonic()
            try:
                nm.up_profile(name, timeout_s=self.cfg.connect_timeout_s)
                link = nm.iw_link(self.cfg.interface)
                rec.update({
                    "connect_ok": True,
                    "bssid": link.get("bssid") or bssid,
                    "signal_dbm": link.get("signal_dbm"),
                    "freq_mhz": link.get("freq_mhz"),
                    "chan": link.get("chan"),
                })
                log.debug("%s: associated in %.1fs", ap.ssid,
                          time.monotonic() - t0)
            finally:
                if bssid:
                    nm.set_profile_bssid(name, "")  # clear pin
        except nm.CommandError as exc:
            rec["connect_error"] = exc.stderr[:300] or str(exc)[:300]
            return rec

        time.sleep(self.cfg.settle_s)  # static: address is already on
        gw = nm.default_gateway(self.cfg.interface) or \
            (self.cfg.static_gateway if self.cfg.static_ipv4 else None)
        rec["gateway"] = gw
        link = nm.iw_link(self.cfg.interface)  # refresh after settle
        rec.update({k: link[k] for k in ("bssid", "signal_dbm", "freq_mhz", "chan")
                    if k in link})

        if not gw:
            rec.update({"sent": 0, "lost": 0, "loss_pct": 100.0,
                        "avg_rtt_ms": None, "max_rtt_ms": None,
                        "connect_error": "no default route via wifi"})
            return rec

        probes = probe.probe_series(
            gw, self.cfg.interface, self.cfg.probe_count,
            self.cfg.probe_interval_s, self.cfg.probe_timeout_s, self.stop)
        stats = probe.summarize(probes)
        rec.update(stats)

        if self.cfg.internet_target:
            inet = probe.ping_once(self.cfg.internet_target,
                                   self.cfg.interface, self.cfg.probe_timeout_s)
            rec["internet_ok"] = inet["ok"]
        return rec

    # -- scan -------------------------------------------------------------

    def scan_pass(self):
        nets = nm.scan_networks(self.cfg.interface, rescan=self.cfg.scan_rescan)
        known = self._known_map()
        items = scanner.plan(
            scanner.group_networks(nets), known,
            auth_probe=self.cfg.auth_probe, open_assoc=self.cfg.open_assoc)

        results = {}
        for net, action, cls in items:
            if self.stop.is_set():
                break
            if action == scanner.PLAN_AUTH:
                cls = self._auth_attempt(net, known[net["ssid"]]["psk"])
                results[(net["bssid"], action)] = cls
            elif action == scanner.PLAN_ASSOC:
                cls = self._assoc_attempt(net)
                results[(net["bssid"], action)] = cls

        classified = scanner.classify_all(items, results)
        self.store.insert_scan_pass(classified)
        self._restore()
        for n in classified:
            log.info("scan %-16s %s ch%-3s %3s%% %-10s %s", n["ssid"] or "<hidden>",
                     n["bssid"], n.get("chan"), n.get("signal"),
                     n.get("security") or "open", n["classification"])
        return classified

    def _known_map(self):
        out = {}
        for ap in self.cfg.aps:
            if not ap.enabled:
                continue
            psk = None
            if not ap.open:
                try:
                    psk = _read_psk(ap)
                except OSError as exc:
                    log.warning("%s: psk unreadable (%s); "
                                "marking KNOWN_UNVERIFIED", ap.ssid, exc)
            out[ap.ssid] = {
                "psk": psk,
                "expected_bssids": ap.expected_bssids,
            }
        return out

    def _auth_attempt(self, net, psk):
        """Associate to one specific BSSID with our PSK; classify outcome."""
        ssid, bssid = net["ssid"], net["bssid"]
        name = nm.ensure_profile(self.cfg.interface, ssid, psk,
                                 nm.key_mgmt_for(net.get("security")),
                                 self.cfg.static_ipv4, self.cfg.static_gateway)
        t0 = time.monotonic()
        try:
            nm.set_profile_bssid(name, bssid)
            try:
                nm.up_profile(name, timeout_s=self.cfg.auth_timeout_s)
                result, cls = "success", "OURS"
            except nm.CommandError as exc:
                if exc.timeout:
                    result, cls = "timeout", "AUTH_TIMEOUT"
                else:
                    result, cls = "auth_fail", "ROGUE_SSID"
            finally:
                nm.set_profile_bssid(name, "")  # clear pin
        finally:
            nm.down_profile(name)
        self.store.insert_auth(ssid, bssid, result, cls,
                               int((time.monotonic() - t0) * 1000))
        return cls

    def _assoc_attempt(self, net):
        """Try associating to an unknown OPEN network."""
        ssid, bssid = net["ssid"], net["bssid"]
        name = nm.ensure_profile(self.cfg.interface, ssid, None, "none",
                                 self.cfg.static_ipv4, self.cfg.static_gateway)
        t0 = time.monotonic()
        try:
            nm.set_profile_bssid(name, bssid)
            try:
                nm.up_profile(name, timeout_s=self.cfg.auth_timeout_s)
                result, cls = "assoc_ok", "OPEN_FOREIGN"
            except nm.CommandError as exc:
                if exc.timeout:
                    result, cls = "timeout", "AUTH_TIMEOUT"
                else:
                    result, cls = "assoc_fail", "OPEN_FOREIGN_REFUSED"
            finally:
                nm.set_profile_bssid(name, "")
        finally:
            nm.down_profile(name)
        self.store.insert_auth(ssid, bssid, result, cls,
                               int((time.monotonic() - t0) * 1000))
        return cls

    # -- lifecycle --------------------------------------------------------

    def run(self, once=False, do_scan=True):
        self.preflight()
        self._orig_connection = nm.current_connection(self.cfg.interface)
        self._last_sweep = 0.0
        log.info("testing iface=%s, %d APs, cycle=%ss, scan=%ss; "
                 "original connection: %r", self.cfg.interface,
                 len([a for a in self.cfg.aps if a.enabled]),
                 self.cfg.cycle_interval_s, self.cfg.scan_interval_s,
                 self._orig_connection)
        self.maybe_lan_sweep()  # neighbor table ready for the first sweep
        try:
            while not self.stop.is_set():
                started = time.monotonic()
                self.cycle()
                if do_scan and not self.stop.is_set():
                    self.scan_pass()
                self.maybe_lan_sweep()
                if once:
                    break
                wait = self.cfg.cycle_interval_s - (time.monotonic() - started)
                if wait > 0:
                    self.stop.wait(wait)
        finally:
            self._restore()

    def maybe_lan_sweep(self):
        """Periodic ARP/ping sweep of the wired LAN so BSSIDs can be matched
        to the ethernet MAC of their physical unit. Never touches wifi."""
        if not self.cfg.lan_sweep_interval_s:
            return
        now = time.monotonic()
        if now - getattr(self, "_last_sweep", 0) < self.cfg.lan_sweep_interval_s:
            return
        self._last_sweep = now
        iface = nm.wired_iface()
        if not iface:
            log.warning("lan sweep skipped: no wired interface")
            return
        cidr = self.cfg.static_ipv4 or nm.iface_cidr(iface)
        if not cidr:
            log.warning("lan sweep skipped: no ipv4 on %s", iface)
            return
        try:
            table = nm.lan_sweep(nm.lan_hosts(cidr), iface)
            self.store.replace_neighbors(sorted(table.items()))
            log.info("lan sweep via %s (%s): %d neighbors", iface, cidr,
                     len(table))
        except nm.CommandError as exc:
            log.warning("lan sweep failed: %s", exc.stderr[:120])

    def _restore(self):
        if not self.cfg.restore_connection:
            return
        orig = self._orig_connection
        if not orig or orig.startswith(nm.PROFILE_PREFIX):
            return
        try:
            if nm.current_connection(self.cfg.interface) != orig:
                log.info("restoring original connection %r", orig)
                nm.up_connection(orig)
        except nm.CommandError as exc:
            log.warning("restore %r failed: %s", orig, exc.stderr[:120])
