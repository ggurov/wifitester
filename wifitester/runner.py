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

    # -- cycle ------------------------------------------------------------

    def cycle(self):
        for ap in self.cfg.aps:
            if self.stop.is_set():
                return
            if not ap.enabled:
                continue
            try:
                rec = self.visit_ap(ap)
            except nm.CommandError as exc:
                rec = {"ssid": ap.ssid, "connect_ok": False,
                       "connect_error": str(exc)[:300]}
                log.error("visit %s failed: %s", ap.ssid, exc)
            self.store.insert_visit(rec)
            if not rec.get("connect_ok"):
                log.warning("%s: connect failed (%s)",
                            ap.ssid, rec.get("connect_error", "?"))
            else:
                log.info("%s: bssid=%s sig=%sdBm loss=%s%% avg=%sms gw=%s",
                         ap.ssid, rec.get("bssid"), rec.get("signal_dbm"),
                         rec.get("loss_pct"), rec.get("avg_rtt_ms"),
                         rec.get("gateway"))

    def visit_ap(self, ap):
        """Connect to one AP, probe the gateway, return a visit record."""
        try:
            psk = None if ap.open else _read_psk(ap)
        except OSError as exc:
            return {"ssid": ap.ssid, "connect_ok": False,
                    "connect_error": f"psk unreadable: {exc}"}
        key_mgmt = "none" if ap.open else "wpa-psk"
        name = nm.ensure_profile(self.cfg.interface, ap.ssid, psk, key_mgmt)

        rec = {"ssid": ap.ssid, "connect_ok": False}
        try:
            t0 = time.monotonic()
            nm.up_profile(name, timeout_s=self.cfg.connect_timeout_s)
            link = nm.iw_link(self.cfg.interface)
            rec.update({
                "connect_ok": True,
                "bssid": link.get("bssid"),
                "signal_dbm": link.get("signal_dbm"),
                "freq_mhz": link.get("freq_mhz"),
                "chan": link.get("chan"),
            })
            log.debug("%s: associated in %.1fs", ap.ssid,
                      time.monotonic() - t0)
        except nm.CommandError as exc:
            rec["connect_error"] = exc.stderr[:300] or str(exc)[:300]
            return rec

        time.sleep(self.cfg.settle_s)  # let DHCP/default route land
        gw = nm.default_gateway(self.cfg.interface)
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
                                 nm.key_mgmt_for(net.get("security")))
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
        name = nm.ensure_profile(self.cfg.interface, ssid, None, "none")
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
        log.info("testing iface=%s, %d APs, cycle=%ss, scan=%ss; "
                 "original connection: %r", self.cfg.interface,
                 len([a for a in self.cfg.aps if a.enabled]),
                 self.cfg.cycle_interval_s, self.cfg.scan_interval_s,
                 self._orig_connection)
        try:
            while not self.stop.is_set():
                started = time.monotonic()
                self.cycle()
                if do_scan and not self.stop.is_set():
                    self.scan_pass()
                if once:
                    break
                wait = self.cfg.cycle_interval_s - (time.monotonic() - started)
                if wait > 0:
                    self.stop.wait(wait)
        finally:
            self._restore()

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
