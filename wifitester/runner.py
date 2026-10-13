"""Daemon: round-robin AP visits with gateway probes + periodic scan passes."""

import logging
import threading
import time

from . import nm, probe, routers, scanner, switch
from .config import _read_psk

log = logging.getLogger("wifitester.runner")


class PreflightError(RuntimeError):
    pass


def _shift_ip(cidr, n):
    """Decrement the last octet of a cidr by n: '...248/24' -1 -> '...247/24'."""
    ip, prefix = cidr.split("/")
    o = [int(x) for x in ip.split(".")]
    o[3] -= n
    if o[3] < 1:
        raise PreflightError(f"no room to shift {cidr} by {n}")
    return f"{'.'.join(map(str, o))}/{prefix}"


def _next_free_cidr(base_cidr, n, taken, arp_iface, tries=8):
    """Walk down from a radio's natural slot (static_ipv4 - (n+k)) to the
    first address that is neither claimed by another radio nor answered
    on the LAN. Returns a cidr, or None if no free address is found."""
    for k in range(1, tries + 1):
        try:
            cidr = _shift_ip(base_cidr, n + k)
        except PreflightError:
            return None
        ip = cidr.split("/")[0]
        if ip in taken or ip.endswith(".0") or ip.endswith(".255"):
            continue
        if nm.addr_assigned(ip) or nm.ip_in_use(ip, arp_iface):
            log.info("candidate %s answered on the LAN; trying next", ip)
            continue
        taken.add(ip)
        return cidr
    return None


def _backoff_window(streak):
    """Cycles to skip a visit item after `streak` consecutive connect
    failures. Retries freely up to streak 2; bounded exponential from the
    third failure, so a flaky node is re-probed roughly every 10-30 sweeps
    without ever being given up on."""
    if streak < 3:
        return 0
    return min(2 ** (streak - 1), 64)


def assign_items(items, caps, chan_of):
    """Balance (ap, bssid) visit items across radios, respecting each
    radio's supported frequencies. caps: {iface: set(freq_mhz)};
    chan_of: {bssid: chan} (unknown chan -> any radio). Returns
    {iface: [(ap, bssid)]} with deterministic config-order tie-breaks."""
    ifaces = list(caps)
    out = {i: [] for i in ifaces}
    for ap, bssid in items:
        chan = chan_of.get(bssid)
        freq = nm.chan_to_freq(chan) if chan else None
        cands = [i for i in ifaces if not freq or freq in caps[i]]
        if not cands:
            cands = [ifaces[0]]  # nobody covers this band: primary tries
        i = min(cands, key=lambda i: (len(out[i]), ifaces.index(i)))
        out[i].append((ap, bssid))
    return out


class Runner:
    def __init__(self, cfg, store):
        self.cfg = cfg
        self.store = store
        self.stop = threading.Event()
        self._orig_connection = None
        self._cycle_no = 0
        self._fail_streak = {}  # (ssid, bssid) -> consecutive connect fails
        self._skip_until = {}   # (ssid, bssid) -> cycle no when due again
        self._dhcp_pending = set()  # radios awaiting their first DHCP lease
        self._radio_resets = {}  # iface -> (attempts, last_epoch)

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

        # extra radios: exist, band capability, address plan
        # (auto mode: hot-plug discovery + DHCP-once-cached; static mode:
        # walk-down allocator from static_ipv4)
        self._bands = nm.iface_bands()
        self._ip_map = {self.cfg.interface: self.cfg.static_ipv4}
        self._metric = {self.cfg.interface: None}
        self._never_default = {self.cfg.interface: False}
        self._radios = [self.cfg.interface]
        self._arp_iface = nm.wired_iface() or self.cfg.interface
        self._taken_ips = {self.cfg.static_ipv4.split("/")[0]} \
            if self.cfg.static_ipv4 else set()
        for iface in self._planned_extras():
            self._register_radio(iface)
        log.info("radios in use: %s", self._radios)

    def _planned_extras(self):
        """Extra radios to manage: the static config list, or (auto mode)
        every wifi interface except the primary and any carrying a
        non-tester (standing) connection."""
        if not self.cfg.auto_radios:
            return list(self.cfg.interfaces)
        conn = nm.wifi_connection_map()
        out = []
        for iface in nm.wifi_interfaces():
            if iface == self.cfg.interface:
                continue
            profile = conn.get(iface)
            if profile and not profile.startswith("wt-"):
                continue  # user's standing link (netplan etc.)
            out.append(iface)
        return out

    def _register_radio(self, iface):
        """Validate a candidate extra radio and add it to the pool.
        Auto mode: DHCP once, cache the lease by MAC, reuse the address.
        Static mode: walk-down allocator from static_ipv4.
        True when registered."""
        if iface in self._radios:
            return False
        if not nm.wifi_interface_present(iface):
            log.warning("interface %s not present; skipping", iface)
            return False
        if iface not in self._bands or not self._bands[iface]:
            self._bands.update(nm.iface_bands())
        if iface not in self._bands or not self._bands[iface]:
            log.warning("no band info for %s; skipping", iface)
            return False
        n = len(self._radios) - 1
        self._metric[iface] = 700 + 10 * n
        mac = nm.iface_mac(iface)
        ip = None
        if self.cfg.auto_radios:
            lease = self.store.radio_lease_get(mac) if mac else None
            if lease and lease[1] > time.time() + 60:
                ip = lease[0]
                log.info("radio %s: cached lease %s (expires %s)", iface, ip,
                         time.strftime("%m-%d %H:%M",
                                       time.localtime(lease[1])))
            self._never_default[iface] = True  # dhcp radios carry no route
        else:
            ip = _next_free_cidr(self.cfg.static_ipv4, n, self._taken_ips,
                                 self._arp_iface) \
                if self.cfg.static_ipv4 else None
            if self.cfg.static_ipv4 and ip is None:
                log.warning("no free static candidate for %s; radio skipped",
                            iface)
                return False
            self._taken_ips.add(ip)
        if ip:
            self._ip_map[iface] = ip
        self._radios.append(iface)
        log.info("radio %s: bands=%s ip=%s", iface,
                 sorted(self._bands[iface])[:4], ip or "dhcp")
        return True

    def _refresh_radios(self):
        """Auto mode: hot-join newly appeared wifi interfaces and drop
        removed ones, so dongles can be plugged/unplugged freely."""
        if not self.cfg.auto_radios:
            return
        conn = nm.wifi_connection_map()
        present = {self.cfg.interface}
        for iface in nm.wifi_interfaces():
            profile = conn.get(iface)
            if profile and not profile.startswith("wt-"):
                continue  # standing link, not ours
            present.add(iface)
        joined = sorted(present - set(self._radios))
        if joined:
            try:
                self._bands.update(nm.iface_bands())
            except Exception:
                pass
        for iface in joined:
            if self._register_radio(iface):
                log.info("radio %s joined (auto-detected)", iface)
        for iface in [i for i in self._radios if i not in present
                      and i != self.cfg.interface]:
            self._radios.remove(iface)
            self._ip_map.pop(iface, None)
            self._metric.pop(iface, None)
            self._never_default.pop(iface, None)
            log.info("radio %s left (interface gone)", iface)

    def _maybe_reset_wedged_radios(self):
        """USB re-enumerate radios deep in timeout streaks (wedged
        firmware). Max 2 resets per MAC per hour; renamed interfaces are
        re-joined automatically by _refresh_radios."""
        if not self.cfg.auto_radios:
            return
        now = time.time()
        for r in self.store.radio_stats():
            if r["iface"] not in self._radios or not r["present"]:
                continue
            if r["consec_fail"] < 4 or "timeout" not in (r["last_error"] or ""):
                continue
            attempts, last = self._radio_resets.get(r["iface"], (0, 0.0))
            if attempts >= 2 and now - last < 3600:
                continue
            self._radio_resets[r["iface"]] = (attempts + 1, now)
            log.warning("radio %s wedged (%d consecutive timeouts); "
                        "USB-resetting", r["iface"], r["consec_fail"])
            try:
                mac = nm.iface_mac(r["iface"])
                if mac:
                    self._radio_resets[mac] = self._radio_resets[r["iface"]]
                nm.usb_reset_radio(r["iface"])
            except Exception as exc:
                log.warning("radio %s USB reset failed: %s", r["iface"], exc)

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

    def _visit_item_worker(self, iface, ap, bssid):
        """Visit one item on one radio; returns/records the visit record."""
        t_start = time.monotonic()
        try:
            rec = self.visit_ap(ap, bssid, iface)
        except nm.CommandError as exc:
            rec = {"ssid": ap.ssid, "bssid": bssid, "iface": iface,
                   "connect_ok": False,
                   "connect_error": str(exc)[:300]}
            log.error("visit %s failed: %s", ap.ssid, exc)
        rec.setdefault("iface", iface)
        self._cycle_done = getattr(self, "_cycle_done", 0) + 1
        self._cycle_visit_time = getattr(self, "_cycle_visit_time", 0.0) \
            + time.monotonic() - t_start
        self.store.insert_visit(rec)
        self.store.radio_visit(iface, bool(rec.get("connect_ok")),
                               rec.get("connect_error"))
        label = f"{iface} {ap.ssid}@{bssid}" if bssid else f"{iface} {ap.ssid}"
        key = (ap.ssid, bssid)
        if rec.get("connect_ok"):
            self._fail_streak.pop(key, None)
            self._skip_until.pop(key, None)
        else:
            streak = self._fail_streak.get(key, 0) + 1
            self._fail_streak[key] = streak
            window = _backoff_window(streak)
            if window:
                self._skip_until[key] = self._cycle_no + window
                log.info("%s: %d consecutive connect failures; "
                         "backing off %d cycles", label, streak, window)
        if not rec.get("connect_ok"):
            log.warning("%s: connect failed (%s)",
                        label, rec.get("connect_error", "?"))
        else:
            log.info("%s: bssid=%s sig=%sdBm loss=%s%% avg=%sms gw=%s",
                     label, rec.get("bssid"), rec.get("signal_dbm"),
                     rec.get("loss_pct"), rec.get("avg_rtt_ms"),
                     rec.get("gateway"))

    def _chan_of(self):
        """{bssid: chan} from the latest scan observations."""
        return {r["bssid"]: r["chan"]
                for r in self.store.latest_classification(0)}

    def _band_of(self, bssid):
        """NM band value ("a"/"bg") for a BSSID from the latest scan data."""
        chan = self._chan_of().get(bssid)
        freq = nm.chan_to_freq(chan) if chan else None
        if freq:
            return "a" if freq >= 4900 else "bg"
        return None

    def _due_items(self):
        """Visit items minus those in connect-failure backoff, so one dead
        node can't stretch every sweep by connect_timeout_s."""
        return [(ap, b) for ap, b in self._visit_items()
                if self._cycle_no >= self._skip_until.get((ap.ssid, b), 0)]

    def cycle(self):
        """One parallel sweep: extras drain their share in worker threads
        while the primary handles its share (plus a scan pass when due)."""
        self._cycle_no += 1
        started = time.monotonic()
        self._cycle_done = 0
        self._cycle_visit_time = 0.0
        try:
            chan = self._chan_of()
        except Exception:
            chan = {}
        for i in self._radios:  # per-adapter heartbeat for the status page
            try:
                self.store.radio_heartbeat(
                    i, nm.wifi_interface_present(i),
                    scan_bss=len(chan) if i == self.cfg.interface else None)
            except Exception as exc:
                log.debug("radio heartbeat %s failed: %s", i, exc)
        try:
            nm.ensure_uplink_route()
        except Exception as exc:  # the guard must never break a sweep
            log.debug("uplink route guard skipped: %s", exc)
        caps = {i: self._bands[i] for i in self._radios}
        due = self._due_items()
        assign = assign_items(due, caps, self._chan_of())
        total = sum(len(v) for v in assign.values())
        extras = [i for i in self._radios if i != self.cfg.interface]
        threads = []
        for n, iface in enumerate(extras):
            t = threading.Thread(target=self._drain_list,
                                 args=(iface, assign.get(iface, []),
                                       4.0 * n),
                                 name=f"wt-{iface}", daemon=True)
            threads.append(t)
            t.start()
        self._drain_primary(assign.get(self.cfg.interface, []),
                            do_scan=not self.stop.is_set())
        for t in threads:
            while t.is_alive():
                t.join(0.5)
                if self.stop.is_set():
                    return
        self._cycle_stats = {
            "radios": len(self._radios), "items_total": total,
            "items_done": self._cycle_done,
            "duration_s": time.monotonic() - started,
            "visits_time_s": self._cycle_visit_time}

    def _drain_list(self, iface, items, stagger=0.0):
        if stagger:
            time.sleep(stagger)  # de-sync radios scanning the same channels
        for ap, bssid in items:
            if self.stop.is_set():
                return
            self._visit_item_worker(iface, ap, bssid)

    def _drain_primary(self, items, do_scan=True):
        now = time.monotonic()
        if do_scan and now - getattr(self, "_last_scan", 0) >= \
                self.cfg.scan_interval_s:
            self._last_scan = now
            try:
                self.scan_pass()
            except nm.CommandError as exc:
                log.error("scan failed: %s", exc.stderr[:120])
        self._drain_list(self.cfg.interface, items)

    def visit_ap(self, ap, bssid=None, iface=None):
        """Associate (optionally pinned to one BSSID), probe the gateway,
        return a visit record."""
        iface = iface or self.cfg.interface
        try:
            psk = None if ap.open else _read_psk(ap)
        except OSError as exc:
            return {"ssid": ap.ssid, "bssid": bssid, "connect_ok": False,
                    "connect_error": f"psk unreadable: {exc}"}
        key_mgmt = "none" if ap.open else "wpa-psk"
        name = nm.ensure_profile(
            iface, ap.ssid, psk, key_mgmt,
            self._ip_map.get(iface, ""),
            self.cfg.static_gateway if self._ip_map.get(iface) else "",
            primary_iface=self.cfg.interface,
            route_metric=self._metric.get(iface),
            band=self._band_of(bssid),
            never_default=self._never_default.get(iface, False))

        rec = {"ssid": ap.ssid, "bssid": bssid, "connect_ok": False}
        try:
            if bssid:
                nm.set_profile_bssid(name, bssid)
            t0 = time.monotonic()
            try:
                nm.up_profile(name, timeout_s=self.cfg.connect_timeout_s)
                link = nm.iw_link(iface)
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
            if iface in self._dhcp_pending and rec["connect_ok"]:
                info = nm.dhcp4_info(iface)
                if info.get("ip") and info.get("expires"):
                    mac = nm.iface_mac(iface)
                    self._ip_map[iface] = info["ip"]
                    self._dhcp_pending.discard(iface)
                    self._never_default[iface] = True
                    if mac:
                        self.store.radio_lease_set(mac, info["ip"],
                                                   info["expires"])
                    log.info("radio %s: dhcp lease %s (expires in %ss)",
                             iface, info["ip"], info.get("lease_time"))
        except nm.CommandError as exc:
            rec["connect_error"] = exc.stderr[:300] or str(exc)[:300]
            return rec

        time.sleep(self.cfg.settle_s)  # static: address is already on
        gw = nm.default_gateway(iface) or \
            (self.cfg.static_gateway if self._ip_map.get(iface) else None)
        rec["gateway"] = gw
        link = nm.iw_link(iface)  # refresh after settle
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
            if do_scan and not self.stop.is_set():
                # first scan before first sweep: chan data feeds the
                # band-aware item assignment (5 GHz items must not land on
                # 2.4 GHz-only radios)
                self._last_scan = time.monotonic()
                self.scan_pass()
            while not self.stop.is_set():
                started = time.monotonic()
                self._refresh_radios()
                self.cycle()
                stats = getattr(self, "_cycle_stats", None)
                if stats:
                    try:
                        self.store.insert_sweep_perf(
                            stats["radios"], stats["items_total"],
                            stats["items_done"], stats["duration_s"],
                            stats.get("visits_time_s", 0.0))
                    except Exception:
                        pass
                if do_scan and not self.stop.is_set():
                    self.scan_pass()
                self.maybe_lan_sweep()
                self._maybe_reset_wedged_radios()
                if time.monotonic() - getattr(self, "_last_router_poll", 0) \
                        >= self.cfg.lan_sweep_interval_s:
                    self._last_router_poll = time.monotonic()
                    self._poll_routers()
                if once:
                    break
                wait = self.cfg.cycle_interval_s - (time.monotonic() - started)
                if wait > 0:
                    self.stop.wait(wait)
        finally:
            self._restore()

    def _poll_routers(self):
        """Collect management-plane inventory from configured routers
        (credentials outside the repo: /home/pi/.wifitester/creds.json)."""
        try:
            log.info("router poll: starting")
            creds = routers.load_router_creds().get("aruba")
            log.info("router poll: aruba creds present=%s host=%s",
                     bool(creds), creds and creds.get("host"))
            if not creds or not creds.get("host"):
                return
            inv = routers.aruba_ssh_inventory(
                creds["host"], creds.get("user", "admin"),
                creds.get("password", ""))
            aps = inv.get("aps", [])
            if not aps:
                cl = inv.get("clients", {})
                log.warning("router poll: aruba returned no AP rows "
                            "(clients seen: %s)", cl.get("total"))
                return
            rows = [{"unit_key": f"aruba-{ap['ip']}", "source": "aruba-ssh",
                     "name": ap["name"], "model": f"Aruba AP-{ap['type']}",
                     "ip": ap["ip"],
                     "uptime": routers.compact_uptime(ap["age"]),
                     "clients": ap["clients"],
                     "radios": [
                         {"band": "2.4 GHz",
                          "chan": ap["chan_24"] if ap["chan_24"] not in ("-", "", None) else None,
                          "util": ap["util_24"] if ap["util_24"] not in ("-", "", None) else None,
                          "on": ap["chan_24"] is not None},
                         {"band": "5 GHz",
                          "chan": ap["chan_50"] if ap["chan_50"] not in ("-", "", None) else None,
                          "util": ap["util_50"] if ap["util_50"] not in ("-", "", None) else None,
                          "on": ap["chan_50"] is not None}]}
                    for ap in aps]
            self.store.upsert_ap_inventory(rows)
            log.info("router poll: %d unit(s) from aruba-ssh", len(rows))
        except Exception as exc:
            log.warning("router poll failed: %s", exc)
        try:
            sw = switch.load_switch_creds()
            log.info("router poll: switch creds present=%s host=%s",
                     bool(sw), sw and sw.get("host"))
            if not sw or not sw.get("host"):
                return
            data = switch.switch_inventory(
                sw["host"], sw.get("user", "root"),
                sw.get("password", ""))
            rows = [{"mac": mac, "port": e["port"], "vlan": e.get("vlan"),
                     "lldp_port": e.get("lldp_port"),
                     "lldp_system": e.get("lldp_system")}
                    for mac, e in data.get("mac_ports", {}).items()]
            self.store.upsert_switch_ports(rows)
            log.info("router poll: %d MAC(s) from switch", len(rows))
        except Exception as exc:
            log.warning("switch poll failed: %s", exc)
        for a in routers.load_router_creds().get("asus") or []:
            try:
                inv = routers.asus_ssh_inventory(
                    a["host"], a.get("user", "admin"),
                    a.get("password", ""))
                if not inv.get("model"):
                    log.warning("asus poll: %s returned no model", a["host"])
                    continue
                clients = sum(r.get("clients") or 0
                              for r in inv.get("radios", [])
                              if r.get("clients") is not None)
                any_clients = any(r.get("clients") is not None
                                  for r in inv.get("radios", []))
                fw = inv.get("firmware", "")
                self.store.upsert_ap_inventory([{
                    "unit_key": f"asus-{a['host']}", "source": "asus-ssh",
                    "name": inv["model"],
                    "model": f"{inv['model']} fw {fw}" if fw else inv["model"],
                    "ip": a["host"],
                    "uptime": routers.compact_uptime(
                        inv.get("uptime_s", 0)),
                    "clients": clients if any_clients else None,
                    "radios": [{"radio": r["radio"], "ssid": r["ssid"],
                                "bssid": r["bssid"], "chan": r.get("chan"),
                                "on": r["on"], "clients": r.get("clients")}
                               for r in inv.get("radios", [])]}])
                log.info("asus poll: %s (%s, %d radio(s), %s clients)",
                         inv["model"], a["host"], len(inv.get("radios", [])),
                         clients if any_clients else "?")
            except Exception as exc:
                log.warning("asus poll %s failed: %s", a.get("host"), exc)
        fios = routers.load_router_creds().get("fios") or {}
        if fios.get("host") and fios.get("cookie"):
            try:
                leases = routers.fios_leases(fios["host"], fios["cookie"])
                self.store.upsert_fios_leases(leases)
                log.info("router poll: %d lease(s) from fios", len(leases))
            except Exception as exc:
                log.warning("fios lease poll failed: %s", exc)
        # auto-pin: radios reported ON by a unit for a configured SSID whose
        # BSSID isn't pinned yet join the probe sweep automatically
        try:
            pins = {ap.ssid: [b.upper() for b in (ap.expected_bssids or [])]
                    for ap in self.cfg.aps}
            creds = routers.load_router_creds()
            for a in creds.get("asus") or []:
                try:
                    inv = routers.asus_ssh_inventory(
                        a["host"], a.get("user", "admin"),
                        a.get("password", ""))
                    missing = routers.missing_pins(pins, inv.get("radios", []))
                    for ssid, bssids in missing.items():
                        for b in bssids:
                            b_up = b.upper()
                            pins.setdefault(ssid, []).append(b_up)
                            for ap in self.cfg.aps:
                                if ap.ssid == ssid:
                                    ap.expected_bssids = (ap.expected_bssids or []) + [b_up]
                            log.info("auto-pinned %s on %s (unit %s reports it on-air)",
                                     b_up, ssid, a["host"])
                except Exception as exc:
                    log.warning("asus auto-pin %s failed: %s", a.get("host"), exc)
        except Exception as exc:
            log.warning("auto-pin setup failed: %s", exc)
        try:
            sw = switch.load_switch_creds()
            if not sw or not sw.get("host"):
                return
            traffic = switch.switch_port_traffic(
                sw["host"], sw.get("user", "root"),
                sw.get("password", ""))
            rows = [{"port": port, **entry}
                    for port, entry in traffic.items()]
            self.store.upsert_port_traffic(rows)
            log.info("router poll: %d port(s) traffic from switch", len(rows))
        except Exception as exc:
            log.warning("port traffic poll failed: %s", exc)

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
