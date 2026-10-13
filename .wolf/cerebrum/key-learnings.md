## Key Learnings


- wlan3 is the Pi's standing wifi link (`netplan-wlan0-77fast5`, DHCP .238) — NEVER list it in
  `tester.interfaces`. Its only protection used to be an accidental IP-collision skip.
- wt-* test connections churn their /24 + default routes on EVERY probe visit (add/delete per
  visit; `ip monitor route` shows it). A connected route for the uplink (eth0, metric 100) must
  always exist or LAN replies blackhole between visits — this was the "pi keeps losing link" bug.
- NM device-type route metrics: ethernet 100, wifi 600+, tester extras 700+10n. Test-radio routes
  must never outrank the uplink's connected /24.
- Netplan-generated NM profiles autoconnect on ANY wifi radio unless `connection.interface-name`
  is pinned — they fight the tester for wlan0/wlan1/wlan2 mid-sweep.
- Mesh APs answer association storms with `CTRL-EVENT-ASSOC-REJECT status_code=16` (station
  limit); tester aggressiveness can itself be an outage contributor.
- This Pi has no `node` — .wolf JS tools (wolf_bug.js, ledger.js, hooks) cannot run here;
  append buglog shards by hand in the documented JSONL format instead.

- RTL8188CUS/EUS sticks fail in a characteristic way when dying: scan returns 1 garbage entry
  (CHAN 0, SIGNAL 0) or zero BSS, and they fall off the bus with `can't set config #1, error -71`.
  Don't debug config first — check `lsusb` + `iw dev <if> scan | grep -c BSS`.
- USB wifi interface NAMES reshuffle on replug (wlan3→wlan1 happened 2026-10-11). Pin
  connections by MAC (`802-11-wireless.mac-address`), never interface-name, for standing links.
- Tester has connect-failure backoff (runner._skip_until/_fail_streak, window 2..24 cycles) and
  an uplink route guard (nm.ensure_uplink_route, re-installs the wired /24) since 2026-10-11.
