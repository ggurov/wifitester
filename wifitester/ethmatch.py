"""Match a BSSID to the LAN-side (ethernet) MAC of its physical unit.

Bridges don't advertise their wired MAC, but consumer APs burn the radio
MACs sequentially from the same base block as the wired/bridge MAC. So:
  exact      : a learned neighbor MAC equals the BSSID (common when br0
               reuses the radio MAC)
  near+K/-K  : closest learned MAC in the same OUI whose last-3-octet
               integer offset is within +-16 -- e.g. BSSID ...BB:A1 with a
               neighbor ...BB:A3 is reported as near+2
  ~vap       : multi-SSID radios often emit VAP BSSIDs with a mangled OUI
               (e.g. 82:67:0E:58:73:EF vs 78:67:0E:58:73:EF); these are
               matched on the identical trailing octets instead, marked
               with a ~vap suffix
"""

OUI_LEN = 8  # "AA:BB:CC"


def _int3(mac):
    return int(mac[9:].replace(":", ""), 16)


def _same_oui(a, b):
    return a[:OUI_LEN].upper() == b[:OUI_LEN].upper()


def _vap_match(b, neighbors):
    """Same trailing 5 octets -> exact unit; same trailing 2 octet-block ->
    near by last-octet delta."""
    tail5, tail2 = b[-14:], b[-5:]
    last_b = int(b[-2:], 16)
    best, best_d = None, None
    for mac in neighbors:
        if mac[-14:] == tail5:
            return mac, neighbors[mac], "exact~vap"
        if mac[-5:-3] == b[-5:-3]:  # same 5th octet, delta on the last
            d = int(mac[-2:], 16) - last_b
            if abs(d) <= 16 and (best is None or abs(d) < abs(best_d)):
                best, best_d = mac, d
    if best is None:
        return None, None, None
    sign = "+" if best_d > 0 else "-"
    return best, neighbors[best], f"near{sign}{abs(best_d):x}~vap"


def match_eth(bssid, neighbors):
    """neighbors: {mac: ip}. Returns (mac|None, ip|None, conf|None)."""
    if not bssid:
        return None, None, None
    b = bssid.upper()
    if b in neighbors:
        return b, neighbors[b], "exact"

    best, best_d = None, None
    for mac in neighbors:
        if mac == b or not _same_oui(mac, b):
            continue
        d = _int3(mac) - _int3(b)
        if abs(d) > 16:
            continue
        if best is None or abs(d) < abs(best_d) or \
                (abs(d) == abs(best_d) and mac < best):
            best, best_d = mac, d
    if best is not None:
        sign = "+" if best_d > 0 else "-"
        return best, neighbors[best], f"near{sign}{abs(best_d):x}"

    return _vap_match(b, neighbors)
