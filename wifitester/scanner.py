"""RF neighborhood classification.

Plan step is pure (testable); execution of auth attempts lives in runner.
Classifications:
  OURS                trusted pin or PSK-authenticated by us
  KNOWN_UNVERIFIED    configured AP we could not verify (no psk / probing off)
  ROGUE_SSID          correct SSID, rejects our PSK
  AUTH_TIMEOUT        association attempt timed out (ambiguous)
  OPEN_FOREIGN        unknown open network, association succeeded
  OPEN_FOREIGN_REFUSED unknown open network refused association
  SECURED_FOREIGN     unknown secured network (not attempted)
  SECURED_8021X       unknown 802.1X network (needs enterprise creds)
  HIDDEN              hidden SSID broadcast
"""

HIDDEN = "HIDDEN"

PLAN_RECORD = "record"      # classification known, no radio action
PLAN_AUTH = "auth"          # try PSK association with our credentials
PLAN_ASSOC = "assoc"        # try association with an open network
PLAN_SKIP = "skip"          # known config but no usable credentials


def group_networks(nets):
    """Dedupe per BSSID (keep strongest), group into {ssid: [net]}.
    Hidden SSIDs grouped under ''."""
    best = {}
    for n in nets:
        b = n["bssid"]
        if b not in best or (n.get("signal") or 0) > (best[b].get("signal") or 0):
            best[b] = n
    groups = {}
    for n in best.values():
        groups.setdefault(n["ssid"], []).append(n)
    return groups


def plan(groups, known_by_ssid, auth_probe="mismatch_only", open_assoc=True):
    """Return list of (net, action, classification|None).

    known_by_ssid: {ssid: {"psk": str|None, "expected_bssids": [..]}}
    auth_probe: never | mismatch_only | all
      - never:          never spend radio time on auth attempts
      - mismatch_only:  auth-test known-SSID BSSIDs we have not pinned trusted
      - all:            same as mismatch_only (pinned ones are already trusted)
    """
    items = []
    for ssid, nets in sorted(groups.items()):
        known = known_by_ssid.get(ssid)
        for net in sorted(nets, key=lambda n: -(n.get("signal") or 0)):
            bssid = net["bssid"]
            if ssid == "":
                items.append((net, PLAN_RECORD, HIDDEN))
                continue
            if known is not None:
                if bssid in known.get("expected_bssids", []):
                    items.append((net, PLAN_RECORD, "OURS"))
                elif known.get("psk") is None or auth_probe == "never":
                    items.append((net, PLAN_RECORD, "KNOWN_UNVERIFIED"))
                else:
                    items.append((net, PLAN_AUTH, None))
                continue
            security = (net.get("security") or "").upper()
            if "802.1X" in security or "8021X" in security:
                items.append((net, PLAN_RECORD, "SECURED_8021X"))
            elif not security:
                if open_assoc:
                    items.append((net, PLAN_ASSOC, None))
                else:
                    items.append((net, PLAN_RECORD, "OPEN_FOREIGN"))
            else:
                items.append((net, PLAN_RECORD, "SECURED_FOREIGN"))
    return items


def auth_outcome_to_classification(ok, timed_out):
    if timed_out:
        return "AUTH_TIMEOUT"
    return "OURS" if ok else "ROGUE_SSID"


def assoc_outcome_to_classification(ok):
    return "OPEN_FOREIGN" if ok else "OPEN_FOREIGN_REFUSED"


def classify_all(items, results):
    """Attach final classification to every net. results maps
    (bssid, action) -> classification for PLAN_AUTH/PLAN_ASSOC items."""
    nets = []
    for net, action, cls in items:
        if action in (PLAN_AUTH, PLAN_ASSOC):
            cls = results.get((net["bssid"], action), "AUTH_TIMEOUT")
        nets.append({**net, "classification": cls})
    return nets
