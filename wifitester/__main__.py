"""CLI: python3 -m wifitester {run|probe|scan|report|dashboard|validate}."""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from . import __version__, config, graph, nm, runner, store


def _data_dir(args):
    return Path(args.data)


def _load_cfg(path):
    cfg, warns = config.load(path)
    for w in warns:
        print(f"warning: {w}", file=sys.stderr)
    return cfg


def _open_store(args):
    return store.Store(_data_dir(args))


def cmd_validate(args):
    cfg, warns = config.load(args.config)
    for w in warns:
        print(f"warning: {w}", file=sys.stderr)
    nm.nmcli_version()
    if not nm.wifi_interface_present(cfg.interface):
        print(f"error: wifi interface {cfg.interface} not present",
              file=sys.stderr)
        return 1
    if cfg.require_wired_uplink and not nm.wired_uplink_present():
        print("error: no wired uplink; cycling wifi would cut access to this "
              "Pi (override: require_wired_uplink=false)", file=sys.stderr)
        return 1
    print(f"ok: {len([a for a in cfg.aps if a.enabled])} APs, iface "
          f"{cfg.interface}, cycle {cfg.cycle_interval_s}s, "
          f"scan {cfg.scan_interval_s}s")
    return 0


def cmd_run(args):
    cfg = _load_cfg(args.config)
    st = _open_store(args)
    r = runner.Runner(cfg, st)
    try:
        r.run(once=args.once, do_scan=not args.no_scan)
    except runner.PreflightError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        st.close()
    return 0


def cmd_probe(args):
    cfg = _load_cfg(args.config)
    ap = next((a for a in cfg.aps if a.ssid == args.ssid and a.enabled), None)
    if ap is None:
        print(f"error: ssid {args.ssid!r} not in config (or disabled)",
              file=sys.stderr)
        return 1
    st = _open_store(args)
    r = runner.Runner(cfg, st)
    try:
        r.preflight()
        rec = r.visit_ap(ap)
        st.insert_visit(rec)
    except (runner.PreflightError, nm.CommandError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        r._restore()
        st.close()
    print(json.dumps(rec, indent=2, sort_keys=True))
    return 0 if rec.get("connect_ok") and (rec.get("loss_pct") or 0) < 100 else 1


def cmd_scan(args):
    cfg = _load_cfg(args.config)
    st = _open_store(args)
    r = runner.Runner(cfg, st)
    try:
        r.preflight()
        nets = r.scan_pass()
    except (runner.PreflightError, nm.CommandError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        st.close()
    if args.json:
        print(json.dumps(nets, indent=2))
    return 0


def _print_table(headers, rows):
    if not rows:
        print("  (no data)")
        return
    widths = [len(h) for h in headers]
    srows = [[str(c) for c in r] for r in rows]
    for r in srows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in srows:
        print(fmt.format(*r))


def cmd_report(args):
    st = _open_store(args)
    since = time.time() - args.hours * 3600
    print(f"== suspects (last {args.hours}h) "
          "==")
    _print_table(["verdict", "SSID", "BSSID", "visits", "loss%", "connects",
                  "last visit"],
                 [[r["verdict"], r["ssid"], r["bssid"] or "-", r["visits"],
                   r["avg_loss_pct"], f"{r['connects']}/{r['visits']}",
                   r["last_ts"]] for r in st.suspects(since)])
    print(f"\n== per-BSSID summary (last {args.hours}h) ==")
    cls = {r["bssid"]: r["classification"]
           for r in st.latest_classification(since)}
    _print_table(
        ["SSID", "BSSID", "visits", "connects", "avg dBm", "loss%",
         "rtt ms", "scan class", "last seen"],
        [[r["ssid"], r["bssid"], r["visits"],
          f"{r['connects']}/{r['visits']}", r["avg_signal_dbm"],
          r["avg_loss_pct"], r["avg_rtt_ms"], cls.get(r["bssid"], "-"),
          time.strftime("%m-%d %H:%M", time.localtime(r["last_epoch"]))]
         for r in st.bssid_summary(since)])
    print(f"\n== scan classification (last {args.hours}h, by signal) ==")
    _print_table(
        ["SSID", "BSSID", "ch", "sig%", "security", "class", "seen"],
        [[r["ssid"] or "<hidden>", r["bssid"], r["chan"], r["signal_pct"],
          r["security"] or "open", r["classification"],
          time.strftime("%m-%d %H:%M", time.localtime(r["last_epoch"]))]
         for r in st.latest_classification(since)])
    print("\n== recent visits ==")
    _print_table(
        ["time", "SSID", "BSSID", "ch", "dBm", "loss%", "rtt ms", "gw",
         "net"],
        [[r["ts"], r["ssid"], r["bssid"] or "-", r["chan"],
          r["signal_dbm"], r["loss_pct"], r["avg_rtt_ms"],
          r["gateway"] or "-",
          "-" if r["internet_ok"] is None else "ok" if r["internet_ok"] else "FAIL"]
         for r in st.visit_log(since, limit=args.limit)])
    st.close()
    return 0


def cmd_dashboard(args):
    st = _open_store(args)
    since = time.time() - args.hours * 3600
    out = graph.build_dashboard(st, since,
                                _data_dir(args) / "dashboard.html")
    st.close()
    print(out)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="wifitester",
        description="Round-robin AP connectivity prober with RF classification")
    ap.add_argument("--version", action="version",
                    version=f"wifitester {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    # SUPPRESS: when the flag is absent at subcommand level, keep the
    # top-level value instead of stomping it with a local default
    common.add_argument("-c", "--config", default=argparse.SUPPRESS,
                        help="config.toml (default: /etc/wifitester/config.toml, "
                             "then ./config.toml)")
    common.add_argument("-d", "--data", default=argparse.SUPPRESS,
                        help="datastore directory (default ./data)")
    ap.add_argument("-c", "--config", default=None, help=argparse.SUPPRESS)
    ap.add_argument("-d", "--data", default="./data", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, help, **kw):
        p = sub.add_parser(name, parents=[common], help=help,
                           description=help, **kw)
        return p

    add("validate", "check config + environment").set_defaults(fn=cmd_validate)
    p = add("run", "daemon loop")
    p.add_argument("--once", action="store_true", help="one cycle, then exit")
    p.add_argument("--no-scan", action="store_true")
    p.set_defaults(fn=cmd_run)
    p = add("probe", "single AP visit + probe")
    p.add_argument("ssid")
    p.set_defaults(fn=cmd_probe)
    p = add("scan", "one scan + classification pass")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_scan)
    p = add("report", "text report from the datastore")
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(fn=cmd_report)
    p = add("dashboard", "write dashboard.html (graphs)")
    p.add_argument("--hours", type=float, default=24)
    p.set_defaults(fn=cmd_dashboard)

    args = ap.parse_args(argv)
    if args.config is None:
        for cand in ("/etc/wifitester/config.toml", "config.toml"):
            if Path(cand).is_file():
                args.config = cand
                break
        else:
            ap.error("no config found (use -c path/to/config.toml)")
    argv = sys.argv[1:] if argv is None else argv
    logging.basicConfig(
        level=logging.DEBUG if "-v" in argv else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
