"""SVG graph + HTML dashboard generation from the SQLite datastore.
Stdlib-only: charts are hand-built SVG, wrapped in one dashboard.html."""

import html
import time
from pathlib import Path

PALETTE = ["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c",
           "#0891b2", "#be185d", "#65a30d", "#7c3aed", "#0f766e"]


def _axis_ticks(lo, hi, n=5):
    if lo == hi:
        lo, hi = lo - 1, hi + 1
    step = (hi - lo) / (n - 1)
    return [lo + i * step for i in range(n)]


def _fmt_t(epoch):
    return time.strftime("%H:%M", time.localtime(epoch))


def _fmt_d(epoch):
    return time.strftime("%m-%d %H:%M", time.localtime(epoch))


def line_chart(series, title, y_label, y_invert=False, width=900, height=340,
               point_r=3.0):
    """series: {label: [(epoch, value), ...]} -> SVG string."""
    m = {"l": 60, "r": 20, "t": 40, "b": 46}
    pw, ph = width - m["l"] - m["r"], height - m["t"] - m["b"]
    pts = [(x, y) for s in series.values() for x, y in s]
    if not pts:
        return (f"<svg width='{width}' height='{height}' role='img'>"
                f"<text x='{width/2}' y='{height/2}' text-anchor='middle' "
                f"fill='#888'>{html.escape(title)}: no data</text></svg>")
    x0, x1 = min(p[0] for p in pts), max(p[0] for p in pts)
    if x0 == x1:
        x1 = x0 + 60
    y0, y1 = min(p[1] for p in pts), max(p[1] for p in pts)
    pad = max((y1 - y0) * 0.08, 1.0)
    y0, y1 = y0 - pad, y1 + pad

    def X(e):
        return m["l"] + (e - x0) * pw / (x1 - x0)

    def Y(v):
        f = (v - y0) / (y1 - y0)
        if y_invert:
            f = 1 - f
        return m["t"] + ph - f * ph

    out = [f"<svg width='{width}' height='{height}' role='img' "
           f"xmlns='http://www.w3.org/2000/svg' font-family='sans-serif' "
           f"font-size='12'>"]
    out.append(f"<text x='{m['l']}' y='18' font-size='14' font-weight='bold' "
               f"fill='#111'>{html.escape(title)}</text>")
    # grid + axes labels
    for v in _axis_ticks(y0, y1):
        y = Y(v)
        out.append(f"<line x1='{m['l']}' y1='{y:.1f}' x2='{width-m['r']}' "
                   f"y2='{y:.1f}' stroke='#e5e7eb'/>")
        out.append(f"<text x='{m['l']-8}' y='{y+4:.1f}' text-anchor='end' "
                   f"fill='#666'>{v:.0f}</text>")
    for f in (0, .25, .5, .75, 1):
        e = x0 + f * (x1 - x0)
        x = X(e)
        out.append(f"<line x1='{x:.1f}' y1='{m['t']}' x2='{x:.1f}' "
                   f"y2='{height-m['b']}' stroke='#f3f4f6'/>")
        out.append(f"<text x='{x:.1f}' y='{height-m['b']+16}' "
                   f"text-anchor='middle' fill='#666'>{_fmt_t(e)}</text>")
    out.append(f"<line x1='{m['l']}' y1='{height-m['b']}' x2='{width-m['r']}' "
               f"y2='{height-m['b']}' stroke='#9ca3af'/>")
    out.append(f"<text x='{m['l']-46}' y='{m['t']+ph/2}' fill='#666' "
               f"transform='rotate(-90 {m['l']-46} {m['t']+ph/2})' "
               f"text-anchor='middle'>{html.escape(y_label)}</text>")
    # series
    for i, (label, data) in enumerate(series.items()):
        color = PALETTE[i % len(PALETTE)]
        if len(data) > 1:
            d = " ".join(f"{X(e):.1f},{Y(v):.1f}" for e, v in data)
            out.append(f"<polyline points='{d}' fill='none' stroke='{color}' "
                       f"stroke-width='1.6'/>")
        for e, v in data:
            x, y = X(e), Y(v)
            out.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='{point_r}' "
                       f"fill='{color}'><title>{html.escape(label)} "
                       f"{_fmt_d(e)}: {v:g}</title></circle>")
    # legend
    lx = m["l"]
    for i, label in enumerate(series):
        color = PALETTE[i % len(PALETTE)]
        out.append(f"<rect x='{lx}' y='{height-20}' width='10' height='10' "
                   f"fill='{color}'/>")
        out.append(f"<text x='{lx+14}' y='{height-11}' fill='#333'>"
                   f"{html.escape(label)}</text>")
        lx += 16 + 7.2 * len(label) + 18
    out.append("</svg>")
    return "".join(out)


def _table(headers, rows):
    out = ["<table>", "<tr>" +
           "".join(f"<th>{html.escape(h)}</th>" for h in headers) + "</tr>"]
    for r in rows:
        out.append("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>"
                                    for c in r) + "</tr>")
    out.append("</table>")
    return "".join(out)


def build_dashboard(store, since_epoch, out_path):
    """Write dashboard.html with signal/loss/neighbor charts + tables."""
    sig_rows = store.signal_series(since_epoch)
    series = {}
    for r in sig_rows:
        series.setdefault(f"{r['ssid']} ({r['bssid']})", []).append(
            (r["epoch"], r["signal_dbm"]))
    chart_sig = line_chart(series, "Signal strength per visit (dBm, higher=better)",
                           "dBm", y_invert=True)

    loss_rows = store.loss_series(since_epoch)
    series = {}
    for r in loss_rows:
        series.setdefault(f"{r['ssid']} ({r['bssid']})", []).append(
            (r["epoch"], r["loss_pct"]))
    chart_loss = line_chart(series, "Probe loss per visit (%)",
                            "loss %", point_r=3.5)

    nb_rows = store.neighbor_series(since_epoch)
    latest_bssids = {}
    for r in nb_rows:
        latest_bssids[r["bssid"]] = r["signal_pct"] or 0
    top = sorted(latest_bssids, key=latest_bssids.get, reverse=True)[:10]
    series = {}
    for r in nb_rows:
        if r["bssid"] in top and r["signal_pct"] is not None:
            label = f"{r['ssid'] or '<hidden>'} ({r['bssid']})"
            series.setdefault(label, []).append((r["epoch"], r["signal_pct"]))
    chart_nb = line_chart(series, "Neighbor APs (scan signal %)",
                          "signal %", height=380)

    summ = store.bssid_summary(since_epoch)
    cls_by_bssid = {r["bssid"]: r["classification"]
                    for r in store.latest_classification(since_epoch)}
    t_rows = []
    for r in summ:
        t_rows.append([r["ssid"], r["bssid"], r["visits"], f"{r['connects']}/{r['visits']}",
                       r["avg_signal_dbm"], r["avg_loss_pct"],
                       r["avg_rtt_ms"], cls_by_bssid.get(r["bssid"], "-"),
                       _fmt_d(r["last_epoch"])])
    table_summary = _table(
        ["SSID", "BSSID", "visits", "connects", "avg dBm", "avg loss %",
         "avg rtt ms", "scan class", "last seen"], t_rows)

    sus = store.suspects(since_epoch)
    sus_rows = [[r["verdict"], r["ssid"], r["bssid"], r["visits"],
                 r["avg_loss_pct"], f"{r['connects']}/{r['visits']}", r["last_ts"]]
                for r in sus]
    table_suspects = _table(
        ["verdict", "SSID", "BSSID", "visits", "avg loss %", "connects",
         "last visit"], sus_rows)

    span_h = int((time.time() - since_epoch) / 3600) if since_epoch else 0
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>wifitester dashboard</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:24px;color:#111;background:#fff}}
 h1{{font-size:22px}} h2{{font-size:16px;margin-top:28px}}
 .sub{{color:#666;font-size:13px}}
 table{{border-collapse:collapse;font-size:13px;margin-top:8px}}
 th,td{{border:1px solid #e5e7eb;padding:4px 8px;text-align:left}}
 th{{background:#f3f4f6}}
 .chart{{margin-top:12px}}
 .no-backhaul{{color:#dc2626;font-weight:bold}}
</style></head><body>
<h1>wifitester dashboard</h1>
<p class="sub">window: last {max(span_h,1)}h &middot; generated
{time.strftime("%Y-%m-%d %H:%M:%S")}</p>

<h2>Suspects &mdash; dropping data or broadcasting with nothing behind it</h2>
<p class="sub">no_backhaul = authenticated fine but 100% probe loss;
dropping = packet loss on gateway pings; failing = could not connect.</p>
{table_suspects}

<h2>Signal strength per visit</h2><div class="chart">{chart_sig}</div>
<h2>Probe loss per visit</h2><div class="chart">{chart_loss}</div>
<h2>Neighbor APs</h2><div class="chart">{chart_nb}</div>

<h2>Per-BSSID summary</h2>
{table_summary}
</body></html>"""
    out_path = Path(out_path)
    out_path.write_text(doc, encoding="utf-8")
    return out_path
