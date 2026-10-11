"""Nearly-realtime web UI: stdlib http.server on the Pi, JSON API consumed
by a single-page HTML/JS client that polls every 2s. No external deps."""

import json
import logging
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import nm

log = logging.getLogger("wifitester.web")


def _rowdicts(rows):
    return [dict(r) for r in rows]


def api_state(store, cfg, started):
    """Everything the status page needs, in one payload."""
    now = time.time()
    live = {"iface": cfg.interface,
            "connection": None, "bssid": None, "signal_dbm": None,
            "chan": None, "freq_mhz": None}
    try:
        live["connection"] = nm.current_connection(cfg.interface) or None
        link = nm.iw_link(cfg.interface)
        live.update({k: link[k] for k in
                     ("bssid", "signal_dbm", "chan", "freq_mhz") if k in link})
    except Exception as exc:  # radio busy mid-switch: show last known
        log.debug("live state unavailable: %s", exc)

    nodes = []
    for r in store.latest_visit_per_bssid(now - 86400):
        nodes.append({
            "ssid": r["ssid"], "bssid": r["bssid"], "ts": r["ts"],
            "age_s": round(now - r["epoch"]),
            "connect_ok": bool(r["connect_ok"]),
            "connect_error": r["connect_error"],
            "chan": r["chan"], "signal_dbm": r["signal_dbm"],
            "loss_pct": r["loss_pct"], "avg_rtt_ms": r["avg_rtt_ms"],
            "internet_ok": None if r["internet_ok"] is None
            else bool(r["internet_ok"]),
        })

    events = []
    for r in store.event_feed(now - 3600, limit=30):
        if not r["connect_ok"]:
            kind = "down"
            detail = (r["connect_error"] or "connect failed")[:120]
        elif r["loss_pct"] is not None and r["loss_pct"] >= 100:
            kind = "no_backhaul"
            detail = f"auth ok, 100% probe loss ({r['bssid']})"
        elif r["internet_ok"] == 0:
            kind = "no_internet"
            detail = f"gateway ok but WAN unreachable (loss {r['loss_pct']}%)"
        else:
            kind = "loss"
            detail = (f"{r['loss_pct']}% loss, rtt {r['avg_rtt_ms']}ms "
                      f"({r['bssid']})")
        events.append({"ts": r["ts"], "age_s": round(now - r["epoch"]),
                       "ssid": r["ssid"], "kind": kind, "detail": detail})

    last_scan = store.last_scan_epoch()
    return {
        "now": now,
        "uptime_s": round(now - started),
        "live": live,
        "nodes": nodes,
        "events": events,
        "suspects": _rowdicts(store.suspects(now - 86400)),
        "last_scan_age_s": (round(now - last_scan) if last_scan else None),
        "cycle": {
            "cycle_interval_s": cfg.cycle_interval_s,
            "probe_count": cfg.probe_count,
            "probe_interval_s": cfg.probe_interval_s,
            "connect_timeout_s": cfg.connect_timeout_s,
            "scan_interval_s": cfg.scan_interval_s,
            "static_ipv4": cfg.static_ipv4,
            "visit_items": len([1 for ap in cfg.aps if ap.enabled
                                for _ in (ap.expected_bssids or [None])]),
        },
    }


def api_series(store, hours):
    now = time.time()
    since = now - hours * 3600
    return {
        "now": now,
        "signal": [{"ssid": r["ssid"], "bssid": r["bssid"],
                    "epoch": r["epoch"], "dbm": r["signal_dbm"]}
                   for r in store.signal_series(since)],
        "loss": [{"ssid": r["ssid"], "bssid": r["bssid"],
                  "epoch": r["epoch"], "pct": r["loss_pct"]}
                 for r in store.loss_series(since)],
    }


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wifitester live</title>
<style>
:root{--bg:#0f1115;--fg:#e6e6e6;--mut:#8b93a1;--ok:#22c55e;--warn:#f59e0b;
--bad:#ef4444;--card:#171a21;--line:#262b36}
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--fg);
margin:0;padding:18px;max-width:1100px;margin:0 auto}
h1{font-size:20px;margin:0 0 4px}
h2{font-size:14px;color:var(--mut);text-transform:uppercase;
letter-spacing:.08em;margin:26px 0 8px}
.sub{color:var(--mut);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:12px 14px}
.k{color:var(--mut);font-size:12px}
.v{font-size:15px;margin-top:2px}
.big{font-size:22px;font-weight:600}
.ok{color:var(--ok)} .warn{color:var(--warn)} .bad{color:var(--bad)}
.mono{font-family:ui-monospace,monospace;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:500}
.badge{padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600}
.ssidtag{float:right;color:var(--mut);font-size:12px}
.ssidtag b{color:var(--fg);font-weight:600}
.b-ok{background:#14321f;color:var(--ok)}
.b-warn{background:#33260e;color:var(--warn)}
.b-bad{background:#3a1414;color:var(--bad)}
.event{padding:4px 0;border-bottom:1px solid var(--line);font-size:13px}
.age{color:var(--mut);font-size:12px;white-space:nowrap}
svg text{fill:var(--mut);font-size:11px}
@media(prefers-color-scheme:light){:root{--bg:#fff;--fg:#111;--mut:#666;
--card:#f6f7f9;--line:#e5e7eb}}
</style></head><body>
<h1>wifitester <span id="dot" class="ok">&#9679;</span></h1>
<div class="sub" id="hdr">&mdash;</div>

<h2>Live link</h2>
<div class="grid">
 <div class="card"><div class="k">associated ssid</div><div class="big" id="l-ssid">&mdash;</div></div>
 <div class="card"><div class="k">bssid</div><div class="v mono" id="l-bssid">&mdash;</div></div>
 <div class="card"><div class="k">signal</div><div class="big" id="l-sig">&mdash;</div></div>
 <div class="card"><div class="k">channel</div><div class="v" id="l-chan">&mdash;</div></div>
</div>

<h2>Mesh nodes (per BSSID)</h2>
<div class="grid" id="aps"></div>

<h2>Signal, last 2h (dBm)</h2>
<div class="card"><div id="c-sig">loading&hellip;</div></div>
<h2>Probe loss, last 2h (%)</h2>
<div class="card"><div id="c-loss">loading&hellip;</div></div>

<h2>Events (last hour)</h2>
<div class="card" id="events"><div class="sub">none</div></div>

<h2>Suspects (24h)</h2>
<div class="card" id="suspects"><div class="sub">none</div></div>

<script>
const PALETTE=["#3b82f6","#ef4444","#22c55e","#a855f7","#f59e0b","#06b6d4","#ec4899","#84cc16"];
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function ago(s){if(s<90)return s+'s';if(s<5400)return Math.round(s/60)+'m';
if(s<172800)return Math.round(s/3600)+'h';return Math.round(s/86400)+'d'}
function fmt(s){return s?esc(s.replace('T',' ').replace('Z','')):'-'}

function nodeCard(n){
 let cls='b-bad',label='DOWN',txt=esc((n.connect_error||'connect failed').slice(0,70));
 if(n.connect_ok){
  if(n.loss_pct>=100){label='NO BACKHAUL';cls='b-bad';txt='assoc ok, zero probes pass'}
  else if(n.loss_pct>0){label='LOSS '+n.loss_pct+'%';cls='b-warn';txt='rtt '+n.avg_rtt_ms+'ms'}
  else{label='OK';cls='b-ok';txt=(n.signal_dbm??'?')+' dBm &middot; rtt '+n.avg_rtt_ms+'ms'+
   (n.internet_ok===false?' &middot; <span class=bad>WAN down</span>':'')}
 }
 return `<div class="card"><div class="k"><span class="badge ${cls}">${label}</span>
 <span class="ssidtag">ssid: <b>${esc(n.ssid||'-')}</b></span></div>
 <div class="v mono">${esc(n.bssid||'-')}</div>
 <div class="sub">ch${n.chan??'-'} &middot; ${(n.signal_dbm??'?')} dBm &middot; rtt ${n.avg_rtt_ms??'-'}ms</div>
 <div class="sub">${txt}</div>
 <div class="sub">probed ${ago(n.age_s)} ago</div></div>`;
}

function chart(el, series, yInv, yLabel){
 if(!series.length||series.every(s=>!s.pts.length)){el.innerHTML='<div class="sub">no data yet</div>';return}
 const W=Math.min(el.clientWidth||900,1040),H=220,m={l:44,r:12,t:10,b:22};
 const pts=series.flatMap(s=>s.pts);
 let x0=Math.min(...pts.map(p=>p[0])),x1=Math.max(...pts.map(p=>p[0]));
 if(x1-x0<60)x1=x0+60;
 let v0=Math.min(...pts.map(p=>p[1])),v1=Math.max(...pts.map(p=>p[1]));
 const pad=Math.max((v1-v0)*.1,1);v0-=pad;v1+=pad;
 const X=t=>m.l+(t-x0)/(x1-x0)*(W-m.l-m.r);
 const Y=v=>{let f=(v-v0)/(v1-v0);if(yInv)f=1-f;return m.t+(H-m.t-m.b)*(1-f)};
 let o=`<svg width="${W}" height="${H}" role="img">`;
 for(let i=0;i<4;i++){const v=v0+(v1-v0)*i/3,y=Y(v);
  o+=`<line x1="${m.l}" y1="${y}" x2="${W-m.r}" y2="${y}" stroke="var(--line)"/>`;
  o+=`<text x="${m.l-6}" y="${y+4}" text-anchor="end">${v.toFixed(0)}</text>`}
 for(let i=0;i<=4;i++){const t=x0+(x1-x0)*i/4,x=X(t);
  const d=new Date(t*1000);
  o+=`<text x="${x}" y="${H-6}" text-anchor="middle">${d.toTimeString().slice(0,5)}</text>`}
 o+=`<text x="8" y="${m.t+10}">${yLabel}</text>`;
 series.forEach((s,i)=>{if(s.pts.length<1)return;const c=PALETTE[i%PALETTE.length];
  if(s.pts.length>1)o+=`<polyline fill="none" stroke="${c}" stroke-width="1.5" points="${
   s.pts.map(p=>X(p[0]).toFixed(1)+','+Y(p[1]).toFixed(1)).join(' ')}"/>`;
  s.pts.forEach(p=>{o+=`<circle cx="${X(p[0]).toFixed(1)}" cy="${Y(p[1]).toFixed(1)}" r="2.6" fill="${c}"><title>${esc(s.label)} ${new Date(p[0]*1000).toTimeString().slice(0,8)}: ${p[1]}</title></circle>`});
  o+=`<rect x="${m.l+i*150}" y="${H-m.b-12}" width="9" height="9" fill="${c}"/>`;
  o+=`<text x="${m.l+i*150+13}" y="${H-m.b-4}">${esc(s.label)}</text>`});
 el.innerHTML=o+'</svg>';
}

function sigClass(dbm){if(dbm==null)return'';
 if(dbm>=-55)return'ok';if(dbm>=-70)return'warn';return'bad'}

async function pollState(){
 try{
  const s=await(await fetch('/api/state')).json();
  $('dot').className='ok';
  const l=s.live;
  $('hdr').textContent=`live view of ${l.iface}`+
   (s.cycle.static_ipv4?` &middot; static ${s.cycle.static_ipv4}`:'')+
   ` &middot; ${s.cycle.visit_items} node probes/sweep &middot; cycle ${s.cycle.cycle_interval_s}s `+
   `(${s.cycle.probe_count} probes / ${s.cycle.probe_interval_s}s) &middot; scan ${s.cycle.scan_interval_s}s`+
   (s.last_scan_age_s!=null?` &middot; last scan ${ago(s.last_scan_age_s)} ago`:'')+
   ` &middot; up ${ago(s.uptime_s)}`;
  $('hdr').innerHTML=$('hdr').textContent;
  $('l-ssid').textContent=l.connection?l.connection.replace(/^wt-/,''):'-';
  $('l-bssid').textContent=l.bssid||'-';
  $('l-sig').innerHTML=l.signal_dbm!=null?
   `<span class="${sigClass(l.signal_dbm)}">${l.signal_dbm} dBm</span>`:'-';
  $('l-chan').textContent=l.chan?`ch${l.chan} (${l.freq_mhz} MHz)`:'-';
  const nodes=[...s.nodes].sort((a,b)=>(a.bssid||'').localeCompare(b.bssid||''));
  $('aps').innerHTML=nodes.map(nodeCard).join('')||'<div class="sub">no probes yet</div>';
  $('events').innerHTML=s.events.length?s.events.map(e=>{
   const cls=e.kind==='loss'?'warn':'bad';
   return `<div class="event"><span class="badge b-${cls}">${e.kind.toUpperCase()}</span>
    <b>${esc(e.ssid)}</b> <span class="sub">${esc(e.detail)}</span>
    <span class="age">${ago(e.age_s)} ago</span></div>`}).join('')
   :'<div class="sub">none &mdash; clean hour</div>';
  $('suspects').innerHTML=s.suspects.length?
   '<table><tr><th>verdict</th><th>ssid</th><th>bssid</th><th>loss%</th><th>connects</th></tr>'+
   s.suspects.map(r=>`<tr><td><span class="badge b-bad">${r.verdict}</span></td>
    <td>${esc(r.ssid)}</td><td class="mono">${esc(r.bssid||'-')}</td>
    <td>${r.avg_loss_pct??'-'}</td><td>${r.connects}/${r.visits}</td></tr>`).join('')+'</table>'
   :'<div class="sub">none</div>';
 }catch(e){$('dot').className='bad'}
}

async function pollSeries(){
 try{
  const s=await(await fetch('/api/series?hours=2')).json();
  const by={};
  s.signal.forEach(r=>{const k=`${r.bssid} ${r.ssid}`;
   (by[k]=by[k]||[]).push([r.epoch,r.dbm])});
  chart($('c-sig'),Object.entries(by).map(([label,pts])=>({label,pts})),true,'dBm');
  const byL={};
  s.loss.forEach(r=>{const k=`${r.bssid} ${r.ssid}`;
   (byL[k]=byL[k]||[]).push([r.epoch,r.pct])});
  chart($('c-loss'),Object.entries(byL).map(([label,pts])=>({label,pts})),false,'%');
 }catch(e){}
}

pollState();pollSeries();
setInterval(pollState,2000);setInterval(pollSeries,5000);
</script></body></html>
"""


def make_handler(store, cfg, started):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # quiet: journald only on error
            log.debug("%s %s", self.address_string(), fmt % args)

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            try:
                if path in ("/", "/index.html"):
                    body = PAGE.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif path == "/api/state":
                    self._json(api_state(store, cfg, started))
                elif path == "/api/series":
                    q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                    hours = min(float(q.get("hours", ["2"])[0]), 48.0)
                    self._json(api_series(store, hours))
                else:
                    self._json({"error": "not found"}, code=404)
            except Exception:
                log.exception("request %s failed", path)
                try:
                    self._json({"error": "internal"}, code=500)
                except Exception:
                    pass

    return Handler


def serve(store, cfg, host="0.0.0.0", port=8787):
    started = time.time()
    httpd = ThreadingHTTPServer((host, port), make_handler(store, cfg, started))
    log.info("web UI on http://%s:%d (also http://%s:%d via wlan0)",
             host if host != "0.0.0.0" else _primary_ip(), port,
             _wlan_ip() or host, port)
    httpd.serve_forever()


def _primary_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.168.1.1", 53))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _wlan_ip():
    import subprocess
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr", "show", "dev", "wlan0"],
                             capture_output=True, text=True, timeout=5).stdout
        import json as j
        info = j.loads(out)
        return info[0]["addr_info"][0]["local"]
    except Exception:
        return None
