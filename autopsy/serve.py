"""Local web explorer for one autopsy: `autopsy serve <out>` -> http://127.0.0.1:8765

Binds to localhost only. No external assets, no telemetry.
"""
from __future__ import annotations

import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .index import Index

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Autopsy explorer</title><style>
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--mute:#6b6b66;--line:#e2e1dc;--acc:#b4441c;--acc2:#1f6f8b;--code:#f1f0ec;--str:#2e7d32;--kw:#8e3fa8}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--panel:#1c1c1a;--ink:#ecebe6;--mute:#a09f99;--line:#33332f;--acc:#e0764e;--acc2:#6bb3cc;--code:#232320;--str:#8fce8f;--kw:#d59ce8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:13px/1.45 system-ui,Segoe UI,sans-serif;height:100vh;display:flex;flex-direction:column}
header{padding:10px 14px;border-bottom:1px solid var(--line);background:var(--panel);display:flex;gap:10px;align-items:center;flex-wrap:wrap}
header b{font-size:15px}input,select,button{font:inherit;padding:6px 9px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink)}
input#q{flex:1;min-width:220px}button{cursor:pointer}button:hover{border-color:var(--acc)}
.wrap{flex:1;display:flex;min-height:0}#list{width:38%;min-width:260px;overflow:auto;border-right:1px solid var(--line);background:var(--panel)}
#list div{padding:5px 10px;border-bottom:1px solid var(--line);cursor:pointer;font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
#list div:hover{background:var(--code)}#list .k{color:var(--mute);font-family:system-ui;font-size:11px;margin-right:6px}
#detail{flex:1;overflow:auto;padding:12px 16px}pre{background:var(--code);padding:10px 12px;border-radius:8px;overflow:auto;font:12px/1.45 ui-monospace,Consolas,monospace}
a.ref{color:var(--acc2);text-decoration:none;cursor:pointer}a.ref:hover{text-decoration:underline}.s{color:var(--str)}.op{color:var(--kw)}
h2{font-size:14px;margin:6px 0;word-break:break-all}h3{font-size:12px;color:var(--mute);margin:14px 0 4px;text-transform:uppercase;letter-spacing:.04em}
.chip{display:inline-block;font-size:11px;padding:1px 7px;border-radius:10px;background:var(--code);margin:1px 3px 1px 0}
@media (max-width:760px){.wrap{flex-direction:column}#list{width:auto;max-height:40vh;border-right:0;border-bottom:1px solid var(--line)}}
</style></head><body>
<header><b>Autopsy explorer</b><span id="title" class="chip"></span>
<select id="kind"><option value="method">methods</option><option value="class">classes</option><option value="string">strings</option>
<option value="ref">callers of ref</option><option value="seam">seam candidates</option></select>
<input id="q" placeholder="search… (e.g. AdBreak, getAdCuePoints, /ads/)"><button id="go">Search</button>
<a class="ref" href="/report" target="_blank">report ↗</a></header>
<div class="wrap"><div id="list"></div><div id="detail"><p style="color:var(--mute)">Search on the left. Click a method to see smali; every
<span class="chip">invoke</span> target and caller is clickable.</p></div></div>
<script>
const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function api(p){const r=await fetch(p);return r.json()}
async function search(){const k=$('#kind').value,q=$('#q').value.trim();const d=await api(`/api/search?kind=${k}&q=${encodeURIComponent(q)}`);
 const L=$('#list');L.innerHTML='';for(const it of d.items){const el=document.createElement('div');el.innerHTML=`<span class="k">${esc(it.k)}</span>${esc(it.label)}`;
 el.onclick=()=>it.id?showMethod(it.id):showClass(it.cls);L.appendChild(el)} if(!d.items.length)L.innerHTML='<div>no results</div>'}
function linkify(smali){return esc(smali).replace(/(L[\w\/$\-]+;-&gt;[\w$&lt;&gt;\-]+\([^)]*\)[\w\/$\[;]+)/g,m=>`<a class="ref" data-sig="${m}">${m}</a>`)
 .replace(/(&quot;.*?&quot;)/g,'<span class="s">$1</span>').replace(/^(\s+)(invoke-[\w\/-]+|const-string[\w\/]*|return[\w-]*|if-\w+|goto[\w\/]*|iget[\w-]*|iput[\w-]*|sget[\w-]*|sput[\w-]*|new-instance)/gm,'$1<span class="op">$2</span>')}
function unesc(s){const t=document.createElement('textarea');t.innerHTML=s;return t.value}
function wire(){document.querySelectorAll('a.ref[data-sig]').forEach(a=>a.onclick=()=>openSig(unesc(a.dataset.sig)));
 document.querySelectorAll('a.ref[data-id]').forEach(a=>a.onclick=()=>showMethod(a.dataset.id));
 document.querySelectorAll('a.ref[data-cls]').forEach(a=>a.onclick=()=>showClass(a.dataset.cls))}
async function openSig(sig){const d=await api('/api/resolve?sig='+encodeURIComponent(sig));if(d.id)showMethod(d.id);else{$('#kind').value='ref';$('#q').value=sig;search()}}
async function showMethod(id){const d=await api('/api/method?id='+id);const D=$('#detail');
 D.innerHTML=`<h2>${esc(d.sig)}</h2><span class="chip">#${d.id}</span><span class="chip">${esc(d.owner)}</span><span class="chip">source ${esc(d.source)}</span>
 <a class="ref" data-cls="${esc(d.cls)}">class outline</a> · <a class="ref" id="fpbtn">draft fingerprint</a>
 <div id="fp"></div><h3>smali</h3><pre>${linkify(d.smali)}</pre>
 <h3>callers (${d.callers.length})</h3>${d.callers.map(c=>`<div><a class="ref" data-id="${c.id}">${esc(c.sig)}</a></div>`).join('')||'<i>none in index</i>'}
 <h3>strings</h3>${d.strings.map(s=>`<div class="s">"${esc(s)}"</div>`).join('')||'<i>none</i>'}`;wire();
 $('#fpbtn').onclick=async()=>{const f=await api('/api/fp?id='+id);$('#fp').innerHTML=`<h3>fingerprint — matches ${f.matches}${f.unique?' (unique)':''}</h3>${f.notes.map(n=>`<div>${esc(n)}</div>`).join('')}<pre>${esc(f.kotlin)}</pre>`}}
async function showClass(cls){const d=await api('/api/class?name='+encodeURIComponent(cls));const D=$('#detail');if(!d.name){D.innerHTML='not in index';return}
 D.innerHTML=`<h2>${esc(d.name)}</h2><div>extends <a class="ref" data-cls="${esc(d.super)}">${esc(d.super)}</a> ${d.interfaces?'implements '+esc(d.interfaces):''}</div>
 <span class="chip">source ${esc(d.source)}</span><span class="chip">${esc(d.owner)}</span><h3>fields</h3><pre>${d.fields.map(esc).join('\n')||'—'}</pre>
 <h3>methods</h3>${d.methods.map(m=>`<div><a class="ref" data-id="${m.id}">${esc(m.label)}</a></div>`).join('')}`;wire()}
$('#go').onclick=search;$('#q').addEventListener('keydown',e=>{if(e.key==='Enter')search()});
api('/api/info').then(d=>{$('#title').textContent=d.title;$('#kind').value='seam';search()});
</script></body></html>"""


def make_api(out_dir: str):
    """The explorer's JSON API for one autopsy dir: (api(path, qs) -> dict, lock, idx, report).
    Shared by `serve` and the GUI (which keeps one per open scan)."""
    idx_path = os.path.join(out_dir, "index.sqlite")
    lock = threading.Lock()
    idx = Index(idx_path)
    idx.db.close()
    import sqlite3
    idx.db = sqlite3.connect(idx_path, check_same_thread=False)
    idx.db.row_factory = sqlite3.Row
    report = {}
    rp = os.path.join(out_dir, "report.json")
    if os.path.exists(rp):
        with open(rp, encoding="utf-8") as f:
            report = json.load(f)
    hunter_box = {}

    def owner(r):
        return r["sdk"] or ("app" if r["is_app"] else "library")

    def api(path, qs):
        g = lambda k, d="": qs.get(k, [d])[0]  # noqa: E731
        if path == "/api/info":
            m = report.get("manifest", {})
            return {"title": f"{m.get('package', '?')} {m.get('versionName', '')}"}
        if path == "/api/search":
            kind, q = g("kind", "method"), g("q")
            items = []
            if kind == "seam":
                for c in report.get("seams", {}).get("candidates", []):
                    if q.lower() in c["sig"].lower():
                        items.append({"k": f"{c['score']}", "label": c["sig"], "id": c["id"]})
            elif kind == "class":
                for r in idx.q("SELECT name FROM classes WHERE lower(name) LIKE lower(?) OR lower(source) LIKE lower(?) LIMIT 300", f"%{q}%", f"%{q}%"):
                    items.append({"k": "class", "label": r["name"], "cls": r["name"]})
            elif kind == "string":
                for r in idx.string_users(q, limit=300):
                    items.append({"k": r["value"][:40], "label": idx.sig(r), "id": r["id"]})
            elif kind == "ref":
                for r in idx.callers(q, limit=300):
                    items.append({"k": owner(r), "label": idx.sig(r), "id": r["id"]})
            else:
                for r in idx.q(idx.METHOD_SQL + "WHERE lower(m.name) LIKE lower(?) OR lower(c.name) LIKE lower(?) LIMIT 300", f"%{q}%", f"%{q}%"):
                    items.append({"k": owner(r), "label": idx.sig(r), "id": r["id"]})
            return {"items": items}
        if path == "/api/method":
            r = idx.method(int(g("id", "0")))
            if not r:
                return {"error": "no such method"}
            sig = idx.sig(r)
            callers = [{"id": x["id"], "sig": idx.sig(x)} for x in idx.callers(sig, limit=200, exact=True)]
            return {"id": r["id"], "sig": sig, "cls": r["cls"], "source": r["source"], "owner": owner(r),
                    "smali": idx.smali(r), "callers": callers, "strings": idx.strings_of(r["id"])[:200]}
        if path == "/api/resolve":
            rows = idx.find_methods(g("sig"), limit=1)
            return {"id": rows[0]["id"] if rows else None}
        if path == "/api/class":
            c = idx.class_row(g("name"))
            if not c:
                return {}
            ms = [{"id": r["id"], "label": f"{r['name']}({r['params']}){r['ret']}"} for r in idx.q(idx.METHOD_SQL + "WHERE c.id=?", c["id"])]
            fs = [f"{r['name']}:{r['type']}" for r in idx.q("SELECT name, type FROM fields WHERE class=?", c["id"])]
            return {"name": c["name"], "super": c["super"], "interfaces": c["interfaces"], "source": c["source"],
                    "owner": c["sdk"] or ("app" if c["is_app"] else "library"), "methods": ms, "fields": fs}
        if path == "/api/fp":
            from .seams import SeamHunter
            if "h" not in hunter_box:
                hunter_box["h"] = SeamHunter(idx)
            return hunter_box["h"].fingerprint(int(g("id", "0")))
        return {"error": "unknown endpoint"}

    return api, lock, idx, report


def serve(out_dir: str, port: int = 8765, open_browser: bool = True):
    api, lock, _idx, _report = make_api(out_dir)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body: bytes, ctype: str, code=200):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            # DNS-rebinding guard: only answer requests addressed to this machine
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            if host not in ("127.0.0.1", "localhost", "::1"):
                return self._send(b"forbidden host", "text/plain", 403)
            u = urlparse(self.path)
            if u.path == "/":
                return self._send(PAGE.encode(), "text/html; charset=utf-8")
            if u.path == "/favicon.ico":
                return self._send(b"", "image/x-icon", 204)
            if u.path == "/report":
                p = os.path.join(out_dir, "report.html")
                if os.path.exists(p):
                    with open(p, "rb") as f:
                        return self._send(f.read(), "text/html; charset=utf-8")
                return self._send(b"no report.html", "text/plain", 404)
            if u.path.startswith("/api/"):
                try:
                    with lock:
                        data = api(u.path, parse_qs(u.query))
                    return self._send(json.dumps(data, default=str).encode(), "application/json")
                except Exception as ex:  # noqa: BLE001 - report errors to the page
                    return self._send(json.dumps({"error": str(ex)}).encode(), "application/json", 500)
            return self._send(b"not found", "text/plain", 404)

    try:
        srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    except OSError:
        raise SystemExit(f"port {port} is busy (another explorer running?) — try: serve {out_dir} -p {port + 1}")
    url = f"http://127.0.0.1:{port}/"
    print(f"explorer on {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
