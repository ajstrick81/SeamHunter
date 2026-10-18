"""Self-contained HTML report (no network, no external assets)."""
from __future__ import annotations

import html
import json

CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--mute:#6b6b66;--line:#e2e1dc;--acc:#b4441c;--acc2:#1f6f8b;
--ok:#2e7d32;--warn:#b26a00;--bad:#b3261e;--code:#f1f0ec;--chip:#efeee9}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--panel:#1c1c1a;--ink:#ecebe6;--mute:#a09f99;--line:#33332f;
--acc:#e0764e;--acc2:#6bb3cc;--ok:#7cc47f;--warn:#e0a84e;--bad:#ef7b72;--code:#232320;--chip:#2a2a27}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{padding:20px 24px;border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:5}
header h1{margin:0;font-size:20px}header .sub{color:var(--mute);font-size:12px}
nav{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}nav a{font-size:12px;padding:3px 9px;border-radius:12px;
background:var(--chip);color:var(--ink);text-decoration:none}nav a:hover{background:var(--acc);color:#fff}
main{max-width:1280px;margin:0 auto;padding:16px 24px 80px}section{background:var(--panel);border:1px solid var(--line);
border-radius:10px;padding:16px 18px;margin:16px 0}h2{margin:0 0 10px;font-size:16px}h3{font-size:14px;margin:14px 0 6px}
table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);
vertical-align:top}th{color:var(--mute);font-weight:600;position:sticky;top:0;background:var(--panel)}
code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}td code{word-break:break-all}
pre{background:var(--code);padding:10px 12px;border-radius:8px;overflow:auto;max-height:520px}
.kv{display:grid;grid-template-columns:160px 1fr;gap:4px 14px}.kv div:nth-child(odd){color:var(--mute)}
.chip{display:inline-block;font-size:11px;padding:1px 7px;border-radius:10px;background:var(--chip);margin:1px 2px}
.s-OK,.s-FOUND_BY_STRINGS{color:var(--ok);font-weight:600}.s-UNVERIFIABLE{color:var(--mute)}
.s-CLASS_MISSING,.s-METHOD_MISSING,.s-SIGNATURE_CHANGED,.s-STRINGS_MISSING{color:var(--bad);font-weight:600}
.s-FLAGS_CHANGED{color:var(--warn);font-weight:600}.score{font-weight:700;color:var(--acc)}
ol.plan li{margin:6px 0}details{border:1px solid var(--line);border-radius:8px;padding:6px 10px;margin:8px 0}
details summary{cursor:pointer;font-weight:600}input.filter{width:100%;padding:6px 10px;border:1px solid var(--line);
border-radius:6px;background:var(--bg);color:var(--ink);margin-bottom:8px}.sev-high{color:var(--bad)}.sev-med{color:var(--warn)}
.mute{color:var(--mute)}.warn{color:var(--warn)}
"""

JS = """
document.querySelectorAll('input.filter').forEach(inp=>{inp.addEventListener('input',()=>{const t=document.getElementById(inp.dataset.t);
const q=inp.value.toLowerCase();t.querySelectorAll('tbody tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'})})});
"""


def e(x):
    return html.escape(str(x) if x is not None else "")


def table(tid, headers, rows, filt=True):
    out = []
    if filt and len(rows) > 12:
        out.append(f'<input class="filter" data-t="{tid}" placeholder="filter…">')
    out.append(f'<div style="overflow:auto;max-height:640px"><table id="{tid}"><thead><tr>' +
               "".join(f"<th>{e(h)}</th>" for h in headers) + "</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
    out.append("</tbody></table></div>")
    return "\n".join(out)


def code(x):
    return f"<code>{e(x)}</code>"


def render(f: dict) -> str:
    m = f["manifest"]
    c = f["code"]
    b = f["bundle"]
    ka = f.get("known_app")
    title = f"{m.get('package')} {m.get('versionName') or ''}"
    S = []
    nav = [("plan", "Plan"), ("known", "Known app"), ("stack", "Ad stack"), ("ip", "Integration points"),
           ("cands", "Seam candidates"), ("hot", "Hot classes"), ("native", "Native"), ("assets", "Assets"),
           ("hosts", "Hosts"), ("prot", "Protections"), ("manifest", "Manifest"), ("code", "Code")]
    S.append(f"<header><h1>APK autopsy · {e(title)}</h1><div class='sub'>{e(f['tool'])} · {e(f['elapsed_seconds'])} s · "
             f"{e(f['input'])}</div><nav>" + "".join(f"<a href='#{a}'>{e(t)}</a>" for a, t in nav) + "</nav></header><main>")
    # summary
    S.append("<section><h2>Summary</h2><div class='kv'>")
    for k, v in (("Package", m.get("package")), ("Version", f"{m.get('versionName')} ({m.get('versionCode')})"),
                 ("Bundle", f"{b['kind']} · {len(b['splits'])} split(s) · {b['size'] / 1e6:.1f} MB"),
                 ("SDK", f"min {m.get('minSdk')} · target {m.get('targetSdk')} · TV {'yes' if m.get('tv') else 'no'}"),
                 ("Code", f"{c['classes']:,} classes ({c['app_classes']:,} app) · {c['methods']:,} methods · {c['instructions']:,} insns"),
                 ("Obfuscation", c["obfuscation"]["verdict"]),
                 ("Engine guess", "; ".join(f.get("engine_guess") or ["—"])),
                 ("Known app", ka["key"] if ka else "no")):
        S.append(f"<div>{e(k)}</div><div>{e(v)}</div>")
    S.append("</div></section>")
    S.append("<section id='plan'><h2>Where to cut</h2><ol class='plan'>" +
             "".join(f"<li>{e(p)}</li>" for p in f.get("plan", [])) + "</ol></section>")
    if ka:
        S.append(f"<section id='known'><h2>Known app: {e(ka['key'])}</h2><div class='kv'>")
        for k in ("engine", "runtime", "delivery", "seam", "action", "drift", "patch_evidence", "device_signature"):
            if ka.get(k):
                S.append(f"<div>{e(k.replace('_', ' '))}</div><div>{e(ka[k])}</div>")
        S.append(f"<div>targets</div><div>{e(', '.join(ka.get('targets') or []))} "
                 f"{'' if ka.get('version_is_target') else '<b class=warn>(this build is not a declared target)</b>'}</div></div>")
        S.append(table("t-known", ["Fingerprint", "Used by", "Status", "Where", "Issues / candidates"],
                       [(code(r["id"]), e(", ".join(r["usedBy"])), f"<span class='s-{e(r['status'])}'>{e(r['status'])}</span>",
                         code(r.get("where") or ""), "<br>".join(e(x) for x in r["issues"] + r["candidates"]))
                        for r in ka["results"]]))
        S.append("</section>")
    S.append("<section id='stack'><h2>SDKs</h2>" + table("t-sdk", ["Category", "SDK", "Evidence", "Note"],
             [(e(s["category"]), e(s["sdk"]), e(f"{s['classes']} classes" if s["classes"] else s["by"]), e(s["note"]))
              for s in f["sdks"]]) + "</section>")
    ip = f["seams"]["integration_points"]
    S.append("<section id='ip'><h2>Integration points</h2>")
    if not ip:
        S.append("<p class='mute'>No app/vendor code calls a catalogued seam API.</p>")
    for p in ip:
        S.append(f"<h3>{e(p['id'])} <span class='chip'>{e(p['engine'])}</span> <span class='chip'>{p['count']} site(s)</span></h3>"
                 f"<p>{e(p['what'])}<br><b>Role:</b> {e(p['strategy'])}<br><b>Risk:</b> {e(p['risk'] or '—')}</p>")
        S.append("<ul>" + "".join(f"<li>{code(s['sig'])} → {code(s['calls'].split('->')[1])}</li>" for s in p["sites"]) + "</ul>")
    S.append("</section>")
    imps = f["seams"].get("implementers") or []
    if imps:
        S.append("<section><h2>Implementers of ad-flow SDK types</h2>")
        for p in imps:
            S.append(f"<h3>{e(p['label'])} <span class='chip'>{p['count']}</span></h3><p class='mute'>{code(p['type'])}<br>{e(p['strategy'])}</p><ul>" +
                     "".join(f"<li>{code(c['class'])} <span class='mute'>{e(c['source'])}</span> " +
                             " ".join(code(m['sig'].split('->')[1]) for m in c['methods']) + "</li>" for c in p["classes"]) + "</ul>")
        S.append("</section>")
    cands = f["seams"]["candidates"]
    S.append("<section id='cands'><h2>Seam candidates</h2>")
    S.append(table("t-cands", ["#", "Score", "Method", "Why", "Strategy", "FP"],
                   [(i, f"<span class='score'>{x['score']}</span>", code(x["sig"]), e("; ".join(x["why"])), e(x["strategy"]),
                     e(("unique" if x["fingerprint"]["unique"] else f"{x['fingerprint']['matches']}") if x.get("fingerprint") else ""))
                    for i, x in enumerate(cands, 1)]))
    for i, x in enumerate(cands[:25], 1):
        S.append(f"<details><summary>{i}. {e(x['sig'])} <span class='score'>{x['score']}</span></summary>")
        S.append(f"<p><b>Strategy:</b> {e(x['strategy'])}<br><span class='mute'>source {e(x['source'])} · {x['insns']} insns"
                 f"{' · vendor ' + e(x['vendor']) if x['vendor'] else ''}</span></p>")
        if x.get("callers"):
            S.append("<p><b>Callers</b><br>" + "<br>".join(code(y["sig"]) for y in x["callers"]) + "</p>")
        for ch in x.get("chains") or []:
            S.append("<p class='mute'>chain: " + " ← ".join(code(y) for y in ch) + "</p>")
        fp = x.get("fingerprint")
        if fp:
            S.append(f"<p><b>Matcher descriptor</b> — matches {fp['matches']} method(s)"
                     f"{' (unique)' if fp['unique'] else ' — tighten it'}</p>" +
                     "".join(f"<p class='mute'>{e(n)}</p>" for n in fp["notes"]) +
                     f"<pre>{e(__import__('json').dumps(fp['descriptor'], indent=2))}</pre>")
        for fl in x.get("dataflow") or []:
            S.append(f"<p class='mute'>data: {e(fl['access'])} {code(fl['field'])} · readers {len(fl['other_readers'])} · writers {len(fl['other_writers'])}</p>")
        if x.get("java"):
            S.append(f"<p><b>Java</b> <span class='mute'>(jadx; names may be invented)</span></p><pre>{e(x['java'])}</pre>")
        if x.get("smali"):
            S.append(f"<p><b>Smali</b></p><pre>{e(x['smali'])}</pre>")
        S.append("</details>")
    S.append("</section>")
    hints = f["seams"].get("deobfuscation_hints", {})
    S.append("<section id='hot'><h2>Hot classes</h2>" + table("t-hot", ["Class", "Score", "Methods", "Recovered name / source"],
             [(code(h["class"]), round(h["score"], 1), h["methods"], e("; ".join(hints.get(h["class"], [])) or h.get("source")))
              for h in f["seams"]["hot_classes"]]) + "</section>")
    ar = f.get("seams_ad_resources") or []
    if ar:
        S.append("<section><h2>Ad-named resources used by code</h2>" + table("t-res", ["Resource", "Id", "Used by"],
                 [(code(r["resource"]), code(r["id"]), "<br>".join(code(u) for u in r["used_by"])) for r in ar]) + "</section>")
    nat = f["native"]
    S.append("<section id='native'><h2>Native libraries</h2>" + table("t-nat", ["Lib", "ABI", "Size", "Engines", "Ad strings",
             "Seam imports", "JNI", "dlopen", "SHA-256"],
             [(code(n["lib"]), e(n["abi"] + (" +" + ",".join(n.get("other_abis", [])) if n.get("other_abis") else "")),
               f"{n['size'] / 1e6:.1f} MB", "<br>".join(f"{e(x['engine'])} <span class='mute'>{e(x['evidence'])}</span>" for x in n["engines"]),
               "<br>".join(f"<b>{e(k)}</b>: " + " · ".join(code(s) for s in v[:3]) for k, v in n["ad_strings"].items()),
               "<br>".join(f"{e(k)} <span class='mute'>{e(v)}</span>" for k, v in n["seam_imports"].items()),
               f"{n['jni_exports']}{' +JNI_OnLoad' if n['has_JNI_OnLoad'] else ''}", e(", ".join(n["dlopen_targets"][:8])),
               code(n["sha256"])) for n in nat["libs"]]))
    if nat["jni_map"]:
        S.append("<h3>Java native methods</h3>" + table("t-jni", ["Method", "Library"],
                 [(code(j["method"]), e(j["lib"])) for j in nat["jni_map"]]))
    S.append("</section>")
    a = f["assets"]
    S.append("<section id='assets'><h2>Assets</h2>")
    if a["hidden_dex"]:
        S.append("<p><b>Hidden DEX:</b> " + ", ".join(code(x) for x in a["hidden_dex"]) + "</p>")
    if a["compressed_libs"]:
        S.append("<p><b>Compressed libs:</b> " + ", ".join(code(x["file"]) for x in a["compressed_libs"]) + "</p>")
    S.append(table("t-anch", ["File", "Anchor", "Context"], [(code(h["file"]), e(h["anchor"]), code(h["context"])) for h in a["ad_anchors"]]))
    S.append(table("t-files", ["Notable file", "Kind", "Size"], [(code(x["file"]), e(x["kind"]), f"{x['size']:,}") for x in a["notable"]]))
    S.append("</section>")
    S.append("<section id='hosts'><h2>Hosts</h2>" + table("t-hosts", ["Host", "Category", "dex/native/assets", "Used by", "URLs"],
             [(code(h["host"]), e(h["category"] or ""), f"{h['dex']}/{h['native']}/{h['assets']}",
               "<br>".join(code(u) for u in h.get("used_by", [])), "<br>".join(code(u) for u in h["urls"][:3]))
              for h in f["hosts"]]) + "</section>")
    S.append("<section id='prot'><h2>Protections & hazards</h2><ul>" + "".join(
        f"<li><b class='sev-{e(p['severity'])}'>{e(p['label'])}</b> ({e(p['severity'])}) {e(p['note'])}"
        + ("<ul>" + "".join(f"<li>{code(h)}</li>" for h in p["hits"][:6]) + "</ul>" if p["hits"] else "") + "</li>"
        for p in f["protections"]) + "</ul></section>")
    dr = f.get("drafts")
    if dr:
        S.append(f"<section><h2>Draft deliverables</h2><p>{code(dr['dir'])}: {e(', '.join(dr['files']))}</p><ul>" +
                 "".join(f"<li>auto {code(h['sig'])} — {e(h['why'])}</li>" for h in dr["hooks"]) +
                 "".join(f"<li class='mute'>review {code(r['sig'])} — {e(r['strategy'])}</li>" for r in dr["review"]) + "</ul></section>")
    S.append("<section id='manifest'><h2>Manifest</h2><pre>" + e(json.dumps(m, indent=1, ensure_ascii=False, default=str)) + "</pre></section>")
    S.append("<section id='code'><h2>Code</h2><pre>" + e(json.dumps(c, indent=1, ensure_ascii=False, default=str)[:60000]) + "</pre></section>")
    S.append("</main>")
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Autopsy · {e(m.get('package'))}</title><style>{CSS}</style></head><body>{''.join(S)}<script>{JS}</script></body></html>")
