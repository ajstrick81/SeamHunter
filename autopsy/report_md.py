"""Compact Markdown report — sized to hand to Claude (or read yourself) instead of
re-running the autopsy in a Claude session. Full detail lives in report.json/html."""
from __future__ import annotations

import json as _json


def _t(s, n=110):
    s = str(s) if s is not None else ""
    s = s.replace("|", "\\|").replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def _obf_line(code) -> str:
    """Decisive obfuscation evidence — the synthetic-root concentration and compiler, not the
    (often-contradictory) short-name ratio. e.g. 'Heavy name obfuscation · 85% under synthetic root Lo/ · D8'."""
    o = code.get("obfuscation") or {}
    name_obf = o.get("name_obfuscation", o.get("verdict", "unknown"))
    parts = [{"heavy": "Heavy name obfuscation", "partial": "Partial name obfuscation",
              "none": "Light/no name obfuscation"}.get(name_obf, str(o.get("verdict", "unknown")))]
    if o.get("synthetic_root"):
        parts.append(f"{o.get('synthetic_root_ratio', 0):.0%} under synthetic root {o['synthetic_root'].split(' ')[0]}")
    elif o.get("short_app_class_ratio"):
        parts.append(f"{o['short_app_class_ratio']:.0%} short class names")
    compiler = o.get("compiler") or code.get("compiler_markers") or []
    if compiler:
        parts.append(str(compiler[0])[:40])
    if o.get("low_confidence"):
        parts.append("low confidence — few app classes")
    return " · ".join(parts)


def _table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(_t(c) for c in r) + " |")
    return "\n".join(out)


def _clip(text: str, n: int) -> str:
    lines = text.splitlines()
    return text if len(lines) <= n else "\n".join(lines[:n]) + f"\n    ... ({len(lines) - n} more lines in report-full.md)"


def _trackers_md(t, full: bool) -> list[str]:
    """Privacy audit section: trackers, where they start, vendor controls, blocklist."""
    if not t:
        return []
    L = [f"## Trackers & analytics — {t['count']} found", ""]
    if not t["items"]:
        return L + ["No known tracker SDKs, manifest components or tracker hosts.", ""]
    L.append("By category: " + ", ".join(f"{k} {v}" for k, v in t["by_category"].items()) +
             (" · sensitive permissions: " + ", ".join(p["what"] for p in t["permissions"]) if t["permissions"] else ""))
    L.append("")
    rows = []
    for i in t["items"]:
        e = i["evidence"]
        ev = (f"{e['classes']} classes" if e["classes"] else "") or (f"{len(e['components'])} manifest components"
                                                                    if e["components"] else "") \
            or ("hosts" if e["hosts"] else "strings " + ", ".join(e["markers"][:2]))
        start = i["init_sites"][0]["caller"] if i["init_sites"] else ""
        rows.append((i["category"], i["name"], ev, ", ".join(h["host"] for h in i["hosts"][:2]), start))
    L.append(_table(["Category", "Tracker", "Evidence", "Hosts in code", "Started from (app code)"],
                    rows if full else rows[:30]))
    ks = [k for k in t["kill_switches"]]
    if ks:
        L.append("")
        L.append("**Vendor control flags** (vendor-documented `<meta-data>` that influence tracking/personalization):")
        for k in ks:
            cur = k.get("current")
            now = "not set (SDK default = on)" if cur is None else f"currently `{cur}`" + (f" via `{k['via']}`" if k.get("via") else "")
            L.append(f"- {k['tracker']}: `{k['key']}` = `{k['value']}` → {k['effect']} ({now})")
    b = t["blocklist"]
    if b["safe"] or b["caution"] or b["never"]:
        L.append("")
        L.append(f"**Blocklist:** {len(b['safe'])} safe · {len(b['caution'])} caution (app features ride them) · "
                 f"{len(b['never'])} never (config/consent — blocking breaks the app).")
        if full and b["safe"]:
            L.append("```")
            L += [f"||{h}^" for h in b["safe"]]
            L.append("```")
        if b["never"]:
            L.append("Do NOT block: " + ", ".join(f"`{h}`" for h in b["never"]))
    L.append("")
    return L


def render(f: dict, full: bool = False) -> str:
    m = f["manifest"]
    code = f["code"]
    L = []
    title = f"{m.get('package')} {m.get('versionName') or ''} ({m.get('versionCode') or '?'})"
    L.append(f"# APK autopsy: {title}")
    L.append("")
    L.append(f"_{f['tool']} · {f['elapsed_seconds']} s · input `{f['input'].replace(chr(92), '/').split('/')[-1]}`_")
    L.append("")
    b = f["bundle"]
    ka = f.get("known_app")
    rows = [
        ("Bundle", f"{b['kind']} · {len(b['splits'])} split(s) · {b['size'] / 1e6:.1f} MB"),
        ("Android", f"minSdk {m.get('minSdk')} · targetSdk {m.get('targetSdk')} · TV/leanback: {'yes' if m.get('tv') else 'no'}"),
        ("Code", f"{len(code['dex_files'])} dex · {code['classes']:,} classes ({code['app_classes']:,} app) · "
                 f"{code['methods']:,} methods · {code['instructions']:,} insns"),
        ("Obfuscation", _obf_line(code)),
        ("Engine guess", "; ".join(f.get("engine_guess") or ["—"])),
        ("Known app", f"{ka['key']} · targets {', '.join(ka.get('targets') or [])} · this build is "
                      f"{'a declared target' if ka.get('version_is_target') else 'NOT a declared target'}" if ka else "no (new app)"),
    ]
    L.append(_table(["", ""], rows))
    L.append("")
    warns = list(f.get("warnings", [])) + list(f.get("bundle", {}).get("warnings", []))
    if warns:
        L.append("> **Warnings:** " + " · ".join(_t(w, 300) for w in warns))
        L.append("")
    L.append("## Investigation points (prioritised)")
    L += [f"{i}. {p}" for i, p in enumerate(f.get("plan", []), 1)]
    L.append("")

    if ka:
        L.append(f"## Known app: {ka['key']} — shipped fingerprints vs this build")
        L.append("")
        for k in ("engine", "delivery", "seam", "action", "drift", "patch_evidence", "device_signature"):
            if ka.get(k):
                L.append(f"- **{k.replace('_', ' ')}**: {_t(ka[k], 400)}")
        L.append("")
        L.append(f"Summary: {ka['summary']}")
        L.append("")
        L.append(_table(["Fingerprint", "Status", "Where / issues / rename candidates"],
                        [(r["id"], r["status"] + (" (partial)" if r.get("partial") else "") +
                          (f" — {r['impact']}" if r.get("impact") else ""),
                          "; ".join(filter(None, [r.get("where")] + r["issues"] + r["candidates"][:3])))
                         for r in ka["results"]]))
        L.append("")

    fixes = [r for r in (ka or {}).get("results", []) if r.get("fix")]
    if fixes:
        L.append("### Proposed fixes (verified: each matches exactly one method in this build)")
        L.append("")
        for r in fixes:
            L.append(f"**{r['id']}** → `{r['fix']['target']}`  changed: " +
                     ", ".join(f"{k} `{o}` → `{n}`" for k, (o, n) in r["fix"]["changed"].items()))
            L.append("```json")
            L.append(_json.dumps(r["fix"]["descriptor"], indent=2))
            L.append("```")
        L.append("")

    L.append("## Ad / tracking stack")
    L.append("")
    sd = [s for s in f["sdks"] if s["category"] not in ("network", "engine", "drm", "consent")] if not full else f["sdks"]
    L.append(_table(["Category", "SDK", "Evidence", "Note"],
                    [(s["category"], s["sdk"], f"{s['classes']} classes" if s["classes"] else s["by"], s["note"])
                     for s in sd[:40]]))
    other = [s["sdk"] for s in f["sdks"] if s not in sd]
    if other:
        L.append("")
        L.append("Also: " + ", ".join(other))
    L.append("")
    L += _trackers_md(f.get("trackers"), full)

    ip = f["seams"]["integration_points"]
    if ip:
        L.append("## Integration points (app/vendor code calling known seam APIs)")
        L.append("")
        shown = ip if full else [p for p in ip if p["engine"] not in ("network", "loader", "native", "analytics", "ads")
                                 or p["id"].startswith("ima")]
        hidden = [p["id"] for p in ip if p not in shown]
        if hidden:
            L.append("Also (sites in report-full.md): " + ", ".join(f"`{h}` ({next(p['count'] for p in ip if p['id'] == h)})"
                                                                     for h in hidden))
            L.append("")
        for p in shown:
            L.append(f"### `{p['id']}` — {p['count']} site(s)")
            L.append(f"{p['what']} **Role:** {p['strategy']}" + (f" **Risk:** {p['risk']}" if p["risk"] else ""))
            L.append("")
            for s in p["sites"][: (12 if full else 4)]:
                L.append(f"- `{s['sig']}` → `{_t(s['calls'].split('->')[1], 70)}`")
            L.append("")

    imps = f["seams"].get("implementers") or []
    if imps:
        L.append("## Implementers of ad-flow SDK types (found by interface, immune to R8 renames)")
        L.append("")
        for p in imps:
            L.append(f"### {p['label']} — {p['count']} class(es)")
            L.append(f"`{p['type']}` · **Strategy:** {p['strategy']}")
            for c in p["classes"][: (12 if full else 3)]:
                ms = ", ".join(f"`{m['sig'].split('->')[1]}` ({m['insns']} insns)" for m in c["methods"]) or "no hooked override"
                L.append(f"- `{c['class']}` (source {c['source']}): {ms}")
            L.append("")

    cands = f["seams"]["candidates"]
    L.append("## Seam candidates (ranked)")
    L.append("")
    L.append(_table(["#", "Score", "Method", "Why", "Fingerprint"],
                    [(i, c["score"], c["sig"], "; ".join(c["why"]),
                      ("unique" if c.get("fingerprint", {}).get("unique") else f"{c['fingerprint']['matches']} matches")
                      if c.get("fingerprint") else "")
                     for i, c in enumerate(cands[: (60 if full else 20)], 1)]))
    L.append("")
    if full:
        detail = cands[:25]
    else:
        drafted = {h["sig"] for h in (f.get("drafts") or {}).get("hooks", [])}
        detail = [c for c in cands if c["sig"] in drafted] + \
                 [c for c in cands if c["sig"] not in drafted][: max(2, 6 - len(drafted))]
        L.append("_Details: candidate seams first, then the top items that need a closer read._")
        L.append("")
    drafted_sigs = {h["sig"] for h in (f.get("drafts") or {}).get("hooks", [])}
    for i, c in enumerate(detail, 1):
        show_code = full or (c["sig"] in drafted_sigs and i <= 4)
        L.append(f"### {i}. `{c['sig']}`")
        L.append(f"- score {c['score']} · {c['insns']} insns · source `{c['source']}`" +
                 (f" · vendor {c['vendor']}" if c["vendor"] else ""))
        L.append(f"- **strategy:** {c['strategy']}")
        if c.get("callers"):
            L.append("- callers: " + ", ".join(f"`{_t(x['sig'], 120)}`" for x in c["callers"][: (4 if full else 2)]))
        for ch in (c.get("chains") or [])[: (2 if full else 1)]:
            L.append("- chain: " + " ← ".join(f"`{_t(x, 90)}`" for x in ch))
        pol = c.get("polarity")
        if pol and pol.get("neutral"):
            avoids = "false" if pol["neutral"] == "0x0" else "true"
            enters = "true" if pol["neutral"] == "0x0" else "false"
            L.append(f"- **branch map (from call sites, {pol.get('confidence')}):** returning `{avoids}` does not "
                     f"enter the ad path; returning `{enters}` does — " + "; ".join(pol["evidence"][:3]))
        elif pol is not None:
            L.append("- branch map: not provable from call sites — confirm by reading the callers")
        for fl in (c.get("dataflow") or [])[: (5 if full else 2)]:
            others = fl["other_readers"][:2] + fl["other_writers"][:2]
            L.append(f"- data: {fl['access']} `{_t(fl['field'], 100)}`" +
                     (f" — also {'read' if fl['other_readers'] else 'written'} by " + ", ".join(f"`{_t(o, 80)}`" for o in others)
                      if others else ""))
        fp = c.get("fingerprint")
        if fp:
            L.append(f"- fingerprint matches **{fp['matches']}** method(s)" + (" (unique)" if fp["unique"] else " — tighten it"))
            for n in fp["notes"]:
                L.append(f"  - {n}")
            L.append("```json")
            L.append(_json.dumps(fp["descriptor"], indent=2))
            L.append("```")
        if c.get("java") and show_code:
            L.append("<details><summary>java (jadx — names may be invented; smali is truth)</summary>\n\n```java")
            L.append(c["java"] if full else _clip(c["java"], 30))
            L.append("```\n</details>")
        if c.get("smali") and show_code and (full or not c.get("java")):
            L.append("<details><summary>smali</summary>\n\n```smali")
            L.append(c["smali"] if full else _clip(c["smali"], 30))
            L.append("```\n</details>")
        L.append("")

    hc = f["seams"]["hot_classes"]
    if hc:
        hints = f["seams"].get("deobfuscation_hints", {})
        L.append("## Hot classes")
        L.append("")
        L.append(_table(["Class", "Score", "Methods", "Source / recovered name"],
                        [(h["class"], round(h["score"], 1), h["methods"],
                          "; ".join(hints.get(h["class"], [])) or h.get("source") or "") for h in hc[:15]]))
        L.append("")

    ar = f.get("seams_ad_resources") or []
    if ar:
        L.append("## Ad-named resources referenced from code")
        L.append("Literal resource ids are stable fingerprint anchors (they survive R8 renames).")
        L.append("")
        L.append(_table(["Resource", "Id", "Used by"], [(r["resource"], r["id"], "; ".join(r["used_by"][:2]) +
                                                         (f" (+{r['count'] - 2})" if r["count"] > 2 else ""))
                                                        for r in ar[: (60 if full else 15)]]))
        L.append("")

    nat = f["native"]["libs"]
    if nat:
        L.append("## Native libraries")
        L.append("")
        L.append(_table(["Lib", "ABI", "Size", "Engines", "Ad strings", "Seam imports", "dlopen targets"],
                        [(n["lib"], n["abi"] + (f" (+{len(n['other_abis'])})" if n.get("other_abis") else ""),
                          f"{n['size'] / 1e6:.1f} MB", ", ".join(e["engine"] for e in n["engines"]),
                          ", ".join(n["ad_strings"]), ", ".join(n["seam_imports"]), ", ".join(n["dlopen_targets"][:4]))
                         for n in nat[: (40 if full else 15)]]))
        L.append("")
        for n in nat[:4]:
            if n["ad_strings"]:
                L.append(f"**{n['lib']}** ad strings:")
                for label, ex in n["ad_strings"].items():
                    L.append(f"- {label}: " + " · ".join(f"`{_t(e, 90)}`" for e in ex[:3]))
                L.append("")
        jm = [j for j in f["native"]["jni_map"] if j["lib"]]
        if jm:
            L.append("JNI (app `native` methods → library): " +
                     "; ".join(f"`{_t(j['method'], 80)}` → {j['lib']}" for j in jm[:12]))
            L.append("")
    if code.get("loadlibrary_confirmed"):
        L.append("System.loadLibrary (packaged .so confirmed): " +
                 ", ".join(f"`{x}`" for x in code["loadlibrary_confirmed"]))
        L.append("")
    poss = code.get("loadlibrary_possible", code.get("loadlibrary_names") or [])
    if poss:
        L.append("System.loadLibrary (possible — literal co-occurs in method, not slice-proven): " +
                 ", ".join(f"`{x}`" for x in poss))
        L.append("")

    a = f["assets"]
    if a["ad_anchors"] or a["compressed_libs"] or a["hidden_dex"]:
        L.append("## Assets")
        L.append("")
        if a["hidden_dex"]:
            L.append("Hidden DEX: " + ", ".join(f"`{x}`" for x in a["hidden_dex"]))
        if a["compressed_libs"]:
            L.append("Compressed/downloadable libs: " + ", ".join(f"`{x['file']}`" for x in a["compressed_libs"]))
        for h in a["ad_anchors"][: (40 if full else 12)]:
            L.append(f"- `{h['file']}` @{h['offset']} **{h['anchor']}**: `{_t(h['context'], 200)}`")
        L.append("")

    hs = [h for h in f["hosts"] if h["category"]]
    if hs:
        L.append("## Ad / tracking hosts")
        L.append("")
        L.append(_table(["Host", "Category", "Seen in", "Used by", "Note"],
                        [(h["host"], h["category"],
                          " ".join(f"{k}:{h[k]}" for k in ("dex", "native", "assets") if h[k]),
                          ", ".join(h.get("used_by", [])[:2]), h["note"]) for h in hs[: (60 if full else 20)]]))
        L.append(f"\n{len(f['hosts']) - len(hs)} other hosts in report.json.")
        L.append("")

    pr = f["protections"]
    if pr:
        L.append("## Protections & modification risks")
        L.append("")
        for p in pr:
            L.append(f"- **{p['label']}** ({p['severity']}){': ' + p['note'] if p['note'] else ''}")
            for h in p["hits"][:3]:
                L.append(f"  - `{_t(h, 140)}`")
        L.append("")

    dr = f.get("drafts")
    if dr:
        L.append("## Scoping deliverables")
        L.append("")
        L.append(f"Written to `{dr['dir']}/`: " + ", ".join(f"`{x}`" for x in dr["files"]))
        L.append("")
        for h in dr["hooks"]:
            conf = h.get("confidence") or "see notes"
            L.append(f"- candidate seam `{h['sig']}` ({h['why']}) — returns `{h['returnType']}`, {conf}")
        for r in dr["review"]:
            L.append(f"- needs a closer read `{r['sig']}` → {r['strategy']}")
        L.append("")
    j = f.get("java") or {}
    if j and not j.get("available"):
        L.append(f"_{j.get('note')}_")
        L.append("")

    L.append("## Manifest essentials")
    L.append("")
    app = m.get("application", {})
    L.append(f"- application: {', '.join(f'{k}={v}' for k, v in app.items())}")
    L.append(f"- launchers: {', '.join(m.get('launchers') or [])}")
    if m.get("ad_permissions"):
        L.append(f"- ad permissions: {', '.join(m['ad_permissions'])}")
    if m.get("ad_components"):
        L.append("- ad components: " + ", ".join(f"{c['kind']} `{c['name']}`" for c in m["ad_components"][:10]))
    nsc = m.get("network_security_config")
    if nsc:
        L.append(f"- network security config: {nsc}")
    if m.get("meta_data"):
        L.append("- meta-data: " + ", ".join(f"`{k}`={_t(v, 40)}" for k, v in list(m["meta_data"].items())[:15]))
    L.append("")
    L.append("## Next queries (run locally, paste results back)")
    L.append("")
    L.append("```")
    L.append("autopsy show   <out> 'Lcls;->method(params)ret'   # smali of one method")
    L.append("autopsy java   <out> 'Lcls;'                       # jadx decompile of one class")
    L.append("autopsy xref   <out> 'getAdCuePoints'               # who calls it")
    L.append("autopsy strings <out> 'adBreak'                     # which methods use the string")
    L.append("seamhunter fp  <out> 'Lcls;->method(...)R'          # draft + verify a matcher descriptor")
    L.append("autopsy serve  <out>                                # browse everything in the browser")
    L.append("```")
    return "\n".join(L) + "\n"
