"""Old build -> new build: what moved, what R8 renamed, which seams survived.

Class renames are matched on a structural "shape" (method signatures with obfuscated
names blanked, field types, super, interfaces) plus the `.source` file name, which R8
keeps. That turns "class LPo/C$c; was renamed again" into a mapping line instead of a hunt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter, defaultdict

from .index import Index
from .kb.markers import ad_string_hits
from .seams import is_obfuscated_name, simple_class


def _load(path):
    if os.path.isfile(path) and not path.endswith((".sqlite", ".json")):
        # an APK/APKM: scan it first
        from .analyze import Autopsy
        from .cli import _out_for
        out = _out_for(path)
        if not os.path.exists(os.path.join(out, "report.json")):
            Autopsy(path, out, log=lambda *a: None).run()
        path = out
    with open(os.path.join(path, "report.json"), encoding="utf-8") as f:
        rep = json.load(f)
    return Index(path), rep


def _norm_type(t: str) -> str:
    """Blank obfuscated class names inside a type so shapes survive renames."""
    base = t.lstrip("[")
    if base.startswith("L") and base.endswith(";"):
        if base.startswith(("Ljava/", "Landroid/", "Lkotlin/", "Landroidx/")):
            return t
        if is_obfuscated_name(simple_class(base).split("$")[-1]):
            return "[" * (len(t) - len(base)) + "L?;"
    return t


def _split(params):
    out, i = [], 0
    while i < len(params):
        j = i
        while params[j] == "[":
            j += 1
        if params[j] == "L":
            j = params.index(";", j)
        out.append(params[i:j + 1])
        i = j + 1
    return out


def shapes(idx: Index):
    """class name -> (shape hash, source, strong hash incl. strings)."""
    meths = defaultdict(list)
    for cid, name, params, ret in idx.q("SELECT class, name, params, ret FROM methods"):
        nm = "" if is_obfuscated_name(name) else name
        sig = nm + "(" + "".join(_norm_type(p) for p in _split(params)) + ")" + _norm_type(ret)
        meths[cid].append(sig)
    fields = defaultdict(list)
    for cid, ftype in idx.q("SELECT class, type FROM fields"):
        fields[cid].append(_norm_type(ftype))
    strs = defaultdict(set)
    for cid, val in idx.q("SELECT m.class, s.value FROM m_str x JOIN methods m ON m.id=x.m JOIN strings s ON s.id=x.s "
                          "JOIN classes c ON c.id=m.class WHERE c.is_app=1 OR c.category IN ('platform','player')"):
        strs[cid].add(val)
    out = {}
    for cid, name, sup, ifs, source, is_app, cat in idx.q(
            "SELECT id, name, super, interfaces, source, is_app, category FROM classes"):
        if not (is_app or cat in ("platform", "player")):
            continue
        h = hashlib.sha1()
        h.update(_norm_type(sup or "").encode())
        h.update(" ".join(sorted(_norm_type(i) for i in (ifs or "").split())).encode())
        h.update("|".join(sorted(meths[cid])).encode())
        h.update("|".join(sorted(fields[cid])).encode())
        shape = h.hexdigest()[:16]
        strong = hashlib.sha1((shape + "|".join(sorted(strs[cid]))).encode()).hexdigest()[:16]
        feats = frozenset(["m:" + x for x in meths[cid]] + ["s:" + x for x in strs[cid]] +
                          ["f:" + x for x in fields[cid]])
        out[name] = (shape, source, strong, feats, _norm_type(sup or ""))
    return out


def diff(old_path, new_path) -> dict:
    oi, orep = _load(old_path)
    ni, nrep = _load(new_path)
    d = {"old": {"version": orep["manifest"].get("versionName"), "code": orep["manifest"].get("versionCode")},
         "new": {"version": nrep["manifest"].get("versionName"), "code": nrep["manifest"].get("versionCode")},
         "package": nrep["manifest"].get("package")}
    # SDKs
    os_ = {s["sdk"]: s for s in orep["sdks"]}
    ns_ = {s["sdk"]: s for s in nrep["sdks"]}
    d["sdks_added"] = [ns_[k] for k in ns_ if k not in os_]
    d["sdks_removed"] = [os_[k] for k in os_ if k not in ns_]
    d["sdks_changed"] = [{"sdk": k, "old": os_[k]["classes"], "new": ns_[k]["classes"]}
                         for k in ns_ if k in os_ and os_[k]["classes"] != ns_[k]["classes"]]
    # classes
    osh, nsh = shapes(oi), shapes(ni)
    gone = [c for c in osh if c not in nsh]
    added = [c for c in nsh if c not in osh]
    by_strong = defaultdict(list)
    by_shape_src = defaultdict(list)
    by_shape = defaultdict(list)
    for c in added:
        shape, src, strong = nsh[c][:3]
        by_strong[strong].append(c)
        by_shape_src[(shape, src)].append(c)
        by_shape[shape].append(c)
    renames = {}
    confidence = {}
    for c in gone:
        shape, src, strong = osh[c][:3]
        for bucket, conf in ((by_strong.get(strong), "high"), (by_shape_src.get((shape, src)), "medium"),
                             (by_shape.get(shape), "low")):
            if bucket and len(bucket) == 1:
                renames[c] = bucket[0]
                confidence[c] = conf
                break
    # fuzzy pass: the class changed a little AND was renamed (the usual app update)
    taken = set(renames.values())
    by_src = defaultdict(list)
    by_super = defaultdict(list)
    for c in added:
        if c in taken:
            continue
        src, sup = nsh[c][1], nsh[c][4]
        if src and src not in ("SourceFile", "r8-map-id") and not src.startswith("R8$$"):
            by_src[src].append(c)
        by_super[sup].append(c)
    for c in gone:
        if c in renames:
            continue
        _, src, _, feats, sup = osh[c]
        if not feats:
            continue
        pool = by_src.get(src) or by_super.get(sup, [])
        scored = []
        for n in pool[:300]:
            if n in taken:
                continue
            nf = nsh[n][3]
            j = len(feats & nf) / max(1, len(feats | nf))
            scored.append((j, n))
        scored.sort(reverse=True)
        if scored and scored[0][0] >= 0.6 and (len(scored) == 1 or scored[0][0] - scored[1][0] >= 0.15):
            renames[c] = scored[0][1]
            confidence[c] = f"fuzzy {scored[0][0]:.0%}"
            taken.add(scored[0][1])
    d["classes"] = {"old": len(osh), "new": len(nsh), "removed": len(gone), "added": len(added),
                    "renamed_matched": len(renames),
                    "by_confidence": dict(Counter(confidence.values()))}
    # seam candidates of the old build -> where now?
    seam_moves = []
    for c in orep["seams"]["candidates"][:40]:
        sig = c["sig"]
        rows = ni.find_methods(sig, limit=1)
        if rows:
            seam_moves.append({"old": sig, "status": "same", "new": sig})
            continue
        cls = c["class"]
        new_cls = renames.get(cls, cls if cls in nsh else None)
        if not new_cls:
            seam_moves.append({"old": sig, "status": "class gone (no confident rename)", "new": None})
            continue
        cand = ni.q(ni.METHOD_SQL + "WHERE c.name=? AND m.params=? AND m.ret=?", new_cls, c["params"], c["ret"])
        if not cand:
            # obfuscated param types may have been renamed too
            want = "(" + "".join(_norm_type(p) for p in _split(c["params"])) + ")" + _norm_type(c["ret"])
            cand = [r for r in ni.q(ni.METHOD_SQL + "WHERE c.name=?", new_cls)
                    if "(" + "".join(_norm_type(p) for p in _split(r["params"])) + ")" + _norm_type(r["ret"]) == want]
        if len(cand) == 1:
            seam_moves.append({"old": sig, "status": f"renamed ({confidence.get(cls, 'same class')})",
                               "new": ni.sig(cand[0])})
        elif cand and len([r for r in cand if r["name"] == c["name"]]) == 1:
            r = next(r for r in cand if r["name"] == c["name"])
            seam_moves.append({"old": sig, "status": f"renamed ({confidence.get(cls, 'same class')}, method name kept)",
                               "new": ni.sig(r)})
        elif cand:
            same_name = [r for r in cand if r["name"] == c["name"]]
            pick = same_name or cand
            seam_moves.append({"old": sig, "status": f"ambiguous ({len(cand)} same-shape methods)",
                               "new": "; ".join(ni.sig(r) for r in pick[:3])})
        else:
            seam_moves.append({"old": sig, "status": "method gone", "new": new_cls})
    d["seam_moves"] = seam_moves
    d["renames_sample"] = [{"old": o, "new": n, "confidence": confidence[o], "source": osh[o][1]}
                           for o, n in list(renames.items())[:200]]
    # ad strings
    def ad_strings(idx):
        return {v for (v,) in idx.q("SELECT value FROM strings WHERE length(value) < 300") if
                any(w >= 3 for w, _ in ad_string_hits(v))}
    oas, nas = ad_strings(oi), ad_strings(ni)
    d["ad_strings_added"] = sorted(nas - oas)[:80]
    d["ad_strings_removed"] = sorted(oas - nas)[:80]
    # native
    onat = {l["lib"]: l for l in orep["native"]["libs"]}
    nnat = {l["lib"]: l for l in nrep["native"]["libs"]}
    d["native"] = {
        "added": [k for k in nnat if k not in onat], "removed": [k for k in onat if k not in nnat],
        "changed": [{"lib": k, "old_size": onat[k]["size"], "new_size": nnat[k]["size"]}
                    for k in nnat if k in onat and onat[k]["sha256"] != nnat[k]["sha256"]],
    }
    # hosts
    oh = {h["host"] for h in orep["hosts"] if h["category"]}
    nh = {h["host"] for h in nrep["hosts"] if h["category"]}
    d["ad_hosts_added"] = sorted(nh - oh)
    d["ad_hosts_removed"] = sorted(oh - nh)
    # known-app status change
    if orep.get("known_app") and nrep.get("known_app"):
        ost = {r["id"]: r["status"] for r in orep["known_app"]["results"]}
        d["fingerprints"] = [{"id": r["id"], "old": ost.get(r["id"]), "new": r["status"], "where": r.get("where"),
                              "candidates": r.get("candidates", [])[:3]}
                             for r in nrep["known_app"]["results"] if ost.get(r["id"]) != r["status"] or r["status"] != "OK"]
    d["body_changes"] = _body_changes(oi, ni, orep, nrep) if d["old"]["code"] == d["new"]["code"] else None
    return d


_JUMBO = re.compile(r"(const-string|goto)/(jumbo|16|32)\b")
_LABEL = re.compile(r":(?:[a-z]+_)+[0-9a-f]+\b")                       # :cond_1f, :sswitch_data_290 ...
_REGS = re.compile(r"^\s*(\.registers \d+|nop)\s*$", re.M)             # + alignment nops before payloads


def _norm_smali(s: str) -> str:
    """Smali with assembler-only differences removed: jumbo/wide encodings, offset-derived labels,
    and the register count (injected code may bump it without changing the original instructions)."""
    s = _JUMBO.sub(r"\1", s)
    s = _LABEL.sub(":L", s)
    return _REGS.sub("", s)


def _body_changes(oi, ni, orep, nrep, limit=100):
    """Same build on both sides (stock vs patched): which method bodies differ. Across different builds
    every dex index shifts, so this only runs when the versionCode matches. Pass 1 compares instruction
    counts for every method (SQL); pass 2 compares the smali of the seam candidates and known-app targets
    exactly, which also catches equal-length patches (a const/4 flip)."""
    old = {}
    for r in oi.q("SELECT c.name, m.name, m.params, m.ret, m.insns FROM methods m JOIN classes c ON c.id=m.class "
                  "WHERE m.code_off != 0"):
        old[(r[0], r[1], r[2], r[3])] = r[4]
    changed = []
    noise = 0
    for r in ni.q(ni.METHOD_SQL + "WHERE m.code_off != 0"):
        k = (r["cls"], r["name"], r["params"], r["ret"])
        if k in old and old[k] != r["insns"]:
            # a re-assembled dex shifts string indexes past 65535 (const-string -> /jumbo) and branch sizes
            # (goto -> goto/16): count differs, code doesn't. Confirm with normalised smali.
            o = oi.find_methods(ni.sig(r), limit=1)
            try:
                if o and len(changed) + noise < 3000 and _norm_smali(oi.smali(o[0])) == _norm_smali(ni.smali(r)):
                    noise += 1
                    continue
            except Exception:  # noqa: BLE001
                pass
            changed.append((r, old[k]))
    seen = {ni.sig(r) for r, _ in changed}
    focus = [c["sig"] for c in orep["seams"]["candidates"][:60]]
    focus += [r["where"] for r in (orep.get("known_app") or {}).get("results", []) if r.get("where") and ";->" in r["where"]]
    for sig in dict.fromkeys(focus):
        if sig in seen:
            continue
        o, n = oi.find_methods(sig, limit=1), ni.find_methods(sig, limit=1)
        if o and n and o[0]["code_off"] and n[0]["code_off"]:
            try:
                if oi.smali(o[0]) != ni.smali(n[0]):
                    changed.append((n[0], o[0]["insns"]))
                    seen.add(sig)
            except Exception:  # noqa: BLE001 — a bad code item must not sink the diff
                pass
    out = []
    for r, old_insns in changed[:limit]:
        try:
            head = [ln.strip() for ln in ni.smali(r).splitlines()[2:8] if ln.strip()]
        except Exception:  # noqa: BLE001
            head = []
        out.append({"sig": ni.sig(r), "app": bool(r["is_app"]), "sdk": r["sdk"], "old_insns": old_insns,
                    "new_insns": r["insns"], "head": head})
    return {"count": len(changed), "methods": out,
            "classes_added": [c for c in _added_classes(oi, ni)][:50]}


def _added_classes(oi, ni):
    have = {r[0] for r in oi.q("SELECT name FROM classes")}
    return [r[0] for r in ni.q("SELECT name FROM classes") if r[0] not in have]


def render(d: dict) -> str:
    L = [f"# Build diff: {d['package']} {d['old']['version']} → {d['new']['version']}", ""]
    c = d["classes"]
    L.append(f"App/vendor classes {c['old']:,} → {c['new']:,} · removed {c['removed']:,} · added {c['added']:,} · "
             f"renames matched {c['renamed_matched']:,} {c['by_confidence']}")
    L.append("")
    if d.get("fingerprints"):
        L.append("## Shipped fingerprints (known app)")
        for f in d["fingerprints"]:
            L.append(f"- `{f['id']}`: {f['old']} → **{f['new']}** {f.get('where') or ''} "
                     + ("; candidates: " + " | ".join(f["candidates"]) if f["candidates"] else ""))
        L.append("")
    bc = d.get("body_changes")
    if bc is not None:
        L.append(f"## Same build: {bc['count']} method bod{'y' if bc['count'] == 1 else 'ies'} changed"
                 + (f", {len(bc['classes_added'])} class(es) added" if bc["classes_added"] else "")
                 + (" — identical code" if not bc["count"] and not bc["classes_added"] else " (patched build?)"))
        for m in bc["methods"][:30]:
            where = "app" if m["app"] else (m["sdk"] or "library")
            L.append(f"- `{m['sig']}` [{where}] insns {m['old_insns']}→{m['new_insns']}: `"
                     + " ; ".join(m["head"][:3]) + "`")
        for c in bc["classes_added"][:15]:
            L.append(f"- + class `{c}`")
        L.append("")
    L.append("## Where the old build's seam candidates went")
    for m in d["seam_moves"]:
        if m["status"] == "same":
            continue
        L.append(f"- {m['status']}: `{m['old']}` → `{m['new']}`")
    same = sum(1 for m in d["seam_moves"] if m["status"] == "same")
    L.append(f"- ({same} unchanged)")
    L.append("")
    for key, title in (("sdks_added", "SDKs added"), ("sdks_removed", "SDKs removed")):
        if d[key]:
            L.append(f"**{title}:** " + ", ".join(s["sdk"] for s in d[key]))
    if d["sdks_changed"]:
        L.append("**SDK size changes:** " + ", ".join(f"{s['sdk']} {s['old']}→{s['new']}" for s in d["sdks_changed"]))
    n = d["native"]
    if n["added"] or n["removed"] or n["changed"]:
        L.append(f"**Native:** +{n['added']} −{n['removed']} changed " +
                 ", ".join(f"{x['lib']} ({x['old_size']:,}→{x['new_size']:,})" for x in n["changed"]))
    if d["ad_hosts_added"] or d["ad_hosts_removed"]:
        L.append(f"**Ad hosts:** +{d['ad_hosts_added']} −{d['ad_hosts_removed']}")
    L.append("")
    if d["ad_strings_added"]:
        L.append("## New ad-related strings")
        L += [f"- `{s[:140]}`" for s in d["ad_strings_added"][:40]]
        L.append("")
    if d["ad_strings_removed"]:
        L.append("## Removed ad-related strings")
        L += [f"- `{s[:140]}`" for s in d["ad_strings_removed"][:40]]
        L.append("")
    renamed = [r for r in d["renames_sample"] if r["old"] != r["new"]]
    if renamed:
        L.append("## Class renames (sample)")
        L += [f"- `{r['old']}` → `{r['new']}` ({r['confidence']}, source {r['source']})" for r in renamed[:60]]
    return "\n".join(L) + "\n"
