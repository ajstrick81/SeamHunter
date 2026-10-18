"""Tracker audit: which analytics / attribution / crash / measurement / engagement / ACR SDKs an app
carries, the evidence for each (code, manifest, strings, hosts), where the app starts them, the
documented manifest kill switches, and a blocklist split by how safe each host is to block.

Evidence that survives R8: manifest component names (receivers/services keep their names), host
strings, and SDK marker strings. Class-package evidence is strongest but vanishes when R8 renames
the SDK (e.g. Google Mobile Ads classes present without a configured app id).
"""
from __future__ import annotations

import re

from .index import esc_like
from .kb.trackers import CATEGORIES, SENSITIVE_PERMISSIONS, TRACKERS

INIT_RE = re.compile(r"(?i)^(init\w*|start\w*|configure\w*|setup\w*|getInstance|with|create\w*|enable\w*|"
                     r"setEnabled|activate\w*|builder|newBuilder|setUserId|logEvent|trackEvent|track)$")


def _components(manifest_tree) -> list[str]:
    out = []
    if not manifest_tree:
        return out
    pkg = (manifest_tree.get("attrs") or {}).get("package", "")
    for app in manifest_tree.get("children", []):
        if app.get("tag") != "application":
            continue
        for c in app.get("children", []):
            if c.get("tag") in ("activity", "activity-alias", "service", "receiver", "provider"):
                n = (c.get("attrs") or {}).get("name") or ""
                if n.startswith("."):
                    n = pkg + n
                out.append(n)
    return out


def _host_match(host: str, domain: str) -> bool:
    host = host.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def audit(idx, f: dict, manifest_tree=None) -> dict:
    q = idx.q
    comps = _components(manifest_tree)
    meta = ((f.get("manifest") or {}).get("meta_data") or {})
    hosts = [h for h in (f.get("hosts") or []) if h.get("host")]
    items = []
    claimed_hosts = set()
    for name, cat, prefixes, markers, thosts, kills, note in TRACKERS:
        ev = {"classes": 0, "components": [], "markers": [], "hosts": []}
        for p in prefixes:
            ev["classes"] += q("SELECT COUNT(*) FROM classes WHERE name LIKE ? ESCAPE '\\'", esc_like(p) + "%")[0][0]
            dotted = p[1:].replace("/", ".")
            ev["components"] += [c for c in comps if c.startswith(dotted)]
        for mk in markers:
            # host/url-like markers by substring; bare words only as an exact string (no "pinpoint accuracy" hits)
            if "." in mk or "/" in mk:
                hit = q("SELECT 1 FROM strings WHERE instr(value, ?) > 0 LIMIT 1", mk)
            else:
                hit = q("SELECT 1 FROM strings WHERE value = ? LIMIT 1", mk)
            if hit:
                ev["markers"].append(mk)
        found_hosts = []
        for dom, block in thosts:
            for h in hosts:
                if _host_match(h["host"], dom):
                    found_hosts.append({"host": h["host"], "block": block, "used_by": (h.get("used_by") or [])[:2],
                                        "seen": {k: h.get(k, 0) for k in ("dex", "native", "assets")}})
                    claimed_hosts.add(h["host"])
        ev["hosts"] = [x["host"] for x in found_hosts]
        if not (ev["classes"] or ev["components"] or ev["markers"] or found_hosts):
            continue
        confidence = ("code" if ev["classes"] else "manifest" if ev["components"] else
                      "hosts" if found_hosts else "strings")
        init_sites = _init_sites(idx, prefixes) if ev["classes"] else []
        ks = [{"key": k, "value": v, "effect": e, "current": meta.get(k)} for k, v, e in kills]
        items.append({"name": name, "category": cat, "category_label": CATEGORIES.get(cat, cat),
                      "confidence": confidence, "evidence": ev, "hosts": found_hosts,
                      "init_sites": init_sites, "kill_switches": ks, "note": note})
    order = list(CATEGORIES)
    items.sort(key=lambda t: (order.index(t["category"]) if t["category"] in order else 99,
                              -t["evidence"]["classes"], t["name"]))
    by_cat: dict[str, int] = {}
    for t in items:
        by_cat[t["category"]] = by_cat.get(t["category"], 0) + 1
    perms = [{"permission": p, "what": w} for p, w in SENSITIVE_PERMISSIONS.items()
             if p in ((f.get("manifest") or {}).get("permissions") or [])]
    block = {"safe": [], "caution": [], "never": []}
    for t in items:
        for h in t["hosts"]:
            if h["host"] not in block[h["block"]]:
                block[h["block"]].append(h["host"])
    other = [h["host"] for h in hosts if h.get("category") in ("analytics", "attribution", "verification")
             and h["host"] not in claimed_hosts]
    return {"items": items, "count": len(items), "by_category": by_cat, "permissions": perms,
            "blocklist": block, "other_hosts": other[:40],
            "kill_switches": [dict(k, tracker=t["name"]) for t in items for k in t["kill_switches"]]}


def _init_sites(idx, prefixes, limit=5) -> list[dict]:
    """App code calling into the SDK — where it is started/configured (the opt-in block hook point)."""
    rows = []
    for p in prefixes:
        like = esc_like(p) + "%"
        rows += idx.q(
            "SELECT DISTINCT c.name AS cls, m.name AS mname, m.params, m.ret, r.ref AS callee "
            "FROM m_call x JOIN refs r ON r.id=x.r JOIN methods m ON m.id=x.m JOIN classes c ON c.id=m.class "
            "WHERE r.ref LIKE ? ESCAPE '\\' AND c.name NOT LIKE ? ESCAPE '\\' AND c.is_app=1 AND c.sdk IS NULL LIMIT 60",
            like, like)
    seen, out = set(), []
    for r in sorted(rows, key=lambda r: not INIT_RE.match(r["callee"].split("->")[1].split("(")[0])):
        caller = f"{r['cls']}->{r['mname']}({r['params']}){r['ret']}"
        if caller in seen:
            continue
        seen.add(caller)
        out.append({"caller": caller, "callee": r["callee"]})
        if len(out) >= limit:
            break
    return out
