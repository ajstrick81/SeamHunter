"""Navigation index + evidence IDs.

Gives SeamHunter's own artifacts the direct navigation Claude otherwise gets from an apktool
class index: every surfaced method gets a stable evidence ID, a class→smali-file (or queryable)
locator, a bounded snippet, and its callers/callees — so an analyst can jump from the short brief
to the exact smali boundary without re-reading the whole report or re-running the scan.

Class descriptors are kept case-sensitive (R8 emits names differing only by case, e.g. `Lsf/c;`
vs `LSf/c;`), so the map is keyed by the exact descriptor.
"""
from __future__ import annotations

import json
import os
import re

SNIPPET_LINES = 24


def assign_evidence(f: dict) -> dict:
    """Assign E-IDs to every surfaced method (candidates, implementer overrides, integration sites).

    A method keeps ONE id across all the places it appears, keyed by its method id.
    """
    by_mid: dict[int, str] = {}
    order: list[str] = []

    def eid_for(mid):
        if mid in by_mid:
            return by_mid[mid]
        e = f"E{len(order) + 1}"
        by_mid[mid] = e
        order.append(e)
        return e

    for c in f["seams"]["candidates"]:
        c["evidence_id"] = eid_for(c["id"])
    for imp in f["seams"].get("implementers", []):
        for cl in imp.get("classes", []):
            for m in cl.get("methods", []):
                m["evidence_id"] = eid_for(m["id"])
    for p in f["seams"].get("integration_points", []):
        for s in p.get("sites", []):
            s["evidence_id"] = eid_for(s["id"])
    return {"by_mid": by_mid, "order": order}


def _apktool_smali_file(apktool_dir: str, cls: str):
    """Map a class descriptor to its baksmali file under an apktool tree, if one was produced."""
    if not apktool_dir or not os.path.isdir(apktool_dir):
        return None
    rel = cls[1:-1] + ".smali"
    for sub in sorted(os.listdir(apktool_dir)):
        if sub.startswith("smali"):
            cand = os.path.join(apktool_dir, sub, *rel.split("/"))
            if os.path.exists(cand):
                return os.path.relpath(cand, os.path.dirname(apktool_dir.rstrip("/\\")))
    return None


def _decl_line(smali_text: str, name: str) -> int | None:
    for i, ln in enumerate(smali_text.splitlines(), 1):
        if ln.lstrip().startswith(".method") and re.search(r"\b%s\(" % re.escape(name), ln):
            return i
    return None


def build(idx, f: dict, out: str, ev: dict) -> dict:
    """Write nav.json (class map + per-evidence locators/snippets/xrefs) and return a compact
    eid→locator map for the reports."""
    apktool_dir = f.get("apktool_dir")
    classes: dict[str, dict] = {}
    evidence: dict[str, dict] = {}
    compact: dict[str, dict] = {}

    for mid, eid in ev["by_mid"].items():
        row = idx.method(mid)
        if not row:
            continue
        sig = idx.sig(row)
        cls = row["cls"]
        try:
            smali = idx.smali(row)
        except Exception:  # noqa: BLE001
            smali = ""
        lines = smali.splitlines()
        snippet = "\n".join(lines[:SNIPPET_LINES]) + (
            f"\n    ... ({len(lines) - SNIPPET_LINES} more lines — `seamhunter show <out> '{sig}'`)"
            if len(lines) > SNIPPET_LINES else "")
        callers = [idx.sig(r) for r in idx.callers(sig, limit=6, exact=True) if r["id"] != mid]
        callees = [c for c in idx.calls_of(mid)
                   if not c.startswith(("Ljava/", "Lkotlin/", "Landroid/util/"))][:8]
        smali_file = _apktool_smali_file(apktool_dir, cls)
        locator = {
            "class": cls, "method_id": mid,
            "show": f"seamhunter show <out> '{sig}'",
            "smali_file": smali_file,
            "source": row["source"],
        }
        evidence[eid] = {
            "sig": sig, "locator": locator, "decl_line": _decl_line(smali, row["name"]),
            "snippet": snippet, "callers": callers, "callees": callees,
        }
        compact[eid] = {"sig": sig, "smali_file": smali_file, "show": locator["show"]}
        cm = classes.setdefault(cls, {"source": row["source"], "dex": row["dex"],
                                      "smali_file": smali_file, "methods": []})
        cm["methods"].append({"sig": sig, "evidence_id": eid, "method_id": mid})

    nav = {
        "note": "Descriptors are case-sensitive. `smali_file` is populated only when the scan ran with "
                "--apktool; otherwise use the `show` locator (or `autopsy serve <out>`) to open a method.",
        "evidence": evidence,
        "classes": classes,
    }
    with open(os.path.join(out, "nav.json"), "w", encoding="utf-8") as fh:
        json.dump(nav, fh, indent=1, ensure_ascii=False, default=str)
    return compact
