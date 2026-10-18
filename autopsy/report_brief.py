"""Ultra-compact investigation brief — the smallest layer, built for an agent's token budget.

Only: identity, per-mechanism path summaries with the top 1-2 app-owned boundaries per populated
stage, regional controls, principal risks, and the runtime-verification contracts — each boundary as
an evidence ID that resolves in nav.json. Everything exhaustive stays in report-full.md / report.json
/ index.sqlite. If `delivery_paths` is absent (e.g. a scan that found no seams) this falls back to a
one-line pointer to the full report.
"""
from __future__ import annotations


def _s(sig, n=78):
    sig = sig or ""
    return sig if len(sig) <= n else sig[: n - 1] + "…"


def render(f: dict) -> str:
    m = f.get("manifest", {})
    code = f.get("code", {})
    L = [f"# SeamHunter brief — {m.get('package')} {m.get('versionName') or ''}", ""]
    obf = (code.get("obfuscation") or {}).get("name_obfuscation", "?")
    L.append(f"_{f.get('tool', '')} · {code.get('app_classes', 0):,} app classes · name-obfuscation: {obf} · "
             f"evidence IDs (E…) resolve in nav.json; full detail in report-full.md / report.json / index.sqlite._")
    L.append("")

    dp = (f.get("delivery_paths") or {}).get("paths") or []
    if not dp:
        L.append("No delivery paths surfaced — see report.md / report-full.md.")
        return "\n".join(L) + "\n"

    L.append("## Delivery paths")
    L.append("")
    for p in dp:
        tag = " · server-stitched" if p.get("server_stitched") else ""
        L.append(f"### {p['label']}{tag}")
        if p.get("server_stitched"):
            L.append("> ⚠ Ad media is in the stream; suppressing events/UI/tracking does not remove it. "
                     "Ceiling: break detection, UI mask, seek-where-allowed, or a clean-variant request.")
        # top 1-2 boundaries per populated stage, app-owned first (already rank-sorted)
        for st in ["request", "scheduling", "playback", "ui", "resume"]:
            items = (p.get("stages") or {}).get(st)
            if not items:
                continue
            short_st = {"request": "req", "scheduling": "sched", "playback": "play", "ui": "ui",
                        "resume": "resume"}[st]
            for it in items[:2]:
                L.append(f"- [{short_st}] `{it['evidence_id']}` `{_s(it['sig'])}` — {it['role']} "
                         f"({it['confidence']}); risk: {_s(it.get('modification_risk'), 60)}")
        for it in (p.get("boundaries") or [])[:2]:
            L.append(f"- `{it['evidence_id']}` `{_s(it['sig'])}` — {it['role']} ({it['confidence']})")
        for s in p.get("subsystems", []):
            L.append(f"- subsystem {s['subsystem']}: {s['vendor_classes']} class(es), {s['call_sites']} site(s) "
                     f"(summarized; sites in full artifacts)")
        v: list = p.get("verification") or []
        if vcheck := v[:3]:
            L.append(f"- verify: " + " ".join(f"({i + 1}) {c}" for i, c in enumerate(vcheck)))
        L.append("")

    r = f.get("regional") or {}
    if r.get("present"):
        L.append("## Regional / configuration controls")
        for o in r["overrides"]:
            key = (o.get("key_strings") or [o.get("preference")])
            key = key[0] if key else None
            g = (o.get("getters") or [None])[0]
            L.append(f"- **{o['kind']}** `{key or ''}` (default `{o.get('default')}`, {o.get('confidence')}): "
                     f"getter `{_s(g, 50)}`" if g else f"- **{o['kind']}** `{key or ''}` ({o.get('confidence')})")
            L.append(f"  - ⚠ {_s(o.get('limitation'), 160)}")
        L.append("")

    plan = f.get("plan") or []
    risks = [p for p in plan if "⚠" in p or "LIVE" in p or "gated" in p.lower() or "ANR" in p][:4]
    if risks:
        L.append("## Principal risks")
        for p in risks:
            L.append(f"- {_s(p, 180)}")
        L.append("")

    L.append("_States: `candidate` / `requires_runtime` only (static). No finding is a completed patch "
             "until runtime-verified. Open a boundary with `seamhunter show <out> '<sig>'`._")
    return "\n".join(L) + "\n"
