"""Draft a reviewer's scoping summary after an autopsy: where ads appear to enter the app, which
methods look like candidate seams, and a device-verification runbook.

SeamHunter performs STATIC ANALYSIS ONLY and never modifies an APK. This output stops at the
candidate signature, the evidence, the return type, a confidence/match-count, and verification
guidance — it does not emit neutralization payloads or patch code.
"""
from __future__ import annotations

import json
import os
import re

from .seams import simple_class  # noqa: F401  (kept for callers/back-compat)


def app_key(pkg: str) -> str:
    parts = [p for p in (pkg or "app").split(".") if p not in ("com", "tv", "android", "app", "mobile", "ott", "atv", "leanback", "org", "net")]
    k = re.sub(r"[^a-z0-9]", "", (parts[0] if parts else "app").lower())
    return k or "app"


SAFE_SHAPES = ("obfuscated method in pause-ad UI class", "shape: ad display entry", "shape: ad beacon", "shape: ad boolean gate", "shape: ad-free flag",
               "shape: ad schedule accessor", "shape: ad timeline builder", "overrides IMA AdEvent listener")


def _auto_ok(c) -> str | None:
    """Why a candidate is a clearly-scoped seam, or None (then it goes to 'needs a closer read')."""
    why = " ".join(c["why"])
    ret = c["ret"]
    if c["strategy"].startswith("⚠"):
        return None
    if ret.startswith("L") and ret not in ("Ljava/util/List;", "Ljava/util/Collection;", "Ljava/util/Set;", "Ljava/util/Map;"):
        return None
    for s in SAFE_SHAPES:
        if s in why:
            if ret == "V" and "schedule" in s:
                continue
            return s
    if "ima-cuepoints" in c.get("seams", []) and ret in ("[J", "[I", "Ljava/util/List;"):
        return "cue-point accessor"
    return None


def pick_hooks(f: dict, max_hooks=6):
    hooks, review, seen = [], [], set()
    biggest = {}
    for c in f["seams"]["candidates"]:
        if any(w.startswith("obfuscated method in") for w in c["why"]):
            if c["class"] not in biggest or c["insns"] > biggest[c["class"]]["insns"]:
                biggest[c["class"]] = c
    for c in f["seams"]["candidates"]:
        if any(w.startswith("obfuscated method in") for w in c["why"]) and biggest.get(c["class"]) is not c:
            continue
        fp = c.get("fingerprint")
        key = (c["class"], c["name"])
        if not fp or key in seen or c["score"] < 8:
            continue
        seen.add(key)
        reason = _auto_ok(c)
        if reason and len(hooks) < max_hooks:
            hooks.append(dict(c, auto_reason=reason))
        elif len(review) < 8:
            review.append(c)
    return hooks, review


def _seam_md(i, c):
    """One candidate seam, as neutral Markdown — evidence and identification only."""
    fp = c.get("fingerprint", {})
    ident = ("unique in this build" if fp.get("unique")
             else f"{fp.get('matches', '?')} matches — ambiguous, needs tightening")
    L = [f"### Candidate seam {i} — `{c['sig']}`",
         f"- **Why it looks ad-related:** {'; '.join(c['why'])}",
         f"- **Role:** {c['strategy']}",
         f"- **Return type:** `{c['ret']}`",
         f"- **Identification:** {ident}"
         + (f"; anchors: {', '.join(fp['anchors'])}" if fp.get("anchors") else "")]
    pol = c.get("polarity") or {}
    if c["ret"] == "Z" and pol.get("neutral") and pol.get("evidence"):
        avoids = "false" if pol["neutral"] == "0x0" else "true"
        enters = "true" if pol["neutral"] == "0x0" else "false"
        L.append(f"- **Branch map ({pol.get('confidence')}):** at the call sites examined, returning "
                 f"`{avoids}` does not enter the ad path and returning `{enters}` does — " + "; ".join(pol["evidence"][:2]))
    for n in fp.get("notes", []):
        L.append(f"- _{n}_")
    if fp.get("descriptor"):
        L.append("- **Matcher descriptor** (structured; adapt to your own tooling):\n\n```json\n"
                 + json.dumps(fp["descriptor"], indent=2) + "\n```")
    return "\n".join(L)


def render(f: dict, out_dir: str) -> dict:
    m = f["manifest"]
    pkg = m.get("package") or "app"
    key = app_key(pkg)
    ver = m.get("versionName") or "?"
    hooks, review = pick_hooks(f)
    d = os.path.join(out_dir, "draft", key)
    os.makedirs(d, exist_ok=True)
    files = {}

    scoping = [
        f"# {pkg} {ver} — ad-seam scoping (SeamHunter)", "",
        "SeamHunter performs **static analysis only** and does not modify the APK. This is a reviewer's map of",
        "where ads appear to enter the app and the candidate seams where that happens. It reports evidence and",
        "identification — not patches. **Verify every seam** against the smali/Java in `report.md` and on a device.", "",
        f"**Engine guess:** {'; '.join(f.get('engine_guess') or ['unknown'])}", "",
    ]
    if hooks:
        scoping += ["## Candidate seams", ""]
        for i, h in enumerate(hooks, 1):
            scoping += [_seam_md(i, h), ""]
    else:
        scoping += ["## Candidate seams", "",
                    "No high-confidence seam surfaced statically. See `report.md` → 'Investigation points' "
                    "(integration points / native / manifest), and consider a runtime or manifest capture.", ""]
    if review:
        scoping += ["## Investigation points — need a closer read first", ""]
        scoping += [f"- `{c['sig']}` → {c['strategy']}" for c in review]
        scoping += [""]
    files["SCOPING.md"] = "\n".join(scoping)

    sdk_tags = []
    names = {s["sdk"] for s in f["sdks"]}
    if names & {"Google IMA SDK", "Media3 IMA extension"}:
        sdk_tags.append("IMASDK")
    if names & {"AndroidX Media3", "ExoPlayer 2"}:
        sdk_tags += ["ExoPlayerImpl", "MediaCodecVideoRenderer"]
    tag = f"SEAMHUNTER-{key.upper()}-ADS"
    grep = "|".join([tag] + sdk_tags + ["(?i)ad.?break", "(?i)vast", "(?i)cue"])
    files["VERIFY.md"] = "\n".join([
        f"# Verify {pkg} {ver} on device", "",
        "Line up: ad delivery -> code seam -> observable signature. SeamHunter only points at the seam;",
        "confirm the behaviour on a device you own before drawing conclusions.", "",
        "## 1. Device signature (unmodified build, while an ad plays)", "```",
        "adb logcat -c",
        f"adb shell monkey -p {pkg} 1",
        f"adb logcat -v time | grep -E \"{grep}\" | tee unmodified.log", "```",
        "Note what appears only while an ad plays (decoder reconfigure, SDK ad events, metrics bursts). "
        "Resolution changes are NOT an ad signal.", "",
        "## 2. Candidate seams to watch", ""] +
        [f"- Candidate {i}: `{h['sig']}`  (return `{h['ret']}`)" for i, h in enumerate(hooks, 1)] +
        ["", "## 3. After an app update",
         "- Re-scan with SeamHunter (`seamhunter scan --apktool`) and compare; fingerprints drift per build.",
         "- Confirm ads are actually being served (frequency capping can hide ads after many test launches).",
         "- Test VOD start, mid-roll position, seek over a break, resume, and live (if any).", ""])

    for name, text in files.items():
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    return {"dir": os.path.relpath(d, out_dir), "files": sorted(files), "key": key,
            "hooks": [{"sig": h["sig"], "why": h["auto_reason"], "returnType": h["ret"],
                       "confidence": (h.get("fingerprint") or {}).get("confidence"),
                       "polarity": h.get("polarity")} for h in hooks],
            "review": [{"sig": c["sig"], "strategy": c["strategy"]} for c in review]}
