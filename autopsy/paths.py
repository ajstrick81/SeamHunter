"""Delivery-path synthesis: turn the flat evidence (seam candidates, integration points,
implementers, SDKs, hosts) into a small number of connected, per-mechanism investigation
profiles an analyst can act on.

Each profile is one delivery mechanism (IMA client / IMA DAI / SSAI / media3 / pause ads /
telemetry) expressed as an ordered flow — request/config → response/stream → scheduling →
playback/detection → UI/seek → resume/fallback — with the app-owned boundaries ranked above
SDK-internal, UI-only and telemetry-only sites. Nothing here modifies anything, and no static
finding is presented as a completed patch: every hypothesis carries a role, an evidence-based
confidence label, a runtime-verification contract, and a state that starts at `candidate`.
"""
from __future__ import annotations

import re

from .kb.seams import SEAMS

_SEAM_BY_ID = {s["id"]: s for s in SEAMS}

# States a hypothesis can be in. Static analysis only ever assigns `candidate` (plausible static
# link) or `requires_runtime` (string/keyword-only, needs behavioral proof); the remaining states
# are reachable only with on-device / write evidence the tool cannot produce by itself.
STATES = ("candidate", "requires_runtime", "experiment_prepared", "matched", "write_verified", "runtime_verified")

# Role/confidence vocabulary (Priority-2 evidence model).
ROLE_CONFIRMED = "confirmed delivery boundary"   # constructs/requests/selects/installs ad media
ROLE_STRONG = "strong intervention candidate"    # app-owned control that influences delivery
ROLE_BREAK = "playback/break/resume control"      # media selection, break lifecycle, seek, pause, resume
ROLE_UI = "UI only"                              # shows/hides an ad surface, no media control
ROLE_TELEMETRY = "telemetry/measurement only"    # observes/reports ad activity
ROLE_CONFIG = "configuration/testing control"    # client-side behavior, may not affect server
ROLE_RUNTIME = "requires runtime evidence"       # plausible static link, no behavioral proof

# Ownership ranking (brief Priority-1): lower sorts first.
RANK = {
    "request": 1,      # app-owned request / configuration / response boundary
    "scheduling": 2,   # app-owned scheduling / media-source construction
    "resume": 3,       # app-owned break-state / content-resume control
    "playback": 3,
    "adapter": 4,      # app-to-SDK adapter / listener boundary
    "ui": 5,           # app-owned UI entry point
    "telemetry": 7,    # tracking / measurement / verification only
}
VENDOR_INTERNAL_RANK = 6

# Mechanisms, in the order the short brief presents them.
MECHANISMS = [
    ("csai", "IMA client-side ad insertion (CSAI)"),
    ("dai", "IMA DAI (server-stitched stream)"),
    ("ssai", "Server-side ad insertion (Yospace / FreeWheel / MediaTailor)"),
    ("media3", "media3 client-side ad insertion (AdsMediaSource)"),
    ("pause", "Pause ads"),
    ("telemetry", "Tracking, measurement & verification"),
]

STAGES = ["request", "scheduling", "playback", "ui", "resume"]
STAGE_LABEL = {
    "request": "configuration / request / response",
    "scheduling": "scheduling / media-source",
    "playback": "playback / break detection",
    "ui": "UI & seek policy",
    "resume": "content resume / fallback",
}

_DAI_NAME = re.compile(r"(?i)\bDAI\b|VODDAI|createVod|createLive|createPod|StreamId|StreamRequest|StreamManager")
_PAUSE = re.compile(r"(?i)pause")
_BEACON = re.compile(r"(?i)beacon|impression|quartile|firetracking|trackad")
_SCHEDULE_NAME = re.compile(r"(?i)adbreaks?|cuepoints?|adpods?|adschedule|insertion|timeline|playbackstate")
_RESUME_NAME = re.compile(r"(?i)onaderror|aderror|contentresume|resume|onadevent|fallback|alternatecdn|preferfallback")
_REQUEST_NAME = re.compile(r"(?i)^(request|fetch|load|get)\w*(ad|stream|dai|ssai|config|url|endpoint|provider)")
_UI_NAME = re.compile(r"(?i)^(show|hide|display|render|bind|toggle)|overlay|slate|countdown|badge")


def _evidence_basis(why: list[str]) -> set[str]:
    basis = set()
    for w in why:
        if w.startswith("calls seam API") or w.startswith("calls ad-named"):
            basis.add("call")
        elif w.startswith("overrides"):
            basis.add("interface")
        elif w.startswith("strings:"):
            basis.add("string")
        elif w.startswith("shape:") or w.startswith("name tokens") or w.startswith("obfuscated method"):
            basis.add("name")
        elif "ad SDK type in signature" in w:
            basis.add("type")
    return basis


def _why_text(c) -> str:
    return " ".join(c.get("why", [])) + " " + (c.get("strategy") or "")


def _mechanisms_of(c) -> set[str]:
    """Every delivery mechanism a candidate plausibly belongs to (a method can touch >1)."""
    seams = set(c.get("seams", []))
    engines = {_SEAM_BY_ID[s]["engine"] for s in seams if s in _SEAM_BY_ID}
    name = c.get("name", "")
    sig = c.get("sig", "")
    w = _why_text(c)
    out = set()
    # DAI first (it is a strict subset of IMA naming)
    if "ima-dai" in engines or _DAI_NAME.search(name) or "IMA DAI VideoStreamPlayer" in w or \
            "createVodStreamRequest" in sig or "createLiveStreamRequest" in sig:
        out.add("dai")
    if {"ssai"} & engines or "media3-ssai-source" in seams or "yospace" in seams or \
            "freewheel" in seams or "mediatailor" in seams:
        out.add("ssai")
    if {"media3-ads-media-source", "media3-adplaybackstate"} & seams or \
            "media3 AdsLoader implementation" in w or "ExoPlayer2 AdsLoader implementation" in w or \
            "custom media3 DataSource" in w:
        out.add("media3")
    if "media3 SSAI updater" in w or "FreeWheel event listener" in w:
        out.add("ssai")
    if "IMA StreamManager impl" in w or "IMA DAI VideoStreamPlayer" in w:
        out.add("dai")
    if _PAUSE.search(name) or _PAUSE.search(sig) or "pause-ad UI" in w:
        out.add("pause")
    if _BEACON.search(name) or "ad beacon" in w or "analytics" in engines:
        out.add("telemetry")
    # IMA client: IMA engine signals that are not DAI
    ima_client = ({"ima"} & engines) or any(s in seams for s in
                  ("ima-adsmanager-start", "ima-cuepoints", "ima-adsloader-request", "ima-adevent")) or \
                 "IMA AdEvent listener" in w or "IMA AdsLoaded listener" in w or "IMA AdError listener" in w or \
                 "IMA custom VideoAdPlayer" in w
    if ima_client and "dai" not in out:
        out.add("csai")
    # Fall back to the shape/name so app-owned boundaries without a seam call still land somewhere.
    if not out:
        if _SCHEDULE_NAME.search(name) or "ad schedule accessor" in w or "ad boolean gate" in w:
            out.add("csai")
        elif _UI_NAME.search(name) and ("ad" in w.lower()):
            out.add("pause" if _PAUSE.search(w) else "csai")
    return out


def _stage_of(c, mechanism: str) -> str:
    seams = set(c.get("seams", []))
    name = c.get("name", "")
    w = _why_text(c)
    if "ima-dai-streamrequest" in seams or "ima-adsloader-request" in seams or "freewheel" in seams or \
            "mediatailor" in seams or "ad request" in w or "config getter" in w or "ad/SSAI config getter" in w or \
            _DAI_NAME.search(name) and mechanism == "dai" and _REQUEST_NAME.search(name) or \
            "getSsaiConfig" in name or "startSession" in name:
        return "request"
    if "ima-cuepoints" in seams or "media3-ads-media-source" in seams or "media3-adplaybackstate" in seams or \
            "ad schedule accessor" in w or "ad timeline builder" in w or "ima-adsmanager-start" in seams or \
            _SCHEDULE_NAME.search(name) or "AdsLoaded listener" in w:
        return "scheduling"
    if "break-start" in w or "onAdBreak" in name or "dispatchAdPodStart" in name or "ima-streammanager" in seams or \
            "metadata output" in w or "exo-metadata" in seams or "VideoStreamPlayer" in w or "loadUrl" in name:
        return "playback"
    if "pause-ad UI" in w or "ad UI" in w or "ad display entry" in w or "UI bank" in w or _UI_NAME.search(name) or \
            "seek" in name.lower():
        return "ui"
    if _RESUME_NAME.search(name) or "AdError listener" in w or "CDN/stream selector" in w or "content resume" in w:
        return "resume"
    return "scheduling"


def classify_role(c) -> dict:
    """Role, confidence and evidence basis for one candidate (evidence-based, not keyword-based)."""
    seams = set(c.get("seams", []))
    name = c.get("name", "")
    ret = c.get("ret", "")
    w = _why_text(c)
    basis = _evidence_basis(c.get("why", []))
    if c.get("callers"):
        basis.add("caller")
    if c.get("dataflow"):
        basis.add("field")

    if {"ima-dai-streamrequest", "media3-ads-media-source", "media3-ssai-source"} & seams or \
            "createVodStreamRequest" in c.get("sig", "") or "requestStream" in w:
        role = ROLE_CONFIRMED
    elif "ad schedule accessor" in w and (ret.startswith("Ljava/util/") or ret.startswith("[")):
        role = ROLE_CONFIRMED
    elif _BEACON.search(name) or "ad beacon" in w:
        role = ROLE_TELEMETRY
    elif "pause-ad UI" in w or "ad UI" in w or "ad display entry" in w or "UI bank" in w or \
            (_UI_NAME.search(name) and ret == "V"):
        role = ROLE_UI
    elif "break-start" in w or _RESUME_NAME.search(name) or "content resume" in w or "metadata output" in w or \
            "onAdBreak" in name or "dispatchAdPodStart" in name or "AdError listener" in w or "AdEvent" in w:
        role = ROLE_BREAK
    elif "ad request" in w or "ad boolean gate" in w or "ad-free flag" in w or "config getter" in w or \
            "ad/SSAI config getter" in w or "ad timeline builder" in w or _DAI_NAME.search(name) or \
            "CDN/stream selector" in w:
        role = ROLE_STRONG
    else:
        role = ROLE_RUNTIME

    # Confidence: a strong/confirmed role needs structural evidence (a call, an implemented
    # interface, a field flow or a caller). Name/string presence alone is downgraded.
    structural = basis & {"call", "interface", "field", "caller", "type"}
    if role in (ROLE_CONFIRMED, ROLE_STRONG) and not structural:
        role, confidence = ROLE_RUNTIME, "low"
    elif role == ROLE_CONFIRMED:
        confidence = "high"
    elif role == ROLE_STRONG:
        confidence = "high" if "call" in basis or "interface" in basis else "medium"
    elif role == ROLE_BREAK:
        confidence = "medium"
    elif role in (ROLE_UI, ROLE_TELEMETRY):
        confidence = "medium" if structural else "low"
    else:
        confidence = "low"
    return {"role": role, "confidence": confidence, "evidence_basis": sorted(basis),
            "state": "candidate" if role != ROLE_RUNTIME else "requires_runtime"}


def _ownership_rank(c, stage: str, role: str) -> int:
    if role == ROLE_TELEMETRY:
        return RANK["telemetry"]
    if "overrides" in _why_text(c) and stage not in ("request",):
        return RANK["adapter"]
    return RANK.get(stage, 4)


# ---------------------------------------------------------------- runtime-verification contracts
_COMMON_CHECKS = [
    "Content starts without waiting indefinitely for an ad callback.",
    "Content resumes after every break or a simulated ad error.",
    "No crash, black screen, spinner, silent wedge, or retry loop.",
    "Expected logs/counters prove the intended branch was reached.",
    "Negative control: unrelated playback is unchanged.",
]
_MECH_CHECKS = {
    "csai": ["Pre-roll, mid-roll and post-roll breaks exercised.", "Cold launch and resumed playback."],
    "dai": ["Stitched stream still plays end-to-end (ad media is part of the stream).",
            "Live-edge behavior and stream continuity hold.", "Seeking/trick-play across a stitched break."],
    "ssai": ["Stitched stream still plays end-to-end.", "Live-edge continuity; no segment stalls.",
             "Confirm the change controls media selection, not just an event/UI."],
    "media3": ["AdPlaybackState reflects the change.", "Seeking, subtitles, audio tracks, bitrate changes.",
               "Cast playback where applicable."],
    "pause": ["Pause-ad surface no longer renders.", "Playback pause/resume still works normally."],
    "telemetry": ["Playback and ad delivery are unchanged (telemetry is not a delivery path)."],
}


def verification_plan(mechanism: str) -> list[str]:
    return _MECH_CHECKS.get(mechanism, []) + _COMMON_CHECKS


# ---------------------------------------------------------------- subsystem dedup
_SUBSYSTEMS = [
    ("Yospace", "ssai", r"(?i)yospace"),
    ("FreeWheel", "ssai", r"(?i)freewheel|fwmrm"),
    ("AWS MediaTailor", "ssai", r"(?i)mediatailor"),
]


def _subsystem_summaries(f, members_by_mech) -> list[dict]:
    """Collapse a large vendor subsystem (hundreds of Yospace internals) into one summary with a
    few app-facing boundaries; the exhaustive sites stay in report-full / report.json / sqlite."""
    out = []
    sdks = {s["sdk"]: s for s in f.get("sdks", [])}
    ips = {p["id"]: p for p in f["seams"].get("integration_points", [])}
    for label, mech, _rx in _SUBSYSTEMS:
        sdk = next((v for k, v in sdks.items() if re.search(_rx, k)), None)
        ip = next((ips[i] for i in ips if re.search(_rx, i)), None)
        classes = sdk["classes"] if sdk else 0
        sites = ip["count"] if ip else 0
        # a lone type-name stub (e.g. a FreeWheel class nobody calls) is not a subsystem worth collapsing
        if sites == 0 and classes < 5:
            continue
        boundaries = []
        for m in members_by_mech.get(mech, []):
            if label.lower().split()[0] in _why_text(m).lower() or "ssai" in _why_text(m).lower() or \
                    (ip and any(m.get("name") in s["sig"] for s in ip.get("sites", []))):
                boundaries.append(m.get("sig"))
        out.append({
            "subsystem": label, "mechanism": mech, "vendor_classes": classes, "call_sites": sites,
            "app_facing_boundaries": boundaries[:4],
            "note": f"{classes} vendor class(es) and {sites} call site(s) collapsed to one subsystem — "
                    "the exhaustive sites are in report-full.md / report.json / index.sqlite.",
            "warning": "Server-stitched: suppressing these events/sessions does not remove the ad media; "
                       "the ceiling is break detection, UI masking, seek-where-allowed, or a clean-variant request."
                       if mech == "ssai" else "",
        })
    return out


# ---------------------------------------------------------------- member union
def _parse_sig(sig: str):
    cls, rest = sig.split("->", 1)
    name = rest.split("(", 1)[0]
    params, ret = rest.split("(", 1)[1].split(")", 1)
    return cls, name, params, ret


_MODRISK = {  # modification risk surfaced alongside ownership rank (Codex: high-value boundaries are more dangerous)
    ROLE_CONFIRMED: "high — content start/selection can depend on it; verify resume/fallback",
    ROLE_STRONG: "high — a request/config boundary the player may block on; check the failure path",
    ROLE_BREAK: "medium-high — resume/seek handling; wrong edits can leave content paused or wedged",
    ROLE_UI: "low — a display surface; hiding it does not change media",
    ROLE_TELEMETRY: "low — observational; not on the playback path",
    ROLE_CONFIG: "medium — client-side config; may not affect server enforcement",
    ROLE_RUNTIME: "unknown — needs runtime evidence before any change",
}


def _members(f: dict) -> dict:
    """Union of every surfaced method (ranked candidates + integration sites + implementer overrides),
    deduplicated by method id, with evidence merged across all three so a boundary that is only an
    integration site (e.g. a media3 AdsMediaSource call that never became a ranked candidate) is not
    lost, and a candidate that is also a seam caller / interface implementer is not wrongly downgraded.
    """
    merged: dict[int, dict] = {}

    def _add_why(m, w):
        if w not in m["why"]:
            m["why"].append(w)

    for c in f["seams"]["candidates"]:
        merged[c["id"]] = c
        c.setdefault("why", [])
        c.setdefault("seams", [])

    seam_by_id = {s["id"]: s for s in SEAMS}
    for p in f["seams"].get("integration_points", []):
        for s in p.get("sites", []):
            mid = s["id"]
            m = merged.get(mid)
            if m is None:
                cls, name, params, ret = _parse_sig(s["sig"])
                m = merged[mid] = {"id": mid, "sig": s["sig"], "class": cls, "name": name,
                                   "params": params, "ret": ret, "score": 0, "insns": 0,
                                   "source": None, "vendor": None, "why": [], "seams": [],
                                   "strategy": seam_by_id.get(p["id"], {}).get("strategy")
                                   or p.get("strategy"), "evidence_id": s.get("evidence_id")}
            if p["id"] not in m["seams"]:
                m["seams"].append(p["id"])
            _add_why(m, "calls seam API: " + p["id"])
            m.setdefault("evidence_id", s.get("evidence_id"))

    for imp in f["seams"].get("implementers", []):
        for cl in imp.get("classes", []):
            for mm in cl.get("methods", []):
                mid = mm["id"]
                m = merged.get(mid)
                if m is None:
                    cls, name, params, ret = _parse_sig(mm["sig"])
                    m = merged[mid] = {"id": mid, "sig": mm["sig"], "class": cls, "name": name,
                                       "params": params, "ret": ret, "score": 0, "insns": mm.get("insns", 0),
                                       "source": cl.get("source"), "vendor": None, "why": [], "seams": [],
                                       "strategy": imp.get("strategy"), "evidence_id": mm.get("evidence_id")}
                _add_why(m, "overrides " + imp["label"])
                m.setdefault("evidence_id", mm.get("evidence_id"))
    return merged


# ---------------------------------------------------------------- main
def build(f: dict) -> dict:
    """Assemble the per-mechanism delivery-path profiles from the already-computed findings."""
    merged = _members(f)
    cand_ids = {c["id"] for c in f["seams"]["candidates"]}
    members_by_mech: dict[str, list] = {k: [] for k, _ in MECHANISMS}
    for m in merged.values():
        info = classify_role(m)
        m.update(info)
        mechs = _mechanisms_of(m)
        m["mechanisms"] = sorted(mechs)
        m["modification_risk"] = _MODRISK.get(info["role"], "")
        for mech in mechs:
            stage = _stage_of(m, mech)
            rank = _ownership_rank(m, stage, info["role"])
            members_by_mech.setdefault(mech, []).append(m)
            m.setdefault("_stage", {})[mech] = stage
            m["ownership_rank"] = min(m.get("ownership_rank", 99), rank)
    # keep the ranked-candidate list enriched in place (reports read role/confidence/mechanisms off it)
    # synthesized site/implementer members that never ranked are reachable via the paths + nav.json.

    sdk_cats = {s["category"] for s in f.get("sdks", [])}
    ssai_present = "ssai" in sdk_cats or any(members_by_mech.get("ssai"))
    subsystems = _subsystem_summaries(f, members_by_mech)

    paths = []
    for mech, label in MECHANISMS:
        members = members_by_mech.get(mech, [])
        sub = [s for s in subsystems if s["mechanism"] == mech]
        present = bool(members) or bool(sub) or (mech == "ssai" and ssai_present) or \
                  (mech == "telemetry" and sdk_cats & {"verification", "analytics", "attribution"})
        if not present:
            continue
        # order members by ownership rank, then score
        members = sorted(members, key=lambda c: (c.get("ownership_rank", 9), -c.get("score", 0)))

        def _item(c):
            return {"evidence_id": c.get("evidence_id"), "sig": c.get("sig"),
                    "role": c.get("role"), "confidence": c.get("confidence"),
                    "ownership_rank": c.get("ownership_rank"),
                    "modification_risk": c.get("modification_risk"),
                    "strategy": c.get("strategy"), "state": c.get("state")}

        # Telemetry has no delivery stages (it is observational), so list its boundaries flat.
        stages = {}
        boundaries = []
        if mech == "telemetry":
            boundaries = [_item(c) for c in members]
        else:
            for st in STAGES:
                items = [c for c in members if c.get("_stage", {}).get(mech) == st]
                if items:
                    stages[st] = [_item(c) for c in items]
        server_stitched = mech in ("dai", "ssai")
        # only claim the stages that actually carry evidence (no empty "connected" flow)
        present_flow = [STAGE_LABEL[s] for s in STAGES if s in stages]
        path = {
            "id": mech, "label": label, "present": True,
            "server_stitched": server_stitched,
            "flow": present_flow,
            "stages": stages,
            "boundaries": boundaries,
            "top_boundaries": [c.get("evidence_id") for c in members[:3]],
            "subsystems": sub,
            "verification": verification_plan(mech),
            "warnings": [],
        }
        if server_stitched:
            path["warnings"].append(
                "Server-stitched delivery: the ad media is part of the returned stream. Suppressing an "
                "event listener, a measurement call or a UI element does NOT remove the ad media unless it "
                "is proven to control the actual media/manifest selection. Realistic client-side options: "
                "detect the break, mask break UI, seek where the stream/player allow it, or change the "
                "request configuration before the stitched stream is issued.")
        if mech == "pause":
            path["warnings"].append(
                "A display method can hide the pause-ad surface, but that is distinct from preventing its "
                "request or state transition — note which one a given candidate controls.")
        if mech == "telemetry":
            path["warnings"].append(
                "Telemetry/measurement/verification is not a delivery mechanism; it is supporting evidence, "
                "ranked below request and playback boundaries.")
        paths.append(path)

    return {"paths": paths, "subsystems": subsystems,
            "states": list(STATES),
            "note": "Each hypothesis is in state `candidate` (plausible static link) or `requires_runtime` "
                    "(string/keyword-only); no static finding is a completed patch. Advance to "
                    "experiment_prepared/matched/write_verified/runtime_verified only with on-device evidence."}
