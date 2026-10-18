"""Seam hunting: rank methods by how likely they are an ad seam, explain why, suggest the
patch strategy that worked before, and draft an obfuscation-resistant method fingerprint
whose uniqueness is checked against the whole index."""
from __future__ import annotations

import re
from collections import defaultdict

from .index import esc_like
from .kb.markers import AD_TOKENS, ad_string_hits, tokens
from .kb.seams import CLASS_SHAPES, GATED_CALLBACKS, IMPLEMENTS, NAME_SHAPES, SEAMS

# Vendor SDKs that are the app's own player/ad stack — real patch targets, unlike generic
# libraries (IMA internals, media3) whose own code is never where we cut.
VENDOR_SDKS = {
    "Paramount AVIA player", "CBS UVP player", "WBD/Discovery player", "Disney DMP player",
    "Disney DSS SDK", "BAMTech player", "Sky Core Player SDK", "Fox player/SDK", "24i player",
    "Prime Video AVOD", "Netflix TV (ninja)", "Netflix mobile client", "Twitch",
    "Amazon Video SDK", "Amazon IVS player",
}

AD_TYPE_RE = re.compile(r"interactivemedia|/ads?/|AdEvent|AdPlaybackState|AdsManager|AdsLoader|freewheel|yospace|"
                        r"mediatailor|StreamManager|AdBreak|CuePoint|Ssai|SSAI|Sgai|Stitcher|innovid", re.I)
OBF_SEG = re.compile(r"^[a-zA-Z]{1,2}\d?$|^[a-z]{1,3}$")

_SEAM_RES = [(s, re.compile(s["ref"])) for s in SEAMS]
_CLASS_RES = [(re.compile(r), label, strat) for r, label, strat in CLASS_SHAPES]
_GATED_RES = [(re.compile(r), w) for r, w in GATED_CALLBACKS]
ADMOB_API = {"loadBannerAd", "loadInterstitialAd", "loadRewardedAd", "loadNativeAd", "loadAppOpenAd",
             "loadRewardedInterstitialAd", "loadInterscrollerAd", "loadRtbBannerAd", "loadRtbInterstitialAd",
             "loadRtbRewardedAd", "loadRtbNativeAd", "getSDKVersionInfo", "getVersionInfo", "collectSignals"}
GMA_TYPE_RE = re.compile(r"Lcom/google/ads/mediation/|Lcom/google/android/gms/ads/")
_SCHED_METHOD = re.compile(r"^get(Points|Ranges|Breaks|Pods|Cues|CuePoints|Insertions|Markers)$")
_SCHED_RET = re.compile(r"^(Ljava/util/(List|Collection|Set);|\[J|\[I|\[F)$")
_SCHED_CLASS = re.compile(r"^(Ad|Ads)?(Insertion|AdBreak|AdPod|CuePoint|AdSchedule|AdTimeline|Stitcher\w*)s?$|^Ad[A-Z]\w*(Break|Pod|Schedule)$")
_SHAPE_RES = [(re.compile(n), re.compile(r), label, strat) for n, r, label, strat in NAME_SHAPES]


SYNTH = re.compile(r"\$r8\$|\$\$|^lambda\$|^access\$|\$lambda\$|^-")


def is_obfuscated_name(name: str) -> bool:
    return bool(OBF_SEG.match(name)) or len(name) <= 2 or bool(SYNTH.search(name))


def simple_class(desc: str) -> str:
    return desc.rstrip(";").rsplit("/", 1)[-1]


def split_params(params: str) -> list[str]:
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


class SeamHunter:
    def __init__(self, idx):
        self.idx = idx
        self.db = idx.db
        self._prep()

    # ------------------------------------------------------------ precompute
    def _prep(self):
        db = self.db
        # ad-ish strings
        self.ad_strings: dict[int, list[tuple[int, str]]] = {}
        for sid, val in db.execute("SELECT id, value FROM strings"):
            if len(val) > 2000:
                val = val[:2000]
            hits = ad_string_hits(val)
            if hits:
                self.ad_strings[sid] = hits
        # seam refs
        self.seam_refs: dict[int, list[dict]] = {}
        self.adish_refs: dict[int, int] = {}
        for rid, ref, name in db.execute("SELECT id, ref, name FROM refs"):
            for seam, rx in _SEAM_RES:
                if rx.search(ref):
                    self.seam_refs.setdefault(rid, []).append(seam)
            w = sum(AD_TOKENS.get(t, 0) for t in set(tokens(name)))
            if w >= 3 and not is_obfuscated_name(name):
                self.adish_refs[rid] = min(w, 6)
        # candidate classes: app code + vendor stacks
        self.cand_classes = {}
        for row in db.execute("SELECT id, name, is_app, sdk, source FROM classes"):
            cid, name, is_app, sdk, source = row
            if is_app or sdk in VENDOR_SDKS:
                self.cand_classes[cid] = (name, sdk, source)

    # ------------------------------------------------------------ scoring
    def score_all(self, limit=80):
        db = self.db
        scores: dict[int, float] = defaultdict(float)
        why: dict[int, list[str]] = defaultdict(list)
        seams_hit: dict[int, set[str]] = defaultdict(set)
        strategy: dict[int, str] = {}

        cand_ids = set(self.cand_classes)
        meth = {}
        for mid, cid, name, params, ret, flags, insns in db.execute(
                "SELECT id, class, name, params, ret, flags, insns FROM methods"):
            if cid not in cand_ids:
                continue
            if name.endswith("$default") or self.cand_classes[cid][0].endswith("$DefaultImpls;"):
                continue  # Kotlin default-argument / interface-default bridges: hook the real method instead
            meth[mid] = (cid, name, params, ret, flags, insns)
            cname = simple_class(self.cand_classes[cid][0])
            if not is_obfuscated_name(name):
                w = 0
                hit = []
                for t in set(tokens(name)):
                    tw = AD_TOKENS.get(t, 0)
                    if tw:
                        w += tw
                        hit.append(t)
                if w:
                    scores[mid] += min(w, 10)
                    why[mid].append(f"name tokens {sorted(set(hit))}")
                for nrx, rrx, label, strat in _SHAPE_RES:
                    if nrx.search(name) and rrx.search(ret):
                        scores[mid] += 18  # a patchable decision point beats a noisy event handler
                        why[mid].append(f"shape: {label}")
                        strategy.setdefault(mid, strat)
                        break
                else:
                    # the ad noun can sit on the CLASS instead of the method (e.g. Insertion.getPoints())
                    if _SCHED_METHOD.match(name) and _SCHED_RET.match(ret) and _SCHED_CLASS.search(cname):
                        scores[mid] += 18
                        why[mid].append(f"shape: ad schedule accessor ({cname}.{name})")
                        strategy.setdefault(mid, "Returns the ad schedule (a list/array the player places breaks from).")
            if not is_obfuscated_name(cname):
                cw = sum(AD_TOKENS.get(t, 0) for t in set(tokens(cname)))
                if cw:
                    scores[mid] += min(cw, 8) / 2
                if cw >= 5 and re.match(r"^get\w*(Host|Url|Endpoint|Provider|Config|Configuration)$", name) and \
                        ret.startswith("L") and mid not in strategy:
                    scores[mid] += 16
                    why[mid].append(f"shape: ad/SSAI config getter in {cname}")
                    strategy[mid] = "Returns the endpoint/config the ad service reads; callers may assume it is non-null."
            if is_obfuscated_name(name) and not name.startswith("<") and ret == "V" and insns >= 20:
                for crx, clabel, cstrat in _CLASS_RES:
                    if crx.search(cname):
                        scores[mid] += 22 + min(insns, 200) / 20
                        why[mid].append(f"obfuscated method in {clabel} {cname}")
                        strategy.setdefault(mid, cstrat)
                        break
            sig = params + ret
            if AD_TYPE_RE.search(sig):
                scores[mid] += 4
                why[mid].append("ad SDK type in signature")
        if not meth:
            return []
        # strings
        per_m_str = defaultdict(dict)
        for m, s in db.execute("SELECT m, s FROM m_str"):
            if m in meth and s in self.ad_strings:
                for w, label in self.ad_strings[s]:
                    per_m_str[m][label] = max(per_m_str[m].get(label, 0), w)
        for m, labels in per_m_str.items():
            scores[m] += min(sum(labels.values()), 10)
            why[m].append("strings: " + ", ".join(sorted(labels)))
        # calls
        per_m_seam = defaultdict(set)
        per_m_adref = defaultdict(int)
        for m, r in db.execute("SELECT m, r FROM m_call"):
            if m not in meth:
                continue
            if r in self.seam_refs:
                for s in self.seam_refs[r]:
                    per_m_seam[m].add(s["id"])
            if r in self.adish_refs:
                per_m_adref[m] += self.adish_refs[r]
        seam_by_id = {s["id"]: s for s in SEAMS}
        for m, ids in per_m_seam.items():
            ad_seams = [i for i in ids if seam_by_id[i]["engine"] not in ("loader", "native", "network", "analytics")
                        and not seam_by_id[i].get("broad")]
            broad = [i for i in ids if seam_by_id[i].get("broad")]
            other = [i for i in ids if i not in ad_seams and i not in broad]
            # broad = "touches this vendor at all" (can be 1000+ sites): presence, not a seam
            scores[m] += min(9 * len(ad_seams), 18) + 2 * len(other) + (2 if broad else 0)
            seams_hit[m] |= ids
            why[m].append("calls seam API: " + ", ".join(sorted(ids)))
            if ad_seams:
                strategy.setdefault(m, seam_by_id[sorted(ad_seams)[0]]["strategy"])
        for m, w in per_m_adref.items():
            scores[m] += min(w, 5)
            why[m].append("calls ad-named methods")
        for imp in self.implementers():
            for c in imp["classes"]:
                for mm in c["methods"]:
                    if mm["id"] in meth:
                        cid = meth[mm["id"]][0]
                        cls_name, vendor = self.cand_classes[cid][0], self.cand_classes[cid][1]
                        stack = vendor in VENDOR_SDKS or re.search(r"(?i)player|avia|ads?[A-Z/]|video|stream|media",
                                                                     cls_name) is not None
                        scores[mm["id"]] += 8 + (8 if stack and not is_obfuscated_name(simple_class(cls_name)) else 0)
                        why[mm["id"]].append(f"overrides {imp['label']}")
                        strategy.setdefault(mm["id"], imp["strategy"])
        # Google Mobile Ads (display/interstitial) is never the TV video-ad seam, and R8 often renames its
        # packages so the SDK table misses it (e.g. a renamed mediation Adapter and its Binder stub
        # stubs). Recognise it by SHAPE and push it down instead.
        by_cls = defaultdict(list)
        for m, (cid, nm, ps, rt, _f, _n) in meth.items():
            if m in scores:
                by_cls[cid].append(m)
        gma_cls = set()
        for cid in by_cls:
            names = {r[0] for r in db.execute("SELECT name FROM methods WHERE class=?", (cid,))}
            if len(names & ADMOB_API) >= 3:
                gma_cls.add(cid)
        # ...and by the SDK's own config strings ("gads:*" flags, its ad-server hosts)
        for (cid,) in db.execute(
                "SELECT DISTINCT m.class FROM m_str x JOIN strings s ON s.id=x.s JOIN methods m ON m.id=x.m "
                "WHERE s.value LIKE 'gads:%' OR s.value LIKE '%googleads.g.doubleclick.net%' "
                "OR s.value LIKE '%googlesyndication.com%' OR s.value LIKE 'Google Mobile Ads%'"):
            if cid in by_cls:
                gma_cls.add(cid)
        # package-mates of recognised GMA classes share the renamed SDK package (n9/*, u8/* ...)
        gma_pkgs = {self.cand_classes[c][0].rsplit("/", 1)[0] for c in gma_cls if c in self.cand_classes}
        for cid in by_cls:
            name = self.cand_classes[cid][0]
            if is_obfuscated_name(simple_class(name)) and name.rsplit("/", 1)[0] in gma_pkgs:
                gma_cls.add(cid)
        for m in list(scores):
            if m not in meth:
                continue
            cid, nm, ps, rt, _f, _n = meth[m]
            binder = rt == "Z" and ps in ("ILandroid/os/Parcel;Landroid/os/Parcel;I", "ILandroid/os/Parcel;Landroid/os/Parcel;") \
                and is_obfuscated_name(nm)
            if cid in gma_cls or GMA_TYPE_RE.search(ps + rt) or binder:
                scores[m] *= 0.25
                why[m].append("Binder stub (onTransact) — IPC plumbing, not a seam" if binder else
                              "Google Mobile Ads (display ads) internals, R8-renamed — not the video-ad path")
        ranked = sorted((m for m in scores if scores[m] >= 5), key=lambda m: -scores[m])
        # interface fan-out: the same callback implemented by many classes (Sky addons' onAdBreakStarted)
        # is ONE lead — keep the best, fold the rest into a count
        groups = defaultdict(list)
        for m in ranked:
            _cid, nm, ps, rt, _f, _n = meth[m]
            if not is_obfuscated_name(nm):
                groups[(nm, ps, rt)].append(m)
        folded = {}
        for key, ms in groups.items():
            if len(ms) >= 3:
                for m in ms[1:]:
                    folded[m] = ms[0]
        fan = {ms[0]: len(ms) for ms in groups.values() if len(ms) >= 3}
        # a bank of UI toggles on ONE class (e.g. showAdCounterText/showAdDonutTimer/...(Z)V)
        # is one lead too: the view, not six seams
        banks = defaultdict(list)
        for m in ranked:
            cid, nm, ps, rt, _f, _n = meth[m]
            if m not in folded and re.match(r"^(show|hide|set|update|toggle)[A-Z]", nm):
                banks[(cid, ps, rt)].append(m)
        bank = {}
        for ms in banks.values():
            if len(ms) >= 3:
                for m in ms[1:]:
                    folded[m] = ms[0]
                bank[ms[0]] = len(ms)
        ranked = [m for m in ranked if m not in folded]
        out = []
        for m in ranked[: limit * 3]:
            cid, name, params, ret, flags, insns = meth[m]
            cls, sdk, source = self.cand_classes[cid]
            strat = strategy.get(m) or self._default_strategy(ret, name)
            if "ima-cuepoints" in seams_hit[m]:
                strat = seam_by_id["ima-cuepoints"]["strategy"]
            if m in fan:
                why[m].append(f"fan-out: {fan[m]} classes implement {name}() — one lead; hook the dispatcher/producer")
            if m in bank:
                why[m].append(f"UI bank: {bank[m]} same-shape toggles on this class — one lead; hook what drives them")
            for rx, warn in _GATED_RES:
                if rx.search(name):
                    strat = "⚠ " + warn
                    break
            out.append({
                "id": m, "score": round(scores[m], 1),
                "sig": f"{cls}->{name}({params}){ret}", "class": cls, "name": name,
                "params": params, "ret": ret, "flags": flags, "insns": insns, "source": source,
                "vendor": sdk, "why": why[m], "seams": sorted(seams_hit[m]),
                "strategy": strat,
            })
        # Tiers: what you'd actually HOOK comes first (the recall@10 audit: shipped seams ranked
        # 13-93 behind noisy listener callbacks). 0 = decision point / accessor / config getter /
        # ad-UI render method; 1 = other leads; 2 = callbacks we warn against or fan-out observers.
        for c in out:
            w = " ".join(c["why"])
            if c["strategy"].startswith("⚠") or "fan-out:" in w:
                c["tier"] = 2
            elif "shape:" in w or "obfuscated method in" in w:
                c["tier"] = 0
            else:
                c["tier"] = 1
        out.sort(key=lambda c: (c["tier"], -c["score"]))
        return out[:limit]

    @staticmethod
    def _default_strategy(ret: str, name: str) -> str:
        if ret == "Z":
            return "Flip the boolean (returnEarly false/true) — confirm which value disables ads by reading callers."
        if ret in ("Ljava/util/List;", "Ljava/util/Collection;") or ret.startswith("["):
            return "Return an empty list/array so no breaks are scheduled."
        if ret == "V":
            return "A void side-effect method; check whether the content flow depends on it (it can hang if it does)."
        return "Read the smali to see what ad object it returns and where that object is consumed."

    # ------------------------------------------------------------ integration points
    def integration_points(self, per_seam=12):
        db = self.db
        rows = defaultdict(list)
        counts = defaultdict(int)
        rid_to_seams = self.seam_refs
        if not rid_to_seams:
            return []
        q = ("SELECT x.r, m.id, c.name, m.name, m.params, m.ret, c.is_app, c.sdk FROM m_call x "
             "JOIN methods m ON m.id=x.m JOIN classes c ON c.id=m.class WHERE x.r IN (%s)" %
             ",".join(str(r) for r in rid_to_seams))
        refname = {r: n for r, n in db.execute(
            "SELECT id, ref FROM refs WHERE id IN (%s)" % ",".join(str(r) for r in rid_to_seams))}
        for r, mid, cls, name, params, ret, is_app, sdk in db.execute(q):
            if not (is_app or sdk in VENDOR_SDKS):
                continue
            for s in rid_to_seams[r]:
                counts[s["id"]] += 1
                if len(rows[s["id"]]) < per_seam:
                    rows[s["id"]].append({"id": mid, "sig": f"{cls}->{name}({params}){ret}", "calls": refname[r]})
        out = []
        for s in SEAMS:
            if s["id"] in rows:
                out.append({**{k: s[k] for k in ("id", "engine", "what", "strategy", "risk")},
                            "count": counts[s["id"]], "sites": rows[s["id"]]})
        return out

    # ------------------------------------------------------------ implementers
    def implementers(self, per_type=12):
        """App/vendor classes extending/implementing ad-flow SDK types, with the override methods."""
        if getattr(self, "_impl", None) is not None:
            return self._impl
        out = self._impl = []
        for typ, hooks, label, strat in IMPLEMENTS:
            subs = self.idx.subclasses(typ)
            rows = []
            for cn in subs:
                c = self.idx.class_row(cn)
                if not c or not (c["is_app"] or c["sdk"] in VENDOR_SDKS):
                    continue
                ms = self.idx.q(self.idx.METHOD_SQL + "WHERE c.id=?", c["id"])
                hits = [m for m in ms if m["name"] in hooks and m["code_off"]]
                rows.append({"class": cn, "source": c["source"],
                             "methods": [{"id": m["id"], "sig": self.idx.sig(m), "insns": m["insns"]} for m in hits]})
            if rows:
                out.append({"type": typ, "label": label, "strategy": strat, "count": len(rows), "classes": rows[:per_type]})
        return out

    # ------------------------------------------------------------ data flow
    def dataflow(self, mid, limit=6):
        """Fields this method writes (and who reads them) / reads (and who writes them)."""
        acc = {}
        for fref, w in self.idx.field_access(mid):
            if fref.startswith(("Ljava/", "Landroid/", "Lkotlin/")):
                continue
            owner = fref.split("->")[0]
            me = self.idx.method(mid)["cls"]
            if owner != me and is_obfuscated_name(simple_class(owner).split("$")[-1]):
                continue  # R8-renamed helper fields carry no meaning for a reader
            acc.setdefault(fref, set()).add("writes" if w else "reads")
        out = []
        for fref, kinds in acc.items():
            readers = [self.idx.sig(r) for r in self.idx.field_users(fref, write=False, limit=limit, exact=True) if r["id"] != mid]
            writers = [self.idx.sig(r) for r in self.idx.field_users(fref, write=True, limit=limit, exact=True) if r["id"] != mid]
            out.append({"field": fref, "access": "+".join(sorted(kinds)), "other_readers": readers, "other_writers": writers})
        return out[:12]

    # ------------------------------------------------------------ call chains
    def callers_of_method(self, mid, limit=8):
        r = self.idx.method(mid)
        if not r:
            return []
        ref = self.idx.sig(r)
        rows = self.idx.callers(ref, limit=limit, exact=True)
        return [{"id": x["id"], "sig": self.idx.sig(x)} for x in rows]

    def chain(self, mid, depth=3):
        """Upward call chain(s) from a method, app/vendor code only, breadth-limited."""
        out = []
        frontier = [(mid, [])]
        seen = {mid}
        for _ in range(depth):
            nxt = []
            for m, path in frontier:
                for c in self.callers_of_method(m, limit=4):
                    if c["id"] in seen:
                        continue
                    seen.add(c["id"])
                    nxt.append((c["id"], path + [c["sig"]]))
            if not nxt:
                break
            frontier = nxt[:6]
        for m, path in frontier:
            if path:
                out.append(path)
        return out

    # ------------------------------------------------------------ fingerprints
    def fingerprint(self, mid) -> dict:
        """Smallest set of STABLE anchors that still matches exactly one method.

        Hardening rules for stable matchers:
        leaf class-name suffix instead of full package; method name only when readable;
        ONE distinctive string, not two; never pin R8-renamed types (they change every build);
        accessFlags loose. Anchor sets are tried from most to least robust and the first unique
        one wins; its match count is measured against the whole index.
        """
        idx = self.idx
        r = idx.method(mid)
        cls, name, params, ret = r["cls"], r["name"], r["params"], r["ret"]
        plist = split_params(params)
        leaf = simple_class(cls)
        obf_cls = is_obfuscated_name(leaf.split("$")[0]) or is_obfuscated_name(leaf.split("$")[-1])
        obf_name = is_obfuscated_name(name)

        def stable_type(t):
            base = t.lstrip("[")
            if not base.startswith("L"):
                return True
            if base.startswith(("Ljava/", "Landroid/", "Lkotlin/", "Landroidx/", "Lokhttp3/", "Lcom/google/")):
                return True
            return not is_obfuscated_name(simple_class(base).split("$")[-1])

        ret_ok = stable_type(ret)
        params_ok = all(stable_type(t) for t in plist)
        strs = [s for s in idx.strings_of(mid) if 4 <= len(s) <= 120]
        ranked_strs = sorted(((idx.string_count(s), s) for s in strs), key=lambda x: (x[0], -len(x[1])))
        best_str = next((s for c, s in ranked_strs if c <= 3), None)
        calls = [c for c in idx.calls_of(mid) if not c.startswith(("Ljava/", "Lkotlin/", "Landroid/util/"))]
        stable_calls = sorted(((idx.ref_count(c), c) for c in calls
                               if not is_obfuscated_name(simple_class(c.split("->")[0]).split("$")[-1])
                               and not is_obfuscated_name(c.split("->")[1].split("(")[0])
                               and c.split("->")[0] != cls), key=lambda x: x[0])
        best_call = stable_calls[0][1] if stable_calls and stable_calls[0][0] <= 5 else None

        # --- candidate id sets per anchor
        def ids(sql, *a):
            return {x[0] for x in idx.q(sql, *a)}
        A = {}
        A["ret"] = ids("SELECT id FROM methods WHERE ret=? AND code_off!=0", ret) if ret_ok else None
        if not obf_name:
            A["name"] = ids("SELECT id FROM methods WHERE name=?", name)
        if not obf_cls:
            A["class"] = ids("SELECT m.id FROM methods m JOIN classes c ON c.id=m.class WHERE c.name LIKE ? ESCAPE '\\'",
                             "%/" + esc_like(leaf) + ";")
        if best_str:
            A["string"] = ids("SELECT x.m FROM m_str x JOIN strings s ON s.id=x.s WHERE s.value=?", best_str)
        if best_call:
            A["call"] = ids("SELECT x.m FROM m_call x JOIN refs r ON r.id=x.r WHERE r.ref=?", best_call)
        if params_ok:
            A["params"] = ids("SELECT id FROM methods WHERE params=?", params)
        sdk_call = False
        if best_call:
            crow = idx.class_row(best_call.split("->")[0])
            sdk_call = crow is None or not crow["is_app"]  # SDK/framework API: survives app-side obfuscation
        order = [("name", "class"), ("string", "class"), ("call", "class")]
        if sdk_call:
            order.append(("call",))
        order += [("string",), ("name", "string"),
                 ("name", "call"), ("call", "string"), ("params", "class"), ("params", "name"),
                 ("params", "string"), ("params", "call"), ("string", "call", "class"), ("params", "call", "class")]
        chosen, matches = None, None
        for combo in order:
            if not all(A.get(k) is not None for k in combo):
                continue
            m = set(A["ret"]) if A["ret"] is not None else None
            for k in combo:
                m = A[k] if m is None else m & A[k]
            if mid in m and len(m) == 1:
                chosen, matches = combo, 1
                break
        if chosen is None:  # nothing unique: use everything stable we have
            chosen = tuple(k for k in ("name", "class", "string", "call", "params") if A.get(k) is not None)
            m = set(A["ret"]) if A["ret"] is not None else None
            for k in chosen:
                m = A[k] if m is None else m & A[k]
            matches = len(m) if m is not None else -1

        # A framework-agnostic, structured matcher descriptor (translate to your own tooling).
        anchors = {}
        if "name" in chosen:
            anchors["methodName"] = name
        if "class" in chosen:
            anchors["classSuffix"] = f"/{leaf};"
        if "string" in chosen:
            anchors["string"] = best_str
        if "call" in chosen:
            anchors["callContains"] = best_call.split("(")[0] + "("
        descriptor = {
            "returnType": ret if ret_ok else None,
            "parameters": plist if "params" in chosen else None,
            "anchors": anchors,
            "matches": matches,
            "unique": matches == 1,
            "confidence": "high" if matches == 1 else "low",
        }
        notes = [f"Anchors: {' + '.join(('returnType',) * ret_ok + chosen)} — smallest set that was unique in this build."]
        if not params_ok:
            notes.append("Parameters not pinned: they contain R8-renamed types that change every build.")
        if obf_cls or obf_name:
            notes.append("Class/method names are R8-renamed: anchored on strings / stable API refs instead.")
        if matches != 1:
            notes.append("NOT unique on stable anchors — add a class-level condition (e.g. the class also "
                         "declares a method returning a known SDK type).")
        src = r["source"]
        if src and src not in ("SourceFile", "r8-map-id") and not src.startswith("R8$$"):
            notes.append(f'.source "{src}" survives R8 — use it to re-find this class after a rename (rescan-reference trick).')
        return {"descriptor": descriptor, "matches": matches, "unique": matches == 1, "anchors": list(chosen),
                "anchor_strings": [best_str] if "string" in chosen else [], "anchor_call": best_call if "call" in chosen else None,
                "notes": notes}

    # ------------------------------------------------------------ boolean polarity
    _INV = re.compile(r"invoke-[\w/-]+ \{[^}]*\}, (L[^;]+;)->([\w$<>-]+)\(")

    def _adish_invokes(self, lines):
        hits = []
        for ln in lines:
            m = self._INV.search(ln)
            if not m:
                continue
            cls, name = m.group(1), m.group(2)
            w = sum(AD_TOKENS.get(t, 0) for t in set(tokens(name)))
            w += sum(AD_TOKENS.get(t, 0) for t in set(tokens(simple_class(cls)))) / 2
            if w >= 3:
                hits.append(f"{simple_class(cls)}.{name}")
        return hits

    def polarity(self, mid, depth=0):
        """Which return value of a Z method leads callers into ad code?

        For each call site: find `move-result vN` + `if-eqz/if-nez vN, :L`, then count ad-named invokes
        on the true path vs the false path (first ~30 instructions of each). Synthetic accessors are
        followed to their callers. Returns {'neutral': '0x0'|'0x1'|None, 'evidence': [...]}.
        """
        r = self.idx.method(mid)
        if not r or r["ret"] != "Z":
            return {"neutral": None, "evidence": []}
        target = self.idx.sig(r)
        votes_true_is_ad = 0
        votes_false_is_ad = 0
        ev = []
        for c in self.idx.callers(target, limit=12, exact=True):
            text = self.idx.smali(c)
            lines = text.splitlines()
            body = [ln.strip() for ln in lines]
            # synthetic accessor: tiny static method that just forwards the call
            if c["insns"] <= 6 and depth < 2 and (is_obfuscated_name(c["name"]) or "access$" in c["name"]) \
                    and sum(1 for ln in body if ln.startswith("invoke-")) == 1:
                sub_p = self.polarity(c["id"], depth + 1)
                if sub_p["neutral"] == "0x0":
                    votes_true_is_ad += 1
                elif sub_p["neutral"] == "0x1":
                    votes_false_is_ad += 1
                ev += [f"via accessor {c['name']}: " + e for e in sub_p["evidence"][:2]]
                continue
            labels = {ln: i for i, ln in enumerate(body) if ln.startswith(":")}
            for i, ln in enumerate(body):
                if target not in ln or not ln.startswith("invoke-"):
                    continue
                j = i + 1
                if j >= len(body) or not body[j].startswith("move-result "):
                    continue
                reg = body[j].split()[1]
                k = j + 1
                while k < len(body) and not body[k] and k < j + 3:
                    k += 1
                m = re.match(r"if-(eqz|nez) (\S+), (:\S+)", body[k]) if k < len(body) else None
                if not m or m.group(2) != reg:
                    continue
                fall = body[k + 1:k + 31]
                li = labels.get(m.group(3))
                jump = body[li + 1:li + 31] if li is not None else []
                true_path, false_path = (fall, jump) if m.group(1) == "eqz" else (jump, fall)
                ta, fa = self._adish_invokes(true_path), self._adish_invokes(false_path)
                if len(ta) > len(fa):
                    votes_true_is_ad += 1
                    ev.append(f"{simple_class(c['cls'])}.{c['name']}: TRUE path calls {', '.join(sorted(set(ta))[:3])}")
                elif len(fa) > len(ta):
                    votes_false_is_ad += 1
                    ev.append(f"{simple_class(c['cls'])}.{c['name']}: FALSE path calls {', '.join(sorted(set(fa))[:3])}")
        neutral = None
        if votes_true_is_ad > votes_false_is_ad:
            neutral = "0x0"
        elif votes_false_is_ad > votes_true_is_ad:
            neutral = "0x1"
        t, f = votes_true_is_ad, votes_false_is_ad
        conf = None if neutral is None else ("unanimous" if min(t, f) == 0 else f"majority {max(t, f)}:{min(t, f)} — read the minority call site")
        return {"neutral": neutral, "evidence": ev[:6], "votes": [t, f], "confidence": conf}

    # ------------------------------------------------------------ deobfuscation hints
    def deobf_hints(self, class_names: list[str]) -> dict[str, list[str]]:
        """Original names recovered from .source, data-class toString() and Kotlin intrinsics."""
        hints: dict[str, list[str]] = {}
        for cn in class_names:
            h = []
            row = self.idx.class_row(cn)
            if row and row["source"] and row["source"] not in ("SourceFile", "r8-map-id") and \
                    not row["source"].startswith("R8$$"):
                h.append(f"source file {row['source']}")
            for (val,) in self.idx.q(
                    "SELECT DISTINCT s.value FROM methods m JOIN classes c ON c.id=m.class JOIN m_str x ON x.m=m.id "
                    "JOIN strings s ON s.id=x.s WHERE c.name=? AND m.name='toString' LIMIT 3", cn):
                mm = re.match(r"^([A-Z][\w$]*)\((\w+)=", val)
                if mm:
                    h.append(f"toString → {mm.group(1)}(…{mm.group(2)}=…)")
                    break
            if h:
                hints[cn] = h
        return hints

    # ------------------------------------------------------------ hot classes
    def hot_classes(self, candidates, limit=20):
        agg = defaultdict(lambda: {"score": 0.0, "methods": 0})
        for c in candidates:
            a = agg[c["class"]]
            a["score"] += c["score"]
            a["methods"] += 1
            a["source"] = c["source"]
            a["vendor"] = c["vendor"]
        ranked = sorted(agg.items(), key=lambda kv: -kv[1]["score"])[:limit]
        return [{"class": k, **v} for k, v in ranked]
