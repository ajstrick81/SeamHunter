"""The autopsy pipeline: bundle -> manifest -> code index -> native -> assets -> SDKs ->
protections -> hosts -> seams -> known-app drift -> findings dict (report.json)."""
from __future__ import annotations

import json
import os
import re
import time
from collections import Counter, defaultdict

from . import __version__, index as indexmod
from .container import DEX_MAGIC, open_bundle
from .drift import app_for_package, check as drift_check
from .elf import ElfInfo, strings as elf_strings
from .kb.markers import (AD_HOSTS, AD_TOKENS, tokens, AD_STRING_RES, AD_STRING_ANY, HOST_RE, JS_AD_ANCHORS,
                         NATIVE_ENGINES, NATIVE_SEAM_IMPORTS, PACKER_FILES, PROTECTIONS, URL_RE)
from .kb.sdks import PREFIXES, STRING_MARKERS
from .resources import ResourceTable, parse_axml, walk
from .seams import SeamHunter

TEXT_EXT = {".js", ".json", ".html", ".htm", ".xml", ".txt", ".m3u8", ".mpd", ".properties", ".bundle",
            ".conf", ".cfg", ".yaml", ".yml", ".css", ".vtt", ".csv", ".ini", ".mjs", ".jsbundle"}
HERMES_MAGIC = bytes.fromhex("c61fbc03c103191f")
MAX_TEXT_SCAN = 40 * 1024 * 1024


def _regexp(pattern, value):
    if value is None:
        return False
    try:
        return re.search(pattern, value) is not None
    except re.error:
        return False


def host_category(host: str):
    host = host.lower()
    for suffix, (cat, note) in AD_HOSTS.items():
        if host == suffix or host.endswith("." + suffix) or (suffix.endswith(".") and suffix in host) or \
                (("." not in suffix) and suffix in host):
            return cat, note
    return None, None


def split_params_(params):
    from .seams import split_params
    return split_params(params) if params else []


def java_method_excerpt(src: str, name: str, nparams: int, max_lines=60) -> str | None:
    """Pull one method out of jadx output by name (+ arity when overloaded)."""
    if name in ("<init>", "<clinit>"):
        return None
    lines = src.splitlines()
    starts = [i for i, ln in enumerate(lines)
              if re.search(r"\b%s\s*\(" % re.escape(name), ln) and not ln.strip().startswith(("//", "*", "return", "this."))
              and re.search(r"(public|private|protected|static|final|void|\w>?)\s+%s\s*\(" % re.escape(name), ln)]
    if not starts:
        return None
    if len(starts) > 1:
        for i in starts:
            sig = lines[i][lines[i].index("(") + 1:lines[i].rfind(")")]
            if (sig.count(",") + 1 if sig.strip() else 0) == nparams:
                starts = [i]
                break
    i = starts[0]
    depth, out = 0, []
    for ln in lines[i:]:
        out.append(ln)
        depth += ln.count("{") - ln.count("}")
        if depth <= 0 and "{" in "".join(out):
            break
        if ln.rstrip().endswith(";") and "{" not in "".join(out):
            break
        if len(out) >= max_lines:
            out.append("        // ...")
            break
    ind = min((len(x) - len(x.lstrip()) for x in out if x.strip()), default=0)
    return "\n".join(x[ind:] for x in out)


def _wordlike(name: str) -> bool:
    """A dictionary-ish identifier: long enough, has a vowel, and some character variety.
    DexGuard/R8 generated names ('a', 'glgg', 'zzb') fail this even when they are not short."""
    return len(name) >= 4 and re.search(r"[aeiouAEIOU]", name) is not None and len(set(name.lower())) >= 3


def obfuscation_profile(app_names, markers) -> dict:
    """Multi-signal name-obfuscation read.

    The old metric only counted class names of <=2 chars, so DexGuard (which generates LONG synthetic
    names) scored as lightly obfuscated. This combines short-name ratio, a dictionary-word ratio, and
    package-relocation concentration (a short synthetic root such as `Lo/` holding most app classes) so
    heavy renaming is caught regardless of name length. Compiler and renaming are reported separately.
    """
    n = len(app_names)
    if not n:
        return {"short_app_class_ratio": 0, "verdict": "unknown", "meaningful_name_ratio": 0,
                "name_obfuscation": "unknown", "package_relocation": "unknown", "synthetic_root_ratio": 0,
                "compiler": sorted({re.sub(r"\{.*", "", m) for m in markers})[:4]}
    simple = [x.rstrip(";").rsplit("/", 1)[-1].split("$")[0] for x in app_names]
    short = sum(1 for s in simple if len(s) <= 2)
    meaningful = sum(1 for s in simple if _wordlike(s))
    roots = Counter(x[1:].split("/")[0] for x in app_names if x.startswith("L"))
    top_root, top_n = roots.most_common(1)[0] if roots else ("", 0)
    synth_ratio = (top_n / n) if (top_root and len(top_root) <= 2) else 0.0
    short_ratio = short / n
    meaningful_ratio = meaningful / n
    # Synthetic-root concentration is the strongest signal; the dictionary-word ratio is subordinate
    # (DexGuard's long generated names often still contain vowels, so meaningful_ratio alone is weak).
    heavy = short_ratio > 0.5 or synth_ratio > 0.5 or meaningful_ratio < 0.30
    partial = short_ratio > 0.15 or synth_ratio > 0.25 or meaningful_ratio < 0.60
    name_obf = "heavy" if heavy else "partial" if partial else "none"
    verdict = ("heavy (renamed; non-dictionary identifiers)" if heavy else
               "partial" if partial else "light/none")
    low_conf = n < 50  # ratio thresholds are noise on tiny apps (config splits, stubs)
    return {
        "short_app_class_ratio": round(short_ratio, 3),
        "meaningful_name_ratio": round(meaningful_ratio, 3),
        "synthetic_root_ratio": round(synth_ratio, 3),
        "synthetic_root": (f"L{top_root}/ ({top_n}/{n} app classes)" if synth_ratio > 0.25 else None),
        "name_obfuscation": name_obf,
        "package_relocation": ("extensive" if synth_ratio > 0.5 else "some" if synth_ratio > 0.25 else "none"),
        "compiler": sorted({re.sub(r"\{.*", "", m) for m in markers})[:4],
        "app_class_count": n,
        "low_confidence": low_conf,
        "verdict": verdict + (" — low confidence (few app classes)" if low_conf else ""),
    }


# Generic terms that are evidence only with a strong ad artifact NEARBY (same/adjacent string record).
# Highcharts ships `quartile`/`trackByArea`, libcronet ships `stitched`/`beacon`/prose; alone they are
# not ad components. Plain `interstitial` is UI/navigation unless a specific ad form sits beside it.
WEAK_AD_LABELS = {"ad tracking", "beacon", "stitcher", "interstitial"}
# Vendor/host tokens establish "a vendor endpoint is referenced" but do NOT, on their own, make a lib an
# ad component, and must NOT corroborate weak terms across a multi-MB library (libcronet `.doubleclick.net`).
VENDOR_AD_LABELS = {"ad vendor"}
CORROBORATION_WINDOW = 2  # a weak hit counts only if a strong hit is within +/- this many string records
# The patterns that count as a strong (corroborating) ad artifact.
AD_STRONG_RES = [(rx, w, label) for rx, w, label in AD_STRING_RES
                 if w >= 3 and label not in WEAK_AD_LABELS and label not in VENDOR_AD_LABELS]


def _bucket_add(bucket, label, line, cap):
    if line not in bucket[label] and len(bucket[label]) < cap:
        bucket[label].append(line)


def classify_native_ad_strings(strs, max_per_label=5, window=CORROBORATION_WINDOW):
    """Classify ad-like strings in one native library, record by record.

    Strong protocol/API artifacts (strict VAST, VMAP, SCTE-35/cue tags, ad-break keys, DAI, roll
    positions, ad tags, known proprietary APIs, specific ad-interstitial) are evidence on their own.
    Generic terms (impression/quartile/tracking, beacon, stitcher, bare interstitial) count ONLY when a
    strong artifact occurs in the SAME or an ADJACENT string record (within `window`); otherwise they are
    charting/telemetry/documentation text, reported under `weak` with a `false_positive_reason` and never
    scored. Vendor/host tokens are tracked separately (`vendor`) and neither score nor corroborate.
    Returns (confirmed, weak, vendor, false_positive_reason, score). A library can't be ranked on raw
    match count or on a lone vendor hostname.
    """
    records = list(strs)
    # Prefilter to the records that contain any ad-ish token (keeps big libs cheap).
    cand = [i for i, s in enumerate(records) if AD_STRING_ANY.search(s)]
    candset = set(cand)

    def _is_strong(s):
        return any(rx.search(s) for rx, w, label in AD_STRONG_RES)

    strong_at = {i for i in cand if _is_strong(records[i])}

    def _corroborated(i):
        for j in range(i - window, i + window + 1):
            if j in strong_at and j in candset:
                return True
        return False

    confirmed, weak, vendor = defaultdict(list), defaultdict(list), defaultdict(list)
    for i in cand:
        s = records[i]
        line = s[:160]
        for rx, w, label in AD_STRING_RES:
            if w < 3 or not rx.search(s):
                continue
            if label in VENDOR_AD_LABELS:
                _bucket_add(vendor, label, line, max_per_label)
            elif label in WEAK_AD_LABELS:
                if len(line) > 120 and " " not in line:
                    continue  # long, space-free: a minified blob, not an ad string
                _bucket_add(confirmed if _corroborated(i) else weak, label, line, max_per_label)
            else:
                _bucket_add(confirmed, label, line, max_per_label)
    confirmed, weak, vendor = dict(confirmed), dict(weak), dict(vendor)
    fp_reason = None
    if weak:
        fp_reason = ("generic ad term(s) [%s] with no corroborating ad artifact (VAST/SCTE-35/cue/"
                     "ad-break/DAI) within %d string record(s) — likely charting, telemetry, networking "
                     "or documentation text" % (", ".join(sorted(weak)), window))
    score = sum(len(v) for v in confirmed.values())  # vendor presence excluded on purpose
    return confirmed, weak, vendor, fp_reason, score


class Autopsy:
    def __init__(self, path: str, out_dir: str, log=print, deep_native=True, java=True, apktool=False):
        self.java = java
        self.apktool = apktool
        self.path = path
        self.out = out_dir
        self.log = log
        self.deep_native = deep_native
        self.f: dict = {"tool": f"apk-autopsy {__version__}", "input": os.path.basename(path)}  # no user paths in reports

    # ------------------------------------------------------------ run
    # every stage writes its section; if one fails the scan continues with these empty defaults
    DEFAULTS = {
        "manifest": {"package": None, "versionName": None, "versionCode": None, "minSdk": None, "targetSdk": None,
                     "application": {}, "tv": False, "features": [], "permissions": [], "ad_permissions": [],
                     "components": {}, "launchers": [], "exported": [], "ad_components": [], "meta_data": {},
                     "split_required": None},
        "assets": {"total_files": 0, "by_type": {}, "notable": [], "ad_anchors": [], "compressed_libs": [], "hidden_dex": []},
        "code": {"dex_files": [], "classes": 0, "app_classes": 0, "methods": 0, "instructions": 0,
                 "obfuscation": {"short_app_class_ratio": 0, "verdict": "unknown"}, "compiler_markers": [],
                 "kotlin": False, "top_app_packages": [], "native_methods": [], "loadlibrary_names": []},
        "native": {"libs": [], "jni_map": []},
        "sdks": [], "engine_guess": [], "protections": [], "hosts": [],
        "seams": {"integration_points": [], "implementers": [], "candidates": [], "hot_classes": [],
                  "deobfuscation_hints": {}},
        "seams_ad_resources": [], "known_app": None, "plan": [],
    }

    def _stage(self, name, fn, *args):
        try:
            return fn(*args)
        except Exception as e:  # noqa: BLE001 - record, keep going, report what's missing
            import traceback
            self.f.setdefault("errors", []).append({"stage": name, "error": f"{type(e).__name__}: {str(e)[:200]}",
                                                    "where": traceback.format_exc().strip().splitlines()[-3][:200]})
            self.log(f"  ! stage '{name}' failed: {type(e).__name__}: {str(e)[:120]} (continuing)")
            return None

    def run(self) -> dict:
        t0 = time.time()
        os.makedirs(self.out, exist_ok=True)
        self.log(f"[1/9] opening {self.path}")
        self.bundle = open_bundle(self.path)          # unusable input: clean SystemExit message
        for k, v in self.DEFAULTS.items():
            self.f.setdefault(k, json.loads(json.dumps(v)))
        self.asset_urls = Counter()
        self.package = None
        self.res = None
        self._bundle_info()
        self.log("[2/9] manifest + resources")
        self._stage("manifest", self._manifest)
        self._stage("art", self._art)
        self.log("[3/9] scanning assets")
        hidden_dex = self._stage("assets", self._assets) or []
        self.log("[4/9] indexing DEX bytecode")
        indexmod.build(self.bundle, self.out, log=self.log, extra_dex=hidden_dex)
        self.idx = indexmod.Index(self.out)
        try:
            return self._run_indexed(t0)
        finally:
            # an open SQLite handle locks index.sqlite on Windows: rescans, rmtree and test cleanup fail
            self.idx.close()

    def _run_indexed(self, t0) -> dict:
        self.idx.db.create_function("REGEXP", 2, _regexp, deterministic=True)
        self._stage("code", self._code_stats)
        self.log("[5/9] native libraries")
        self._stage("native", self._native)
        self.log("[6/9] SDKs, protections, hosts")
        self._stage("sdks", self._sdks)
        self._stage("protections", self._protections)
        self._stage("hosts", self._hosts)
        self._stage("trackers", self._trackers)
        self.log("[7/9] hunting ad seams")
        self._stage("seams", self._seams)
        if self.java:
            self._stage("java", self._java)
        self.log("[8/9] known-app drift check")
        self._stage("drift", self._drift)
        if self.apktool:
            self._stage("apktool", self._apktool)
        self.f["elapsed_seconds"] = round(time.time() - t0, 1)
        from .drafts import render as render_drafts
        self.f["drafts"] = self._stage("drafts", render_drafts, self.f, self.out)
        self._stage("verdict", self._verdict)
        with open(os.path.join(self.out, "report.json"), "w", encoding="utf-8") as fh:
            json.dump(self.f, fh, indent=1, ensure_ascii=False, default=str)
        self.log("[9/9] findings written")
        return self.f

    # ------------------------------------------------------------ art (GUI cards)
    def _art(self):
        from .art import extract
        app = (self.f.get("manifest") or {}).get("application") or {}
        self.f["art"] = extract(self.bundle, self.res, app, self.out)
        # local-only pointer back to the input (reports themselves carry no absolute paths)
        with open(os.path.join(self.out, ".source"), "w", encoding="utf-8") as fh:
            fh.write(os.path.abspath(self.path))

    # ------------------------------------------------------------ bundle
    def _bundle_info(self):
        b = self.bundle
        self.f["bundle"] = {
            "kind": b.kind,
            "size": os.path.getsize(self.path),
            "splits": [{"name": s.name, "size": s.size, "entries": len(s.names())} for s in b.splits],
            "info": b.info,
            "warnings": b.warnings,
            "extra_files": b.extra_files[:50],
        }

    # ------------------------------------------------------------ manifest
    def _manifest(self):
        base = self.bundle.base
        man = parse_axml(base.read("AndroidManifest.xml"))
        if man.get("_error"):
            self.f.setdefault("warnings", []).append(
                f"AndroidManifest.xml is malformed ({man['_error']}) — protector trick or corrupt download; "
                f"manifest facts below are incomplete")
        self.manifest_tree = man
        try:
            self.res = ResourceTable(base.read("resources.arsc")) if "resources.arsc" in base.names() else None
        except Exception as e:  # noqa: BLE001 - resource tables vary a lot; never fatal
            self.res = None
            self.f.setdefault("warnings", []).append(f"resources.arsc unreadable: {e}")
        a = man["attrs"]
        app = next((c for c in man["children"] if c["tag"] == "application"), {"attrs": {}, "children": []})
        sdk = next((c for c in man["children"] if c["tag"] == "uses-sdk"), {"attrs": {}})
        perms = sorted({c["attrs"].get("name") for c in man["children"]
                        if c["tag"] in ("uses-permission", "uses-permission-sdk-23") and c["attrs"].get("name")})
        comps = []
        for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
            for c in app.get("children", []):
                if c["tag"] != kind:
                    continue
                ca = c["attrs"]
                cats = [n["attrs"].get("name") for n in walk(c, "category")]
                actions = [n["attrs"].get("name") for n in walk(c, "action")]
                comps.append({"kind": kind, "name": ca.get("name"), "exported": ca.get("exported"),
                              "leanback": "android.intent.category.LEANBACK_LAUNCHER" in cats,
                              "launcher": "android.intent.category.LAUNCHER" in cats,
                              "actions": actions[:6]})
        meta = {}
        for c in walk(app, "meta-data"):
            nm = c["attrs"].get("name")
            if nm:
                v = c["attrs"].get("value", c["attrs"].get("resource"))
                meta[nm] = v
        feats = [c["attrs"].get("name") for c in man["children"] if c["tag"] == "uses-feature"]
        pkg = a.get("package")
        self.package = pkg
        appattrs = {k: v for k, v in app.get("attrs", {}).items()
                    if k in ("name", "debuggable", "extractNativeLibs", "networkSecurityConfig", "usesCleartextTraffic",
                             "allowBackup", "appComponentFactory", "requiredSplitTypes", "splitTypes",
                             "largeHeap", "banner", "icon", "isGame")}
        ad_comps = [c for c in comps if c["name"] and
                    any(AD_TOKENS.get(t, 0) >= 3 for t in tokens(c["name"].rsplit(".", 1)[-1]))]
        info = self.bundle.info or {}
        self.f["manifest"] = {
            "package": pkg,
            "versionName": a.get("versionName") or info.get("versionname") or info.get("version_name"),
            "versionCode": a.get("versionCode") or info.get("versioncode") or info.get("version_code"),
            "minSdk": sdk["attrs"].get("minSdkVersion"), "targetSdk": sdk["attrs"].get("targetSdkVersion"),
            "application": appattrs,
            "tv": any(c["leanback"] for c in comps) or "android.software.leanback" in feats,
            "features": feats,
            "permissions": perms,
            "ad_permissions": [p for p in perms if re.search(r"AD_ID|ACCESS_ADSERVICES|advertising", p or "", re.I)],
            "components": {k: sum(1 for c in comps if c["kind"] == k) for k in ("activity", "service", "receiver", "provider")},
            "launchers": [c["name"] for c in comps if c["leanback"] or c["launcher"]],
            "exported": [c["name"] for c in comps if c["exported"] is True][:40],
            "ad_components": ad_comps[:30],
            "meta_data": {k: v for k, v in meta.items()
                          if re.search(r"(?i)ads?|ima|cast|google|firebase|split|vending|freewheel|amazon|appsflyer|"
                                       r"adjust|braze|facebook|onetrust|nielsen|conviva", k)},
            "split_required": meta.get("com.android.vending.splits.required"),
        }
        self._nsc(app)

    def _nsc(self, app):
        ref = app.get("attrs", {}).get("networkSecurityConfig")
        if not ref or not self.res:
            return
        path = self.res.file_for(ref)
        if not path:
            self.f["manifest"]["network_security_config"] = {"ref": ref, "note": "resource path not resolvable"}
            return
        for s in self.bundle.splits:
            if path in s.names():
                try:
                    tree = parse_axml(s.read(path))
                except Exception:  # noqa: BLE001
                    return
                certs = [c["attrs"].get("src") for c in walk(tree, "certificates")]
                pins = [c for c in walk(tree, "pin")]
                domains = [c for c in walk(tree, "domain")]
                cleartext = [c["attrs"].get("cleartextTrafficPermitted") for c in walk(tree, "base-config")]
                self.f["manifest"]["network_security_config"] = {
                    "path": path, "trust_anchors": certs, "pins": len(pins),
                    "pinned_domains": [d.get("attrs", {}).get("name") for d in domains][:20] if pins else [],
                    "base_cleartext": cleartext[0] if cleartext else None,
                    "user_certs_trusted": "user" in certs,
                }
                return

    # ------------------------------------------------------------ assets
    def _assets(self):
        hidden = []
        files = []
        js_hits = []
        text_urls = Counter()
        compressed_libs = []
        types = Counter()
        total = 0
        for split, zi in self.bundle.iter_files():
            name = zi.filename
            total += 1
            ext = os.path.splitext(name)[1].lower()
            top = name.split("/", 1)[0]
            if name.startswith(("classes",)) and ext == ".dex" and "/" not in name:
                continue
            if top == "lib" and ext == ".so":
                continue
            types[ext or "(none)"] += 1
            interesting = top in ("assets", "res") and (ext in TEXT_EXT or ext in (".dex", ".jar", ".apk", ".zip", ".br",
                                                                                     ".bin", ".hbc", ".so", ".dat", ""))
            if name.endswith((".so.br", ".so.gz", ".so.xz", ".so.zst")) or (ext in (".br",) and "lib" in name):
                compressed_libs.append({"file": name, "size": zi.file_size, "split": split.name})
            if not interesting or zi.file_size > MAX_TEXT_SCAN:
                if top == "assets" and zi.file_size > 200_000:
                    files.append({"file": name, "size": zi.file_size, "kind": ext or "?"})
                continue
            data = split.read(name)
            kind = None
            if data.startswith(DEX_MAGIC):
                kind = "DEX (hidden)"
                hidden.append((split.name, name, data))
            elif data[:4] == b"PK\x03\x04":
                kind = "zip/jar/apk"
                try:
                    import io
                    import zipfile
                    z = zipfile.ZipFile(io.BytesIO(data))
                    for n in z.namelist():
                        if n.endswith(".dex"):
                            dd = z.read(n)
                            if dd.startswith(DEX_MAGIC):
                                hidden.append((split.name, f"{name}!{n}", dd))
                                kind = "zip containing DEX (dynamic code)"
                except Exception:  # noqa: BLE001
                    pass
            elif data[:8] == HERMES_MAGIC:
                kind = "Hermes bytecode"
            elif data[:4] == b"\x7fELF":
                kind = "ELF in assets"
            if kind:
                files.append({"file": name, "size": len(data), "kind": kind})
            if kind in (None, "Hermes bytecode") and ext not in (".properties", ".css", ".vtt", ".csv") and \
                    not re.match(r"assets/(org|com|net|io|javax?|kotlin|okhttp3|META-INF)/", name):
                try:
                    text = data.decode("utf-8") if kind is None else data.decode("latin-1")
                except UnicodeDecodeError:
                    continue
                for m in URL_RE.finditer(text):
                    text_urls[m.group(0)[:200]] += 1
                seen_here = 0
                for m in JS_AD_ANCHORS.finditer(text):
                    if seen_here >= 6:
                        break
                    seen_here += 1
                    s = max(0, m.start() - 90)
                    js_hits.append({"file": name, "anchor": m.group(0), "offset": m.start(),
                                    "context": re.sub(r"\s+", " ", text[s:m.end() + 90])})
                if ext in (".js", ".bundle", ".jsbundle", ".mjs") or kind == "Hermes bytecode" or \
                        name.endswith("index.android.bundle"):
                    files.append({"file": name, "size": len(data), "kind": kind or "JavaScript"})
        self.asset_urls = text_urls
        self.f["assets"] = {
            "total_files": total, "by_type": dict(types.most_common(15)),
            "notable": files[:60], "ad_anchors": js_hits[:80],
            "compressed_libs": compressed_libs, "hidden_dex": [h[1] for h in hidden],
        }
        return hidden

    # ------------------------------------------------------------ code stats
    def _code_stats(self):
        q = self.idx.q
        n_cls = q("SELECT COUNT(*) FROM classes")[0][0]
        n_app = q("SELECT COUNT(*) FROM classes WHERE is_app=1")[0][0]
        n_m = q("SELECT COUNT(*) FROM methods")[0][0]
        app_names = [r[0] for r in q("SELECT name FROM classes WHERE is_app=1")]
        pkgs = Counter()
        for n in app_names:
            parts = n[1:].split("/")
            pkgs["/".join(parts[:3]) if len(parts) > 3 else "/".join(parts[:-1]) or "(root)"] += 1
        markers = []
        for path, in q("SELECT path FROM dexfiles"):
            with open(os.path.join(self.out, path), "rb") as fh:
                data = fh.read()
            for m in re.finditer(rb"~~(R8|D8|L8)\{[^}]{0,300}\}", data):
                markers.append(m.group(0).decode("utf-8", "replace"))
        kotlin = q("SELECT COUNT(*) FROM classes WHERE name LIKE 'Lkotlin/%'")[0][0] > 0
        native_methods = q("SELECT c.name, m.name, m.params, m.ret FROM methods m JOIN classes c ON c.id=m.class "
                           "WHERE (m.flags & 256) != 0 AND (c.is_app=1 OR c.category IN ('platform','player')) LIMIT 200")
        self.f["code"] = {
            "dex_files": [dict(r) for r in q("SELECT split, entry, n_classes, n_methods, version FROM dexfiles")],
            "classes": n_cls, "app_classes": n_app, "methods": n_m,
            "instructions": int(self.idx.meta("insns", 0)),
            "obfuscation": obfuscation_profile(app_names, markers),
            "compiler_markers": sorted(set(markers))[:6],
            "kotlin": kotlin,
            "top_app_packages": pkgs.most_common(15),
            "native_methods": [f"{c}->{n}({p}){r}" for c, n, p, r in native_methods],
            # NOTE: m_str/m_call carry no instruction order, so this associates every short string in a
            # method with its loadLibrary call rather than slicing the invoke's actual register. The filter
            # keeps only soname-shaped tokens (no space, no '/', no '.') so property reads like `os.arch` or
            # `java.version` are not reported as library names. A true backward register slice needs the
            # indexer to record const-string → invoke order (Tier 2).
            "loadlibrary_names": sorted({r[0] for r in q(
                "SELECT s.value FROM m_call x JOIN refs r ON r.id=x.r JOIN m_str y ON y.m=x.m JOIN strings s ON s.id=y.s "
                "WHERE r.ref LIKE 'Ljava/lang/System;->loadLibrary%' AND length(s.value) < 40 "
                "AND length(s.value) > 1 AND s.value NOT LIKE '% %' AND s.value NOT LIKE '%/%' "
                "AND s.value NOT LIKE '%.%' AND s.value GLOB '[A-Za-z]*'")})[:40],
        }

    # ------------------------------------------------------------ native
    def _native(self):
        libs = []
        seen = {}
        jni_exports = {}
        for split, zi in self.bundle.iter_files():
            n = zi.filename
            if not (n.startswith("lib/") and n.endswith(".so")) and not (n.startswith("assets/") and n.endswith(".so")):
                continue
            data = split.read(n)
            parts = n.split("/")
            abi = parts[1] if len(parts) > 2 and parts[0] == "lib" else "assets"
            lib = parts[-1]
            e = ElfInfo(data, lib)
            key = (lib, e.sha256)
            entry = {"lib": lib, "abi": abi, "split": split.name, "size": len(data), "sha256": e.sha256[:16],
                     "machine": e.machine, "needed": e.needed, "exports": len(e.exports), "imports": len(e.imports),
                     "stripped": e.stripped, "build_id": e.build_id, "error": e.error}
            same = [x for x in libs if x["lib"] == lib]
            if same:
                same[0].setdefault("other_abis", []).append(abi)
                continue
            # engines / markers over symbols + strings
            sym_text = "\n".join(e.exports + e.imports)
            if self.deep_native:
                strs = [s for _, s in elf_strings(data)]
            else:
                strs = []
            text = sym_text + "\n" + "\n".join(strs)
            engines = []
            for label, rx, note in NATIVE_ENGINES:
                m = re.search(rx, text)
                if m:
                    engines.append({"engine": label, "evidence": m.group(0)[:60], "note": note})
            ad, weak_ad, vendor_ad, fp_reason, ad_score = classify_native_ad_strings(strs)
            stext = "\n".join(strs)
            urls = Counter(m.group(0)[:160] for m in URL_RE.finditer(stext))
            self.native_urls = getattr(self, "native_urls", Counter()) + urls
            seam_imports = {k: v for k, v in NATIVE_SEAM_IMPORTS.items() if k in e.imports}
            jni = [x for x in e.exports if x.startswith("Java_")]
            for x in jni:
                jni_exports[x] = lib
            dl_targets = sorted({s for s in strs if re.fullmatch(r"lib[\w.+-]+\.so(\.br)?", s)})[:20]
            packer = [label for rx, label in PACKER_FILES if re.search(rx, lib)]
            entry.update({"engines": engines, "ad_strings": ad, "seam_imports": seam_imports,
                          "jni_exports": len(jni), "has_JNI_OnLoad": "JNI_OnLoad" in e.exports,
                          "dlopen_targets": dl_targets, "packer": packer, "url_count": len(urls),
                          "ad_score": ad_score})
            if weak_ad:
                entry["weak_ad_strings"] = weak_ad
                entry["false_positive_reason"] = fp_reason
            if vendor_ad:
                entry["vendor_hosts"] = vendor_ad  # endpoint referenced; not scored, not corroborating
            libs.append(entry)
            seen[key] = entry
        libs.sort(key=lambda x: (-x["ad_score"], -x["size"]))
        # map Java native methods to JNI exports
        mapped = []
        for jm in self.f["code"]["native_methods"]:
            cls, rest = jm.split("->")
            name = rest.split("(")[0]
            mangled = "Java_" + cls[1:-1].replace("_", "_1").replace("/", "_").replace("$", "_00024") + "_" + \
                name.replace("_", "_1")
            lib = jni_exports.get(mangled) or next((l for x, l in jni_exports.items() if x.startswith(mangled + "__")), None)
            mapped.append({"method": jm, "lib": lib or "(RegisterNatives / unresolved)"})
        self.f["native"] = {"libs": libs, "jni_map": mapped[:80]}
        # loadLibrary provenance: a literal that names a .so actually packaged in the bundle is a
        # confirmed library; the rest merely co-occur in the method (no instruction-order slice yet), so
        # they stay "possible". This is the honest interim until the backward register slice exists.
        stems = {l["lib"][3:-3] for l in libs if l["lib"].startswith("lib") and l["lib"].endswith(".so")}
        stems |= {l["lib"][:-3] for l in libs if l["lib"].endswith(".so")}  # some names loaded without 'lib'
        names = self.f["code"].get("loadlibrary_names", [])
        self.f["code"]["loadlibrary_confirmed"] = sorted(n for n in names if n in stems)
        self.f["code"]["loadlibrary_possible"] = sorted(n for n in names if n not in stems)

    # ------------------------------------------------------------ SDKs
    def _sdks(self):
        q = self.idx.q
        found = {}
        for sdk, cat, n in q("SELECT sdk, category, COUNT(*) FROM classes WHERE sdk IS NOT NULL GROUP BY sdk, category"):
            note = next((p[3] for p in PREFIXES if p[1] == sdk and p[3]), "")
            found[sdk] = {"sdk": sdk, "category": cat, "classes": n, "by": "package", "note": note}
        # Google Mobile Ads needs a core rendering class before we treat it as an ad-delivery mechanism;
        # the ad-identifier package is split out separately (kb/sdks), but a GAM hit can still be only
        # mediation stubs. Flag that so a reviewer doesn't read "ads" into ID/mediation support alone.
        gma = found.get("Google Mobile Ads (AdMob/GAM)")
        if gma:
            core = q("SELECT 1 FROM classes WHERE name LIKE 'Lcom/google/android/gms/ads/%' AND ("
                     "name LIKE '%/MobileAds;' OR name LIKE '%/AdView;' OR name LIKE '%/AdRequest;' OR "
                     "name LIKE '%/AdLoader;' OR name LIKE '%InterstitialAd;' OR name LIKE '%RewardedAd;' OR "
                     "name LIKE '%/AdManagerAdView;' OR name LIKE '%/AdManagerAdRequest;') LIMIT 1")
            gma["core_classes"] = bool(core)
            if not core:
                gma["note"] = (gma["note"] + " ").strip() + \
                    " ⚠ No core Mobile Ads classes (MobileAds/AdView/AdRequest/Interstitial/Rewarded) — " \
                    "likely mediation/ID support only, not confirmed ad rendering."
        for name, cat, markers in STRING_MARKERS:
            if name in found:
                continue
            hits = []
            for mk in markers:
                r = q("SELECT value FROM strings WHERE instr(value, ?) > 0 LIMIT 1", mk)
                if r:
                    hits.append(mk)
            if hits:
                found[name] = {"sdk": name, "category": cat, "classes": 0, "by": "strings " + ", ".join(hits),
                               "note": "present by marker strings only — classes renamed (R8) or loaded natively"}
        order = {"ads": 0, "ssai": 1, "platform": 2, "player": 3, "verification": 4, "analytics": 5,
                 "attribution": 6, "consent": 7, "drm": 8, "engine": 9, "network": 10}
        self.f["sdks"] = sorted(found.values(), key=lambda s: (order.get(s["category"], 99), -s["classes"]))
        # engine guess
        engines = {s["sdk"] for s in self.f["sdks"]}
        native_eng = {e["engine"] for lib in self.f["native"]["libs"] for e in lib["engines"]}
        guess = []
        if engines & {"Google IMA SDK", "Media3 IMA extension", "ExoPlayer2 IMA extension", "Google DAI"}:
            guess.append("Google IMA / DAI client SDK (client-side VAST and/or server-stitched DAI)")
        if engines & {"FreeWheel AdManager", "Yospace", "AWS MediaTailor", "Adobe Primetime/TVSDK"}:
            guess.append("Server-side stitching (SSAI) — look for the manifest / ad-free variant seam")
        if native_eng & {"V8 JavaScript engine", "QuickJS", "WAMR / WebAssembly", "Hermes"} or \
                engines & {"React Native", "Flutter"}:
            guess.append("Proprietary JS/native engine — ad logic may live in a .so or JS bundle")
        if any(s["sdk"] == "Twitch" for s in self.f["sdks"]) or \
                q("SELECT 1 FROM refs WHERE ref LIKE 'Landroid/webkit/WebViewClient;->shouldInterceptRequest%' LIMIT 1"):
            guess.append("WebView content path present — check whether the player is a WebView")
        self.f["engine_guess"] = guess

    # ------------------------------------------------------------ trackers
    def _trackers(self):
        from .trackers import audit
        t = audit(self.idx, self.f, getattr(self, "manifest_tree", None))
        # meta-data kill switches are often set through a resource (@bool/...): show the real value
        for k in t["kill_switches"] + [k for i in t["items"] for k in i["kill_switches"]]:
            cur = k.get("current")
            if isinstance(cur, str) and cur.startswith("@0x") and self.res is not None:
                try:
                    rid = int(cur[1:], 16)
                    k["current"] = self.res.values.get(rid, cur)
                    k["via"] = self.res.name(rid)
                except ValueError:
                    pass
        self.f["trackers"] = t

    # ------------------------------------------------------------ protections
    def _protections(self):
        out = []
        q = self.idx.q
        all_strings = q("SELECT id, value FROM strings WHERE length(value) < 300")
        all_refs = q("SELECT id, ref FROM refs")
        for label, sev, kind, pattern, note in PROTECTIONS:
            rx = re.compile(pattern)
            if kind == "string":
                ids = [str(i) for i, v in all_strings if rx.search(v)][:500]
                rows = q("SELECT s.value, c.name, m.name, c.is_app FROM strings s JOIN m_str x ON x.s=s.id "
                         "JOIN methods m ON m.id=x.m JOIN classes c ON c.id=m.class WHERE s.id IN (%s) "
                         "ORDER BY c.is_app DESC LIMIT 8" % ",".join(ids)) if ids else []
                hits = [f"{c}->{m}  \"{v[:60]}\"" for v, c, m, _ in rows]
            else:
                ids = [str(i) for i, v in all_refs if rx.search(v)][:500]
                rows = q("SELECT r.ref, c.name, m.name, c.is_app FROM refs r JOIN m_call x ON x.r=r.id "
                         "JOIN methods m ON m.id=x.m JOIN classes c ON c.id=m.class WHERE r.id IN (%s) "
                         "ORDER BY c.is_app DESC LIMIT 8" % ",".join(ids)) if ids else []
                hits = [f"{c}->{m}  calls {v.split('->')[1][:50]}" for v, c, m, _ in rows]
            if hits:
                out.append({"label": label, "severity": sev, "hits": hits, "note": note})
        packers = sorted({p for lib in self.f["native"]["libs"] for p in lib["packer"]})
        for p in packers:
            out.append({"label": f"Packer/protector: {p}", "severity": "high", "hits": [], "note":
                        "Real code may be encrypted/loaded at runtime; static DEX shows only the stub."})
        if self.f["assets"]["hidden_dex"]:
            out.append({"label": "DEX hidden in assets", "severity": "med", "hits": self.f["assets"]["hidden_dex"][:10],
                        "note": "Indexed too (split column shows the asset)."})
        nsc = self.f["manifest"].get("network_security_config") or {}
        if nsc.get("pins"):
            out.append({"label": "Pinning in network_security_config", "severity": "med",
                        "hits": nsc.get("pinned_domains", []), "note": "Needs a resource patch to inspect traffic."})
        if self.f["manifest"]["application"].get("extractNativeLibs") is False:
            out.append({"label": "extractNativeLibs=false", "severity": "info", "hits": [],
                        "note": "Injected .so must be page-aligned+stored, or force extractNativeLibs=true (native-adstrip-toolkit lesson)."})
        self.f["protections"] = out

    # ------------------------------------------------------------ hosts
    def _hosts(self):
        q = self.idx.q
        hosts = defaultdict(lambda: {"dex": 0, "native": 0, "assets": 0, "urls": set(), "users": []})
        for (val,) in q("SELECT value FROM strings WHERE value LIKE '%.%' AND length(value) < 600"):
            for m in URL_RE.finditer(val):
                h = m.group(0).split("/")[2].split(":")[0].lower()
                hosts[h]["dex"] += 1
                if len(hosts[h]["urls"]) < 4:
                    hosts[h]["urls"].add(m.group(0)[:140])
            if "://" not in val and len(val) < 120:
                for m in HOST_RE.finditer(val):
                    h = m.group(0).lower()
                    if h.count(".") >= 1 and not re.search(r"\.(java|kt|class|so|xml|json|png|js)$", h) and \
                            not h.startswith(("com.", "org.", "net.", "io.", "tv.", "co.")):
                        hosts[h]["dex"] += 1
        for url, n in self.asset_urls.items():
            h = url.split("/")[2].split(":")[0].lower() if url.count("/") >= 2 else url
            hosts[h]["assets"] += n
            if len(hosts[h]["urls"]) < 4:
                hosts[h]["urls"].add(url[:140])
        for url, n in getattr(self, "native_urls", Counter()).items():
            h = url.split("/")[2].split(":")[0].lower() if url.count("/") >= 2 else url
            hosts[h]["native"] += n
            if len(hosts[h]["urls"]) < 4:
                hosts[h]["urls"].add(url[:140])
        out = []
        for h, v in hosts.items():
            if not h or "." not in h or len(h) > 80:
                continue
            cat, note = host_category(h)
            out.append({"host": h, "category": cat, "note": note, "dex": v["dex"], "native": v["native"],
                        "assets": v["assets"], "urls": sorted(v["urls"])})
        out.sort(key=lambda x: (x["category"] is None, x["category"] or "", -(x["dex"] + x["native"] + x["assets"])))
        # who uses the ad hosts in code
        for h in out:
            if h["category"] in ("ads", "ssai", "verification", "analytics", "attribution") and h["dex"]:
                rows = self.idx.string_users(h["host"], limit=4)
                h["used_by"] = [f"{r['cls']}->{r['name']}" for r in rows]
        self.f["hosts"] = out[:250]

    # ------------------------------------------------------------ seams
    def _seams(self):
        hunter = SeamHunter(self.idx)
        cands = hunter.score_all(limit=120)
        for c in cands:
            if c["ret"] == "Z":
                c["polarity"] = hunter.polarity(c["id"])
        for i, c in enumerate(cands):
            shaped = any(w.startswith(("shape:", "obfuscated method in", "overrides")) for w in c["why"])
            if i < 25 or shaped:
                c["fingerprint"] = hunter.fingerprint(c["id"])
                c["callers"] = hunter.callers_of_method(c["id"], limit=5)
        shaped = [c for c in cands[12:] if any(w.startswith(("shape:", "obfuscated method in")) for w in c["why"])]
        for c in cands[:12] + shaped[:12]:
            c["chains"] = hunter.chain(c["id"], depth=3)
            c["dataflow"] = hunter.dataflow(c["id"])
            r = self.idx.method(c["id"])
            text = self.idx.smali(r)
            lines = text.splitlines()
            c["smali"] = "\n".join(lines[:60]) + (f"\n    ... ({len(lines) - 60} more lines)" if len(lines) > 60 else "")
        # ad-named resources (layouts, ids, strings) referenced from code: stable literal anchors
        ad_res = []
        if self.res:
            wanted = {}
            for rid, nm in self.res.names.items():
                short = nm.split("/", 1)[-1]
                if nm.split("/")[0] in ("layout", "id", "string", "drawable", "dimen", "bool", "integer") and \
                        sum(AD_TOKENS.get(t, 0) for t in set(tokens(short.replace("_", " ").title().replace(" ", "")))) >= 3:
                    wanted[rid] = nm
            if wanted:
                for rid, mids in self._res_users(list(wanted)).items():
                    ad_res.append({"resource": wanted[rid], "id": hex(rid), "used_by": mids[:5], "count": len(mids)})
        ad_res.sort(key=lambda x: -x["count"])
        self.f["seams_ad_resources"] = ad_res[:60]
        self.f["seams"] = {
            "integration_points": hunter.integration_points(),
            "implementers": hunter.implementers(),
            "candidates": cands,
            "hot_classes": hunter.hot_classes(cands),
            "deobfuscation_hints": hunter.deobf_hints([c["class"] for c in cands[:40]]),
        }

    def _java(self):
        """jadx Java for the classes a reviewer would open first (only when jadx is installed)."""
        from .tools import jadx_source, which
        jadx = which()["jadx"]
        if not jadx:
            self.f["java"] = {"available": False, "note": "jadx not found — `autopsy tools install` adds Java excerpts"}
            return
        cands = self.f["seams"]["candidates"]
        if not self.f["seams"]["implementers"] and not any(c["score"] >= 12 for c in cands):
            self.f["java"] = {"available": True, "classes": [], "note": "skipped: no credible seam to read"}
            return
        self.log("      jadx: decompiling top classes")
        classes = []
        shaped = [c for c in cands if any(w.startswith(("shape:", "obfuscated method in")) for w in c["why"])]
        for c in cands[:10] + shaped[:8]:
            if c["class"] not in classes:
                classes.append(c["class"])
        for imp in self.f["seams"]["implementers"]:
            for c in imp["classes"][:2]:
                if c["class"] not in classes:
                    classes.append(c["class"])
        classes = classes[:16]
        jdir = os.path.join(self.out, "java")
        os.makedirs(jdir, exist_ok=True)
        done = {}
        for cn in classes:
            src = jadx_source(self.idx, cn, jadx)
            if src:
                fn = re.sub(r"[^\w.$-]", "_", cn[1:-1].replace("/", ".")) + ".java"
                with open(os.path.join(jdir, fn), "w", encoding="utf-8") as fh:
                    fh.write(src)
                done[cn] = src
        for c in cands:
            src = done.get(c["class"])
            if src:
                c["java"] = java_method_excerpt(src, c["name"], len(split_params_(c["params"])))
        self.f["java"] = {"available": True, "classes": [os.path.join("java", re.sub(r"[^\w.$-]", "_", c[1:-1].replace("/", ".")) + ".java")
                                                         for c in done]}

    def _apktool(self):
        from .tools import apktool_tree
        base = os.path.join(self.out, "base.apk")
        with open(base, "wb") as fh:
            fh.write(open(self.path, "rb").read() if self.bundle.kind == "apk" else
                     self._split_bytes(self.bundle.base))
        out = os.path.join(self.out, "apktool")
        self.log("      apktool: decoding smali tree")
        apktool_tree(base, out)
        self.f["apktool_dir"] = out

    @staticmethod
    def _split_bytes(split):
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for zi in split.zf.infolist():
                z.writestr(zi, split.zf.read(zi.filename))
        return buf.getvalue()

    def _res_users(self, rids):
        out = defaultdict(list)
        for i in range(0, len(rids), 500):
            chunk = rids[i:i + 500]
            for rid, mid in self.idx.q("SELECT res, m FROM m_res WHERE res IN (%s)" % ",".join(map(str, chunk))):
                r = self.idx.method(mid)
                out[rid].append(self.idx.sig(r))
        return out

    # ------------------------------------------------------------ drift
    def _drift(self):
        key, app = app_for_package(self.package or "")
        if not app:
            self.f["known_app"] = None
            return
        if not self.f["code"].get("classes"):
            # a config/resource split has no code: every fingerprint would read CLASS_MISSING
            self.f.setdefault("warnings", []).append(
                f"Known app ({key}) but this input has no DEX code — drift not checked; scan the base/universal APK.")
            self.f["known_app"] = None
            return
        from .drift import find_reference
        ref = None
        try:  # an earlier scan of this app is the rename oracle (.source of the class that held each hook)
            ref = find_reference(self.out, self.package, {fp["id"] for fp in app.get("fingerprints", [])})
        except Exception:  # noqa: BLE001 - the reference is a bonus, never a failure
            ref = None
        from .drift import check_injected
        try:
            results = drift_check(self.idx, key, app, ref=ref)
            self._injected = check_injected(self.idx, app, ref)
        finally:
            if ref:
                ref["idx"].close()
        self._drift_ref = ref["version"] if ref else None
        fixes = [r for r in results if r.get("fix")]
        if fixes:
            fd = os.path.join(self.out, "draft", "fixes")
            os.makedirs(fd, exist_ok=True)
            payload = {"package": self.package, "versionName": self.f["manifest"].get("versionName"),
                       "note": "Re-anchored matcher descriptors; each matches exactly one method in this build.",
                       "fixes": [{"id": r["id"], "status": r["status"], "target": r["fix"]["target"],
                                  "changed": {k: {"from": old, "to": new} for k, (old, new) in r["fix"]["changed"].items()},
                                  "descriptor": r["fix"]["descriptor"]} for r in fixes]}
            with open(os.path.join(fd, f"{key}-fingerprints.fix.json"), "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
        self.f["known_app"] = {
            "key": key, "targets": app.get("targets"), "engine": app.get("engine_label") or app.get("engine"),
            **{k: app.get(k) for k in ("runtime", "delivery", "seam", "action", "patch_evidence", "device_signature",
                                       "drift", "log_tags")},
            "patches": app.get("patches"),
            "version_is_target": (self.f["manifest"].get("versionName") in (app.get("targets") or [])),
            "results": results,
            "summary": dict(Counter(r["status"] for r in results)),
            "reference": getattr(self, "_drift_ref", None),
            "injected": getattr(self, "_injected", []),
        }

    # ------------------------------------------------------------ verdict
    def _verdict(self):
        """A short, prioritised list of investigation points."""
        plan = []
        ka = self.f.get("known_app")
        if ka:
            bad = [r for r in ka["results"] if r["status"] not in ("OK", "FOUND_BY_STRINGS", "UNVERIFIABLE", "AMBIGUOUS")]
            n_cm = sum(r["status"] == "CLASS_MISSING" for r in ka["results"])
            n_ok = sum(r["status"] == "OK" for r in ka["results"])
            hard_cm = any(r["status"] == "CLASS_MISSING" and r.get("hard") for r in ka["results"])
            # soft (optional) fingerprints vanishing next to a working one can be a planned architecture
            # move (e.g. logic moved from Java to native), not a rewrite
            if n_cm >= 3 and n_cm >= 0.7 * len(ka["results"]) and (hard_cm or not n_ok):
                plan.append(f"DIFFERENT LINEAGE? {n_cm}/{len(ka['results'])} of the recorded fingerprints' classes are "
                            f"absent — this looks like a rewrite / different app line, not drift. "
                            f"Treat it as a new app; don't re-anchor the old fingerprints.")
            if bad:
                hard = [r["id"] for r in bad if r.get("hard")]
                fixed = [r["id"] for r in bad if r.get("fix")]
                if fixed:
                    plan.append(f"FIX READY for {', '.join(fixed)}: draft/fixes/{ka['key']}-Fingerprints.fix.kt "
                                f"(re-anchored, verified unique in this build).")
                plan.append(f"Known app ({ka['key']}): {len(bad)} fingerprint(s) drifted — fix those first: " +
                            "; ".join(f"{r['id']} {r['status']}" + (f" → likely {r['candidates'][0].split('  [')[0]}"
                                                                    if r.get("candidates") else "")
                                      for r in bad[:6]) +
                            (f". ⚠ {', '.join(hard)} used via .method — the WHOLE PATCH ABORTS on this build until re-anchored."
                             if hard else ". All use methodOrNull — patching succeeds but those hooks are skipped."))
            else:
                amb = [r["id"] for r in ka["results"] if r["status"] == "AMBIGUOUS" or r.get("partial")]
                msg = f"Known app ({ka['key']}): every checkable fingerprint still matches this build uniquely."
                if amb:
                    msg += (f" {len(amb)} only PARTIALLY verified ({', '.join(amb[:4])}) — some custom conditions "
                            f"weren't evaluated; confirm with a real patch run before adding the target.")
                if not ka.get("version_is_target") and not amb:
                    msg += (f" Safe to add AppTarget(\"{self.f['manifest'].get('versionName')}\") to the patch's "
                            f"Constants.COMPATIBILITY targets (then confirm on device).")
                plan.append(msg)
            for it in [i for i in ka.get("injected", []) if i["status"] != "OK"]:
                to = f" → re-pin to `{it['fix']['target']}` ({it['fix']['evidence']})" if it.get("fix") else ""
                plan.append(f"INJECTED TYPE MISSING: `{it['type']}` is used inside {it['file'] or 'a patch'}'s injected "
                            f"smali but no longer exists{to}. The patch still APPLIES but throws NoClassDefFoundError "
                            f"at runtime.")
        dr = self.f.get("drafts") or {}
        for h in dr.get("hooks", []):
            plan.append(f"SEAM (scoped in {dr['dir']}/SCOPING.md): {h['sig']} — {h['why']} "
                        f"(returns {h['returnType']}, {h.get('confidence') or 'see notes'})")
        ip = self.f["seams"]["integration_points"]
        ad_ip = [p for p in ip if p["engine"] not in ("loader", "native", "network", "analytics")]
        for p in ad_ip[:4]:
            plan.append(f"[{p['id']}] {p['count']} call site(s), e.g. {p['sites'][0]['sig']} → {p['strategy']}")
        ids = {p["id"] for p in ip}
        if ids & {"ima-dai-streamrequest", "ima-streammanager"}:
            stack_ic = [c for imp in self.f["seams"]["implementers"] if imp["label"] == "OkHttp Interceptor"
                        for c in imp["classes"] if re.search(r"(?i)player|avia|video|stream|media", c["class"])]
            where = (f" In-app network seam: {stack_ic[0]['class']}->intercept.") if stack_ic else ""
            plan.append("LIVE (DAI): full-service IMA-DAI returns one stitched stream — the ad media is part of "
                        "the stream, so it is not separable client-side. The usual ceiling is masking the break." + where)
        review = (self.f.get("drafts") or {}).get("review", [])
        gated = [r for r in review if r["strategy"].startswith("⚠")]
        if gated:
            plan.append("Investigate before modifying: " + "; ".join(r["sig"].split("->")[1].split("(")[0] + " in " +
                                                     r["sig"].split("->")[0].rsplit("/", 1)[-1] for r in gated[:4]) +
                        " — gated callbacks/event handlers (content can hang or ANR if removed); see Investigation points.")
        cands = self.f["seams"]["candidates"]
        has_ad_stack = any(s["category"] in ("ads", "ssai") for s in self.f["sdks"]) or bool(ad_ip)
        strong = [c for c in cands if c["score"] >= 12]
        if not has_ad_stack and not strong:
            plan.append(f"No ad SDK, no seam-API call sites, and no strong candidate (best score "
                        f"{cands[0]['score'] if cands else 0}). Either the app shows no ads, or ads are fully "
                        f"server-side / native / WebView — capture a manifest (seamhunter stream) or check native libs.")
            cands = []
        drafted = {h["sig"] for h in dr.get("hooks", [])}
        noise = re.compile(r"Google Mobile Ads \(display ads\) internals|Binder stub")
        cands = [c for c in cands if not any(noise.search(w) for w in c.get("why", []))]
        strong = [c for c in strong if c in cands]
        for c in [c for c in (strong or cands) if c["sig"] not in drafted and not c["strategy"].startswith("⚠")][:3]:
            fp = c.get("fingerprint", {})
            u = "unique" if fp.get("unique") else f"{fp.get('matches', '?')} matches"
            plan.append(f"Candidate {c['sig']} (score {c['score']}, fingerprint {u}) → {c['strategy']}")
        measurement = re.compile(r"(?i)comscore|nielsen|conviva|moat|omid|adjust|appsflyer|crashlytics|sentry|datadog")
        eng = [lib for lib in self.f["native"]["libs"] if (lib["ad_score"] >= 3 and not measurement.search(lib["lib"])) or
               any(e["engine"] in ("V8 JavaScript engine", "QuickJS", "WAMR / WebAssembly") for e in lib["engines"])]
        js_engine = [lib["lib"] for lib in eng if any(e["engine"] in ("V8 JavaScript engine", "QuickJS", "WAMR / WebAssembly")
                                                      for e in lib["engines"])]
        if js_engine and not [c for c in cands if c["score"] >= 30]:
            plan.append(f"JAVA SIDE HAS NO REAL AD SEAM: ad logic runs in {', '.join(js_engine[:2])} (JS/WASM engine), "
                        f"often in code downloaded at runtime — static candidates above are weak. Work at runtime "
                        f"(work at the native response buffers); strings absent from this APK "
                        f"can still arrive over the network.")
        for lib in eng[:3]:
            plan.append(f"Native: {lib['lib']} ({', '.join(e['engine'] for e in lib['engines'][:3]) or 'ad strings'}) — "
                        f"seam imports: {', '.join(lib['seam_imports']) or 'none'}; inspect this library directly.")
        if self.f["assets"]["ad_anchors"]:
            files = sorted({h["file"] for h in self.f["assets"]["ad_anchors"]})[:4]
            plan.append(f"Ad anchors in assets/JS: {', '.join(files)} — possible string/asset seam.")
        if not self.f["code"]["dex_files"]:
            plan.insert(0, "NO DEX CODE FOUND — this may be a split-only bundle, a packed/encrypted app, or a "
                           "Flutter/React Native/Unity app whose logic lives in native libs or assets. The verdicts "
                           "below are NOT evidence of 'no ads'.")
        skipped = int(self.idx.meta("skipped_malformed", 0) or 0) if getattr(self, "idx", None) else 0
        if skipped:
            plan.insert(0, f"{skipped} malformed classes/methods were skipped while indexing (protector or corrupt "
                           f"download) — seams inside them are invisible to this report.")
        for e in self.f.get("errors", []):
            plan.insert(0, f"STAGE FAILED: {e['stage']} ({e['error']}) — that section of the report is empty.")
        if not plan:
            plan.append("No ad seam surfaced statically. Check: dynamic code (hidden DEX, downloaded .so.br), "
                        "server-side-only SSAI (manifest capture needed), or a WebView player.")
        self.f["plan"] = plan
