"""Run: python -m unittest discover -s tests -v   (from the apk-autopsy folder)

Fixtures: a synthetic ad-supported app (sources in tests/fixtures/src) compiled with d8 against
the real Google IMA SDK 3.33.0, packed as .apk and as an APKMirror-style .apkm (base + ABI split).
v2.apk is the same app after a simulated R8 rename (La/b/c; -> La/b/q;) plus one new method.
"""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from autopsy import drift  # noqa: E402
from autopsy.analyze import Autopsy  # noqa: E402
from autopsy.container import open_bundle  # noqa: E402
from autopsy.dex import Dex  # noqa: E402
from autopsy.index import Index  # noqa: E402
from autopsy.seams import SeamHunter  # noqa: E402
from autopsy.stream import analyze_file, decode_scte35  # noqa: E402

FX = os.path.join(HERE, "fixtures")
TMP = tempfile.mkdtemp(prefix="autopsy-test-")
_cache = {}


def scan(name):
    if name not in _cache:
        out = os.path.join(TMP, name)
        _cache[name] = (Autopsy(os.path.join(FX, name), out, log=lambda *a: None).run(), out)
    return _cache[name]


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class Container(unittest.TestCase):
    def test_apkm_splits(self):
        b = open_bundle(os.path.join(FX, "sample.apkm"))
        self.assertEqual(b.kind, "apkm")
        self.assertEqual(b.base.name, "base.apk")
        self.assertEqual(len(b.splits), 2)
        self.assertEqual(b.info["pname"], "com.example.tvapp")
        self.assertEqual([n for _, n in b.dex_entries()], ["classes.dex"])


class Disassembler(unittest.TestCase):
    def test_smali_of_known_method(self):
        b = open_bundle(os.path.join(FX, "base.apk"))
        d = Dex(b.base.read("classes.dex"))
        for c in d.iter_classes():
            if c["name"] == "La/b/c;":
                for midx, flags, code in c["methods"]:
                    if d.method_parts(midx)[1] == "d":
                        s = d.disassemble(code, midx, flags)
                        self.assertIn('const-string v0, "/ads/"', s)
                        self.assertIn("invoke-virtual {p1, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z", s)
                        self.assertIn(":cond_11", s)
                        return
        self.fail("method not found")


class Scan(unittest.TestCase):
    def test_sdk_and_integration_points(self):
        f, _ = scan("sample.apkm")
        sdks = {s["sdk"] for s in f["sdks"]}
        self.assertIn("Google IMA SDK", sdks)
        ids = {p["id"] for p in f["seams"]["integration_points"]}
        self.assertTrue({"ima-adsmanager-start", "ima-cuepoints", "ima-dai-streamrequest"} <= ids)

    def test_top_candidate_and_gated_warning(self):
        f, _ = scan("sample.apkm")
        cands = f["seams"]["candidates"]
        # hookable decision points rank first; the gated callback is still found, tier 2, with the warning
        self.assertEqual(cands[0]["tier"], 0)
        loaded = next(c for c in cands if "onAdsManagerLoaded" in c["sig"])
        self.assertEqual(loaded["tier"], 2)
        self.assertTrue(loaded["strategy"].startswith("⚠"))  # RTE lesson: never kill this callback
        self.assertTrue(loaded["fingerprint"]["unique"])

    def test_obfuscated_fingerprint_is_anchored(self):
        f, out = scan("sample.apkm")
        idx = Index(out)
        row = idx.find_methods("La/b/c;->a")[0]
        fp = SeamHunter(idx).fingerprint(row["id"])
        # descriptor is framework-agnostic JSON; the stable anchor (a call) survives R8
        blob = __import__("json").dumps(fp["descriptor"])
        self.assertIn("createVodStreamRequest", blob)
        self.assertEqual(fp["matches"], 1)
        self.assertNotIn("Fingerprint(", blob)   # no patcher-specific Kotlin
        self.assertNotIn("kotlin", fp)

    def test_protections_assets_native(self):
        f, _ = scan("sample.apkm")
        labels = {p["label"] for p in f["protections"]}
        self.assertIn("DexGuard CertCheck", labels)
        self.assertIn("Certificate pins (sha256/)", labels)
        self.assertTrue(any(h["anchor"] == "adBreaks" for h in f["assets"]["ad_anchors"]))
        self.assertTrue(f["native"]["libs"])
        self.assertEqual(f["native"]["jni_map"][0]["method"], "La/b/d;->nativeStrip([B)I")

    def test_queries(self):
        _, out = scan("sample.apkm")
        idx = Index(out)
        self.assertTrue(idx.callers("AdsManager;->start()V"))
        self.assertTrue(idx.string_users("fwmrm.net"))


class Drift(unittest.TestCase):
    def test_statuses(self):
        _, out = scan("base.apk")
        idx = Index(out)
        app = {"packages": ["org.fdroid.fdroid"], "fingerprints": [
            {"id": "Ok", "definingClass": "Lcom/example/tvapp/player/AdBreakScheduler;", "name": "getAdBreaks",
             "returnType": "Ljava/util/List", "parameters": []},
            {"id": "Sig", "definingClass": "Lcom/example/tvapp/player/AdBreakScheduler;", "name": "shouldPlayAd",
             "returnType": "Z", "parameters": ["I"]},
            {"id": "Gone", "definingClass": "Lcom/example/Nope;", "name": "x", "returnType": "V"},
            {"id": "Str", "strings": ["pauseAd shown"]},
            {"id": "Custom", "returnType": "V", "hasCustomMatcher": True},
        ]}
        res = {r["id"]: r["status"] for r in drift.check(idx, "t", app)}
        self.assertEqual(res, {"Ok": "OK", "Sig": "SIGNATURE_CHANGED", "Gone": "CLASS_MISSING",
                               "Str": "FOUND_BY_STRINGS", "Custom": "UNVERIFIABLE"})


class Diff(unittest.TestCase):
    def test_rename_found(self):
        from autopsy.diff import diff
        _, o = scan("base.apk")
        _, n = scan("v2.apk")
        d = diff(o, n)
        moves = {m["old"]: m for m in d["seam_moves"]}
        m = moves["La/b/c;->isAdDisabled()Z"]
        self.assertEqual(m["new"], "La/b/q;->isAdDisabled()Z")
        self.assertIn("midroll podding enabled", d["ad_strings_added"])


class Stream(unittest.TestCase):
    def test_scte35_reference_vectors(self):
        a = decode_scte35("/DAvAAAAAAAA///wFAVIAACPf+/+c2nALv4AUsz1AAAAAAAKAAhDVUVJAAABNWLbowo=")
        self.assertEqual(a["command"], "splice_insert")
        self.assertAlmostEqual(a["break_duration_s"], 60.294, places=2)
        b = decode_scte35("/DA0AAAAAAAA///wBQb+cr0AUAAeAhxDVUVJSAAAjn/PAAGlmbAICAAAAAAsoKGKNAIAmsnRfg==")
        self.assertEqual(b["segmentation"][0]["type"], "Provider Placement Opp Start")
        self.assertEqual(b["segmentation"][0]["duration_s"], 307.0)

    def test_hls(self):
        t = analyze_file(os.path.join(FX, "live.m3u8"))
        self.assertIn("AD hosts in segments: ads.fwmrm.net", t)
        self.assertIn("DATERANGE", t)


if __name__ == "__main__":
    unittest.main()


class Parity(unittest.TestCase):
    """What a Claude session would find/write by hand: implementers, data flow, drafts."""

    def test_obfuscated_listener_found_by_interface(self):
        f, _ = scan("sample.apkm")
        imps = {p["label"]: p for p in f["seams"]["implementers"]}
        self.assertIn("IMA AdEvent listener", imps)
        self.assertEqual(imps["IMA AdEvent listener"]["classes"][0]["class"], "La/b/e;")
        self.assertIn("IMA AdError listener", imps)

    def test_dataflow_links_cuepoints_field(self):
        f, _ = scan("sample.apkm")
        top = next(c for c in f["seams"]["candidates"] if "onAdsManagerLoaded" in c["sig"])
        fields = {d["field"] for d in top["dataflow"]}
        self.assertIn("Lcom/example/tvapp/player/AdBreakScheduler;->cuePoints:Ljava/util/List;", fields)

    def test_drafts_are_conservative(self):
        f, out = scan("sample.apkm")
        dr = f["drafts"]
        auto = {h["sig"]: h for h in dr["hooks"]}
        self.assertIn("Lcom/example/tvapp/player/AdBreakScheduler;->getAdBreaks()Ljava/util/List;", auto)
        # analysis-only: hooks carry evidence/return type/confidence, NOT neutralization payloads
        self.assertNotIn("smali", auto["La/b/c;->isAdDisabled()Z"])
        self.assertEqual(auto["La/b/c;->isAdDisabled()Z"]["returnType"], "Z")
        review = {r["sig"] for r in dr["review"]}
        self.assertIn("Lcom/example/tvapp/player/AdBreakScheduler;->onAdsManagerLoaded("
                      "Lcom/google/ads/interactivemedia/v3/api/AdsManagerLoadedEvent;)V", review)  # gated callback
        self.assertNotIn("Lcom/example/tvapp/player/AdBreakScheduler;->vastUrl()Ljava/lang/String;", auto)  # no null returns
        # SeamHunter emits neutral scoping docs only — never patch/Kotlin files
        for name in ("SCOPING.md", "VERIFY.md"):
            self.assertTrue(os.path.exists(os.path.join(out, dr["dir"], name)), name)
        for gone in ("Fingerprints.kt", "SkipAdsPatch.kt", "Constants.kt", "seam-map-overlay.json"):
            self.assertFalse(os.path.exists(os.path.join(out, dr["dir"], gone)), gone)


class Regressions(unittest.TestCase):
    """Permanent assertions for the Tier-1 false-positive fixes (SDK ID, native strings, obfuscation, etc.)."""

    def test_advertising_id_is_not_google_mobile_ads(self):
        from autopsy.index import classify
        sdk, cat, is_app = classify("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;")
        self.assertEqual(sdk, "Advertising ID client")
        self.assertEqual(cat, "identity")        # never ranked as an ad-delivery mechanism
        # a real Mobile Ads class still classifies as ads (the longer identifier prefix doesn't swallow it)
        self.assertEqual(classify("Lcom/google/android/gms/ads/MobileAds;")[:2],
                         ("Google Mobile Ads (AdMob/GAM)", "ads"))

    def test_highcharts_quartile_is_not_ad_tracking(self):
        from autopsy.analyze import classify_native_ad_strings
        # generic terms alone (Highcharts charting code) → not scored, flagged as a likely false positive
        confirmed, weak, vendor, reason, score = classify_native_ad_strings(
            ["Highcharts trackByArea", "series.firstQuartile value", "impression tooltip"])
        self.assertEqual(score, 0)
        self.assertFalse(confirmed)
        self.assertTrue(weak)
        self.assertIn("charting", reason)

    def test_weak_terms_count_only_when_corroborated_nearby(self):
        from autopsy.analyze import classify_native_ad_strings
        # same string record: strong ad-break key + weak quartile → both confirmed
        c, w, v, r, s = classify_native_ad_strings(["adBreaks firstQuartile"])
        self.assertIn("ad-break field/key", c)
        self.assertIn("ad tracking", c)
        self.assertFalse(w)
        self.assertGreaterEqual(s, 2)
        # adjacent records (within the window) also corroborate
        c, w, v, r, s = classify_native_ad_strings(["<VAST version=1>", "firstQuartile"])
        self.assertIn("VAST", c)
        self.assertIn("ad tracking", c)
        self.assertFalse(w)

    def test_weak_not_corroborated_across_distant_records(self):
        from autopsy.analyze import classify_native_ad_strings
        # the strong artifact is 11 records away — library-wide promotion must NOT happen
        c, w, v, r, s = classify_native_ad_strings(["adBreaks"] + ["zzz"] * 10 + ["firstQuartile"])
        self.assertIn("ad-break field/key", c)
        self.assertNotIn("ad tracking", c)
        self.assertIn("ad tracking", w)

    def test_vast_majority_is_not_vast(self):
        from autopsy.analyze import classify_native_ad_strings
        c, w, v, r, s = classify_native_ad_strings(["the vast majority of requests succeed"])
        self.assertNotIn("VAST", c)
        self.assertEqual(s, 0)

    def test_libcronet_prose_is_not_an_ad_library(self):
        from autopsy.analyze import classify_native_ad_strings
        # VERBATIM string records from the real libcronet.92.0.4515.131.so (Netflix 13.1.5), supplied by
        # a 'stitched' prose record, the bare .doubleclick.net host, and a Wikipedia-derived blob
        # containing 'vast majority of'. None is a real ad artifact; nothing may be scored.
        cronet = [
            "That data will be stitched into a single file (this one) once logging",
            ".doubleclick.net",
            '  (function() {the 15th century.preventDefault(large number of Byzantine Empire.jpg|thumb|'
            'left|vast majority ofmajority of the  align="center">University Pressdominated by theSecond '
            'World Wardistribution of style="position:the rest of the characterized by rel="nofollow">'
            'derives from therather than the a combination ofstyle="width:100English-speakingcomputer '
            'scienceborder="0" alt="the existence ofDemocratic Party" style="margin-For this reason,'
            '.js"></script>',
        ]
        c, w, v, r, s = classify_native_ad_strings(cronet)
        self.assertEqual(s, 0)            # nothing scored → libcronet is not a prioritized ad lead
        self.assertFalse(c)               # no confirmed ad strings
        self.assertIn("ad vendor", v)     # .doubleclick.net kept as presence-only vendor evidence
        self.assertIn("stitcher", w)      # 'stitched' kept as unscored weak evidence (uncorroborated)
        self.assertNotIn("VAST", c)       # 'vast majority of' is not VAST

    def test_bare_interstitial_is_weak_specific_is_strong(self):
        from autopsy.analyze import classify_native_ad_strings
        c, w, v, r, s = classify_native_ad_strings(["show interstitial screen on back"])
        self.assertEqual(s, 0)
        self.assertIn("interstitial", w)
        c, w, v, r, s = classify_native_ad_strings(["loadInterstitialAd(adUnitId)"])
        self.assertIn("ad interstitial", c)
        self.assertGreaterEqual(s, 1)

    def test_os_arch_is_not_a_loadlibrary_name(self):
        import sqlite3
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE strings(value TEXT)")
        db.executemany("INSERT INTO strings VALUES (?)",
                       [("os.arch",), ("java.version",), ("gadget",), ("native-lib",),
                        ("c++_shared",), ("a b",), ("foo/bar",), ("x",)])
        # the exact predicate used in analyze._code_stats for loadlibrary_names
        got = {r[0] for r in db.execute(
            "SELECT value FROM strings WHERE length(value) < 40 AND length(value) > 1 "
            "AND value NOT LIKE '% %' AND value NOT LIKE '%/%' AND value NOT LIKE '%.%' "
            "AND value GLOB '[A-Za-z]*'")}
        self.assertEqual(got, {"gadget", "native-lib", "c++_shared"})
        db.close()

    def test_dexguard_long_names_are_not_light(self):
        from autopsy.analyze import obfuscation_profile, _wordlike
        self.assertTrue(_wordlike("SettingsActivity"))
        self.assertFalse(_wordlike("glgg"))   # long but no vowel
        self.assertFalse(_wordlike("zz"))
        # DexGuard-style: long synthetic names concentrated under a 1-char root
        dg = [f"Lo/zz{i}q;" for i in range(30)]
        prof = obfuscation_profile(dg, markers=[])
        self.assertEqual(prof["name_obfuscation"], "heavy")
        self.assertNotIn("light", prof["verdict"])
        self.assertEqual(prof["package_relocation"], "extensive")
        # a clean app with dictionary names under a real package → light/none
        clean = ["Lcom/example/player/VideoController;", "Lcom/example/ui/SettingsActivity;",
                 "Lcom/example/data/SubscriptionRepository;", "Lcom/example/net/ApiClient;"]
        self.assertIn("light", obfuscation_profile(clean, markers=[])["verdict"])

    def test_split_loading_is_not_dynamic_code(self):
        from autopsy.kb.markers import PROTECTIONS
        import re as _re
        pat = next(p[3] for p in PROTECTIONS if p[0] == "Dynamic code loading")
        rx = _re.compile(pat)
        self.assertFalse(rx.search("Ldalvik/system/PathClassLoader;-><init>(Ljava/lang/String;)V"))
        self.assertFalse(rx.search("Ldalvik/system/BaseDexClassLoader;-><init>(...)V"))
        self.assertTrue(rx.search("Ldalvik/system/DexClassLoader;-><init>(...)V"))
        self.assertTrue(rx.search("Ldalvik/system/InMemoryDexClassLoader;-><init>(...)V"))
