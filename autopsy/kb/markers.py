"""Ad / tracking / protection markers distilled from Android TV ad-delivery reverse-engineering.

Everything here is data; scoring lives in seams.py.
"""
import re

# ---------------------------------------------------------------- identifier tokens
# camelCase/snake tokens (lower-cased) and their weight when found in a METHOD name.
# Class-name hits count at half weight. Only whole tokens match, so "load"/"add"/"head"
# never hit "ad".
AD_TOKENS = {
    "ad": 3, "ads": 3, "adbreak": 6, "adbreaks": 6, "break": 1, "breaks": 1, "cue": 3, "cuepoint": 5,
    "cuepoints": 5, "pod": 3, "pods": 3, "preroll": 5, "midroll": 5, "postroll": 5, "interstitial": 4,
    "commercial": 4, "slate": 3, "ssai": 6, "dai": 5, "sgai": 6, "csai": 5, "stitcher": 5,
    "stitched": 4, "beacon": 4, "beacons": 4, "vast": 5, "vmap": 5, "pause": 1, "pausead": 6,
    "sponsor": 3, "sponsored": 3, "insertion": 4, "companionad": 4, "companionads": 4, "impression": 3, "quartile": 4,
    "tracking": 1, "tracker": 1, "overlay": 1, "creative": 3, "adpod": 6, "adbreakinfo": 6,
    "adplayback": 5, "adplaybackstate": 6, "admanager": 5, "adsmanager": 6, "adsloader": 6,
    "adevent": 5, "adtag": 5, "adschedule": 6, "scte": 5, "scte35": 6, "daterange": 4,
    "interstitials": 4, "freewheel": 5, "yospace": 5, "mediatailor": 5, "innovid": 5,
    "brightline": 4, "nielsen": 2, "moat": 2, "omid": 2, "adchoices": 4, "skippable": 3,
    "promo": 1, "promoted": 2, "adfree": 4, "adsupported": 4, "avod": 4,
}

# Split identifiers into tokens: getAdBreaks -> [get, ad, breaks]; AD_BREAK -> [ad, break]
_TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\d|\b|_|$)|[A-Z]?[a-z]+|[A-Z]+|\d+")


def tokens(name: str) -> list[str]:
    toks = [t.lower() for t in _TOKEN_RE.findall(name)]
    # also consider joined bigrams so AdBreak -> adbreak, CuePoint -> cuepoint
    joined = [toks[i] + toks[i + 1] for i in range(len(toks) - 1)]
    joined3 = [toks[i] + toks[i + 1] + toks[i + 2] for i in range(len(toks) - 2)]
    return toks + joined + joined3


# ---------------------------------------------------------------- strings
# (regex, weight, label). Applied to const-strings in method bodies.
AD_STRING_PATTERNS = [
    (r"(?i)\bad[_ ]?breaks?\b|adBreaks?", 6, "ad-break field/key"),
    (r"(?i)cue[_ ]?points?", 5, "cue points"),
    # Strict: protocol/markup forms only. Case-sensitive \bVAST\b (allcaps token) and the markup/path
    # forms — NOT a case-insensitive word, so English prose like "vast majority" is not matched (libcronet).
    (r"<VAST|VASTAdTagURI|/vast\b|vast\.xml|\bVAST\b", 5, "VAST"),
    (r"(?i)\bvmap\b|vmap:", 5, "VMAP"),
    (r"(?i)\bssai\b|serverSideAd|server[_ ]side[_ ]ad", 6, "SSAI"),
    (r"(?i)\bsgai\b|server[_ ]guided", 6, "SGAI"),
    (r"\bDAI\b|/dai/|daiUrl|DaiUrl|streamActivityMonitorId|/ondemand/hls/content/", 5, "DAI"),
    (r"(?i)stitcher|stitched", 4, "stitcher"),
    (r"(?i)scte[-_ ]?35|SCTE35-(OUT|IN|CMD)|EXT-X-CUE-(OUT|IN)|EXT-OATCLS-SCTE35|splice_?insert", 6, "SCTE-35 / cue tags"),
    (r"EXT-X-DATERANGE|com\.apple\.hls\.interstitial|X-ASSET-(URI|LIST)", 5, "HLS DateRange/interstitial"),
    (r"X-TV-TWITCH-AD|stitched-ad|twitch-ad", 6, "Twitch ad tags"),
    (r"(?i)pause[_ ]?ads?\b|pauseAd", 5, "pause ad"),
    (r"(?i)\bpre[-_ ]?roll|mid[-_ ]?roll|post[-_ ]?roll", 5, "roll position"),
    (r"(?i)\bad[_ ]?pod|podding|ad[_ ]?slot", 5, "ad pod"),
    (r"(?i)impression|quartile|firstQuartile|thirdQuartile|clickthrough|tracking[_ ]?events?", 3, "ad tracking"),
    (r"(?i)\bad[_-]?tag(url)?\b|adTagUrl|\bad[_-]?unit(id)?\b|adUnitId|[?&]iu=/", 5, "ad tag"),
    # Specific ad-interstitial identifiers are strong; bare "interstitial" (UI/navigation) is weak (see WEAK_AD_LABELS).
    (r"(?i)InterstitialAd|\bad[_ -]?interstitial|interstitialAd(Unit|Manager|Loader)?", 5, "ad interstitial"),
    (r"(?i)interstitial", 3, "interstitial"),
    (r"(?i)\bads?[_-]?(enabled|disabled|free|supported|tier|config|policy|decision|request|response|schedule|plan|timeline)\b", 5, "ad config flag"),
    (r"(?i)isAd(Disabled|Enabled|Free|Supported|Playing|Break)|shouldPlayAd|showAds?\b|hasAds?\b|canSkipAd", 6, "ad boolean"),
    (r"(?i)\bads?\b", 1, "\"ad\" word"),
    (r"(?i)getVideoAds|intraTitlePlaylist|regolith|getAdMetadata|adMetadata", 6, "known proprietary ad API"),
    (r"(?i)\bavod\b|\bad[-_ ]?supported|\bwith[-_ ]?ads\b", 3, "ad tier"),
    (r"(?i)beacon", 3, "beacon"),
    (r"(?i)freewheel|fwmrm|yospace|mediatailor|innovid|brightline\.tv|springserve|doubleclick\.net|imasdk", 5, "ad vendor"),
]
AD_STRING_RES = [(re.compile(p), w, label) for p, w, label in AD_STRING_PATTERNS]
# One combined pass first; only strings that hit it are tested per pattern.
AD_STRING_ANY = re.compile("|".join("(?:%s)" % p.replace("(?i)", "") for p, _, _ in AD_STRING_PATTERNS), re.I)


def ad_string_hits(val: str):
    if not AD_STRING_ANY.search(val):
        return []
    return [(w, label) for rx, w, label in AD_STRING_RES if rx.search(val)]

URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[a-z0-9.\-_]+(?::\d+)?(?:/[^\s\"'<>\\]*)?")
HOST_RE = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|io|tv|co|org|google|amazon|cloud|me|us|uk|app|link|ly)\b")

# ---------------------------------------------------------------- hosts
# host suffix -> (category, note). Categories mirror kb.sdks.
AD_HOSTS = {
    "doubleclick.net": ("ads", "Google Ad Manager / DFP (pubads.g.doubleclick.net = VAST tags)"),
    "googlesyndication.com": ("ads", "Google ads"),
    "googleadservices.com": ("ads", "Google ads"),
    "imasdk.googleapis.com": ("ads", "IMA SDK loader"),
    "dai.google.com": ("ssai", "Google DAI stream server"),
    "pubads.g.doubleclick.net": ("ads", "GAM VAST"),
    "fwmrm.net": ("ssai", "FreeWheel ad server"),
    "freewheel.tv": ("ssai", "FreeWheel"),
    "yospace.com": ("ssai", "Yospace"),
    "mediatailor.": ("ssai", "AWS MediaTailor"),
    "innovid.com": ("ads", "Innovid"),
    "brightline.tv": ("ads", "BrightLine"),
    "springserve.com": ("ads", "SpringServe"),
    "spotxchange.com": ("ads", "SpotX"),
    "spotx.tv": ("ads", "SpotX"),
    "amazon-adsystem.com": ("ads", "Amazon APS"),
    "aax.amazon-adsystem.com": ("ads", "Amazon APS"),
    "adsrvr.org": ("ads", "The Trade Desk"),
    "adnxs.com": ("ads", "Xandr"),
    "pubmatic.com": ("ads", "PubMatic"),
    "rubiconproject.com": ("ads", "Magnite"),
    "tremorhub.com": ("ads", "Tremor"),
    "teads.tv": ("ads", "Teads"),
    "moatads.com": ("verification", "Moat"),
    "adsafeprotected.com": ("verification", "IAS"),
    "doubleverify.com": ("verification", "DoubleVerify"),
    "imrworldwide.com": ("verification", "Nielsen"),
    "nielsen.com": ("verification", "Nielsen"),
    "scorecardresearch.com": ("verification", "comScore"),
    "conviva.com": ("analytics", "Conviva"),
    "newrelic.com": ("analytics", "New Relic"),
    "nr-data.net": ("analytics", "New Relic"),
    "adjust.com": ("attribution", "Adjust"),
    "adjust.io": ("attribution", "Adjust"),
    "adjust.net.in": ("attribution", "Adjust"),
    "adjust.world": ("attribution", "Adjust"),
    "appsflyer.com": ("attribution", "AppsFlyer"),
    "branch.io": ("attribution", "Branch"),
    "app-measurement.com": ("analytics", "Firebase/GA"),
    "crashlytics.com": ("analytics", "Crashlytics"),
    "segment.io": ("analytics", "Segment"),
    "amplitude.com": ("analytics", "Amplitude"),
    "mparticle.com": ("analytics", "mParticle"),
    "braze.com": ("analytics", "Braze"),
    "sentry.io": ("analytics", "Sentry"),
    "npaw.com": ("analytics", "NPAW"),
    "youboranqs01.com": ("analytics", "NPAW"),
    "mux.com": ("analytics", "Mux"),
    "litix.io": ("analytics", "Mux"),
    "media.max.com": ("ssai", "SSAI manifest origin (blocking it can be fatal mid-stream; prefer a clean variant)"),
    "gmss": ("ssai", "WBD GMSS ad origin"),
    "pluto.tv": ("platform", "Pluto TV stitcher host"),
    "unityads.unity3d.com": ("ads", "Unity Ads"),
    "applovin.com": ("ads", "AppLovin"),
}

# ---------------------------------------------------------------- protections (DEX strings / refs)
PROTECTIONS = [
    # (label, severity, kind, pattern, note)  kind: string | ref | class
    ("DexGuard CertCheck", "high", "string", r"CertCheck failed", "DexGuard signature check; crashes a re-signed APK."),
    ("Signature check", "med", "ref", r"Landroid/content/pm/PackageInfo;->(signatures|signingInfo)|Landroid/content/pm/SigningInfo;->", "Reads the app's own signing cert — re-signing may trip it. Patch the comparison or spoof the expected cert."),
    ("Play Integrity", "med", "ref", r"Lcom/google/android/play/core/integrity/", "Server-side verdict; not bytecode-beatable if enforced server-side."),
    ("SafetyNet", "med", "ref", r"Lcom/google/android/gms/safetynet/", ""),
    ("Root detection", "low", "string", r"/system/xbin/su|/sbin/su|Superuser\.apk|com\.topjohnwu\.magisk|test-keys|RootBeer|isRooted", ""),
    ("Frida/instrumentation detection", "med", "string", r"(?i)frida|gum-js-loop|linjector|xposed|de\.robv|substrate|\b27042\b", "Matters when you bench with Frida (native-adstrip-toolkit)."),
    ("Debugger detection", "low", "ref", r"Landroid/os/Debug;->isDebuggerConnected|TracerPid", ""),
    ("Emulator detection", "low", "string", r"(?i)goldfish|ranchu|generic_x86|sdk_gphone|Genymotion", ""),
    ("Certificate pinning (OkHttp)", "med", "ref", r"Lokhttp3/CertificatePinner", "Override certificate pinning to inspect traffic: empty the pinner / trust user CAs."),
    ("Certificate pins (sha256/)", "med", "string", r"^sha256/[A-Za-z0-9+/=]{43,44}$", ""),
    ("Custom TrustManager", "low", "ref", r"Ljavax/net/ssl/X509TrustManager;->checkServerTrusted", ""),
    # Only DexClassLoader / InMemoryDexClassLoader load code from an arbitrary (writable/network-derived)
    # path. PathClassLoader and BaseDexClassLoader are ordinary app + split/feature loading (createIsolated
    # SplitContext etc.) and are NOT evidence of downloaded DEX — flagging them produced false positives.
    ("Dynamic code loading", "med", "ref", r"Ldalvik/system/(DexClassLoader|InMemoryDexClassLoader);-><init>", "Loads DEX from an arbitrary path (hidden DEX in assets or downloaded at runtime). Check assets for embedded dex/jar/zip and whether the path is writable."),
    ("Native library loading", "info", "ref", r"Ljava/lang/System;->(loadLibrary|load)\(", ""),
    ("Reflection-heavy", "info", "ref", r"Ljava/lang/Class;->forName|Ljava/lang/reflect/Method;->invoke", ""),
    ("WebView JS bridge", "info", "ref", r"Landroid/webkit/WebView;->addJavascriptInterface", "WebView-based players — the request seam is shouldInterceptRequest."),
    ("In-app updates", "info", "ref", r"Lcom/google/android/play/core/appupdate/", "In-app auto-update prompts (commonly disabled by mods)."),
    ("Household / account-sharing checks", "info", "string", r"(?i)household|out[_ ]?of[_ ]?home|extra[_ ]?member|ooh_|verifyHousehold", "Often enforced server-side; may not be a client-side decision."),
    ("Widevine", "info", "string", r"edef8ba9-79d6-4ace-a3c8-27dcd51d21ed", "DRM — never needs touching for ad removal."),
]

# Packers / protectors recognised by native lib or asset names.
PACKER_FILES = [
    (r"libjiagu", "Qihoo 360 Jiagu packer"), (r"libsecexe|libsecmain", "Bangcle"),
    (r"libshella|libshellx", "Tencent Legu"), (r"libexec\.so|libexecmain", "Ijiami"),
    (r"libDexHelper", "SecNeo/DexHelper"), (r"libbaiduprotect", "Baidu protect"),
    (r"libprotectClass", "Unknown class protector"), (r"libshield\.so", "Promon SHIELD"),
    (r"libapp[Dd]ome|appdome", "Appdome"), (r"libarxan|libtfd", "Arxan/Digital.ai"),
    (r"libdexguard|libdg[a-z]*\.so", "DexGuard native"), (r"libnesec|libNetHTProtect", "NetEase protect"),
    (r"libpairipcore", "Google Play PairIP (license/anti-tamper)"), (r"libsgmain|libsgsecuritybody", "Alibaba SecurityGuard"),
]

# ---------------------------------------------------------------- native markers
NATIVE_ENGINES = [
    # (label, regex over strings/symbols, note)
    ("V8 JavaScript engine", r"(?:^|\W)v8::|V8 version|Isolate::New|v8_inspector", "JS VM inside the .so — ad logic may be JS text/bytecode loaded at runtime."),
    ("QuickJS", r"QuickJS|JS_NewRuntime|JS_Eval", "Player/timeline logic may run in a QuickJS VM."),
    ("Hermes", r"hermes::|HermesRuntime|facebook::hermes", ""),
    ("JavaScriptCore", r"JSGlobalContextCreate|JavaScriptCore", ""),
    ("WAMR / WebAssembly", r"wasm_runtime_|wamr|aot_|WASM_", "WebAssembly AoT runtime (can host an embedded ad/player engine)."),
    ("Flutter/Dart", r"Dart_|_kDartVmSnapshot|flutter", "Logic in libapp.so."),
    ("Unity / IL2CPP", r"il2cpp|UnityPlayer", ""),
    ("Rust", r"rust_panic|/rustc/|core::panicking", "Rust code (sometimes a downloaded .so)."),
    ("BoringSSL (static)", r"BoringSSL|boringssl|SSL_do_handshake", "TLS inside the lib — plaintext only visible after decrypt (memcpy seam)."),
    ("OpenSSL", r"OpenSSL \d|SSLeay", ""),
    ("libcurl", r"libcurl|CURLOPT_|curl_easy_", ""),
    ("zlib / inflate", r"inflateInit2?_|inflate ", "Pull seam candidate for compressed manifests."),
    ("Brotli", r"BrotliDecoder|brotli", "Brotli decompression (seen with downloaded .so.br payloads)."),
    ("Lua", r"lua_pcall|luaL_", ""),
    ("ShadowHook/Dobby/xHook (hooking)", r"shadowhook|DobbyHook|xhook_register|bhook", "Already hooked by the app/SDK."),
    ("Anti-debug", r"TracerPid|/proc/self/status|PTRACE_TRACEME|ptrace", ""),
    ("Frida detection", r"(?i)frida|gum-js-loop|linjector|\b27042\b", ""),
]

NATIVE_AD_PATTERNS = AD_STRING_PATTERNS  # reuse; applied to .so and asset strings

# Imports that make a good GOT/PLT "plaintext seam" (native interception taxonomy).
NATIVE_SEAM_IMPORTS = {
    "memcpy": "push seam (one-shot copy): edits must be same-length blanking; never touch a truncated payload",
    "memmove": "push seam variant",
    "SSL_read": "pull seam: can withhold & reassemble whole bodies (fix Content-Length if shrinking)",
    "inflate": "pull seam for gzip/deflate bodies",
    "BrotliDecoderDecompressStream": "pull seam for brotli bodies",
    "recv": "raw socket (still TLS ciphertext unless plain HTTP)",
    "read": "raw fd reads",
    "dlopen": "loads more libs at runtime (e.g. downloaded ad engine)",
    "android_dlopen_ext": "loads more libs at runtime",
    "__system_property_get": "device-property checks",
}

# JS/asset ad anchors worth quoting with context.
JS_AD_ANCHORS = re.compile(
    r"(?i)\b(getAdMetadata|adMetadata|adBreaks?|cuePoints?|pauseAds?|vast|vmap|ssai|sgai|"
    r"adPod|preroll|midroll|getVideoAds|intraTitlePlaylist|insertionPoints|adSchedule|"
    r"shouldShowAds?|isAdFree|adsEnabled|EXT-X-DATERANGE|SCTE35|X-TV-TWITCH-AD)\b")
