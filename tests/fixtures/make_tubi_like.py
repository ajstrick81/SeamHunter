#!/usr/bin/env python3
"""Generate a fully synthetic 'Tubi-like' streaming-app fixture (package com.example.streamtv).

It models the delivery paths the SeamHunter final-revisions brief needs to exercise end-to-end:
IMA client (CSAI), IMA DAI, Yospace SSAI (many vendor-internal classes -> dedup), media3
AdsMediaSource, pause ads, telemetry, and a regional debug-override chain (sudoCountryOverride /
mockRegion / OneTrust consent geoloc). No third-party code is included -- SDK types are empty
type-name stubs so the SDKs are only *detected* by name, exactly like the existing fixture.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.streamtv" android:versionCode="103650000" android:versionName="10.36.5000">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>
    <uses-feature android:name="android.software.leanback" android:required="false"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="com.google.android.gms.permission.AD_ID"/>
    <application android:label="@string/app_name" android:extractNativeLibs="true">
        <activity android:name="com.example.streamtv.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LEANBACK_LAUNCHER"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name="com.example.streamtv.debug.AppDebugSettingActivity" android:exported="false"/>
        <meta-data android:name="com.comscore.app.id" android:value="12345"/>
        <meta-data android:name="io.nielsen.app.sdk" android:value="on"/>
    </application>
</manifest>
"""
APKTOOL_YML = """version: 2.12.1
apkFileName: tubi_like.apk
usesFramework:
  ids:
  - 1
sdkInfo:
  minSdkVersion: 21
  targetSdkVersion: 34
packageInfo:
  forcedPackageId: 127
versionInfo:
  versionCode: 103650000
  versionName: 10.36.5000
"""
STRINGS = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Example Stream TV</string>
    <string name="ad_overlay_title">Advertisement</string>
</resources>
"""
PUBLIC = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <public type="string" name="app_name" id="0x7f010000" />
    <public type="string" name="ad_overlay_title" id="0x7f010001" />
</resources>
"""
DEBUG_PREFS = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="sudoCountryOverride">Default</string>
    <string name="mockRegion">control</string>
    <boolean name="debug_force_ads" value="false" />
</map>
"""
PLAYER_CONFIG = """{"ssai":{"provider":"yospace","sessionUrl":"https://csm-e.cds.yospace.com/csm/access"},
 "csai":{"adTagUrl":"https://pubads.g.doubleclick.net/gampad/ads?output=vast"},
 "dai":{"assetKey":"stream-123"},
 "regions":{"US":"US","GB":"UK","CA":"CA","AU":"AU","MX":"MX","default":"OTHER"}}
"""


def scaffold(proj):
    """Write the apktool project skeleton (manifest, resources, assets) around the smali tree."""
    os.makedirs(os.path.join(proj, "res", "values"), exist_ok=True)
    os.makedirs(os.path.join(proj, "assets"), exist_ok=True)
    for rel, text in [("AndroidManifest.xml", MANIFEST), ("apktool.yml", APKTOOL_YML),
                      ("res/values/strings.xml", STRINGS), ("res/values/public.xml", PUBLIC),
                      ("assets/debug_prefs_name.xml", DEBUG_PREFS), ("assets/player_config.json", PLAYER_CONFIG)]:
        with open(os.path.join(proj, rel.replace("/", os.sep)), "w", encoding="utf-8") as fh:
            fh.write(text)


PROJ = sys.argv[1] if len(sys.argv) > 1 else os.path.join(tempfile.mkdtemp(prefix="tubi-fixture-"), "tubi")
os.makedirs(PROJ, exist_ok=True)
scaffold(PROJ)
SMALI = os.path.join(PROJ, "smali")


def w(path, text):
    full = os.path.join(SMALI, path.replace("/", os.sep) + ".smali")
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(text.lstrip("\n"))


def stub(desc, *, interface=False, super_="Ljava/lang/Object;", interfaces=()):
    """An empty type-name stub: present by name, carries no compiled vendor code."""
    kind = "public interface abstract" if interface else "public"
    lines = [f".class {kind} L{desc};", f".super {super_}"]
    for i in interfaces:
        lines.append(f".implements L{i};")
    lines.append(".source \"stub\"")
    return "\n".join(lines) + "\n"


def cls(desc, *, super_="Ljava/lang/Object;", interfaces=(), source=None, fields=(), methods=()):
    src = source or (desc.rsplit("/", 1)[-1] + ".java")
    lines = [f".class public L{desc};", f".super {super_}", f".source \"{src}\""]
    for i in interfaces:
        lines.append(f".implements L{i};")
    lines.append("")
    for f in fields:
        lines.append(f".field {f}")
    lines.append("")
    lines.append(".method public constructor <init>()V")
    lines.append("    .locals 0")
    lines.append(f"    invoke-direct {{p0}}, {super_}-><init>()V")
    lines.append("    return-void")
    lines.append(".end method")
    lines.append("")
    for m in methods:
        lines.append(m)
        lines.append("")
    return "\n".join(lines) + "\n"


def filler(n, startreg=0):
    """n harmless instructions (const/add) to pad an obfuscated void method past the insns gate."""
    out = []
    for i in range(n):
        out.append(f"    const/4 v0, 0x{(i % 8):x}" if i % 2 == 0 else f"    add-int/lit8 v0, v0, 0x1")
    return "\n".join(out)


# ---------------------------------------------------------------- SDK type-name stubs (no code)
IMA = "com/google/ads/interactivemedia/v3/api"
IMA_PLAYER = "com/google/ads/interactivemedia/v3/api/player"
for d in [f"{IMA}/AdsLoader", f"{IMA}/AdsManager", f"{IMA}/BaseManager", f"{IMA}/ImaSdkFactory",
          f"{IMA}/StreamRequest", f"{IMA}/StreamManager", f"{IMA}/AdEvent", f"{IMA}/AdEvent$AdEventType",
          f"{IMA}/AdErrorEvent", f"{IMA}/AdsManagerLoadedEvent"]:
    w(d, stub(d))
for d in [f"{IMA}/AdEvent$AdEventListener", f"{IMA}/AdErrorEvent$AdErrorListener",
          f"{IMA_PLAYER}/VideoStreamPlayer", f"{IMA}/AdsLoader$AdsLoadedListener"]:
    w(d, stub(d, interface=True))

# media3 stubs
for d in ["androidx/media3/exoplayer/source/ads/AdsMediaSource",
          "androidx/media3/common/AdPlaybackState",
          "androidx/media3/exoplayer/source/MediaSource"]:
    w(d, stub(d))

# Yospace SSAI: many vendor-internal classes -> a subsystem that must be summarized, not enumerated.
YO = "com/yospace/admanagement"
for n in ["Session", "SessionLive", "SessionVOD", "AdBreak", "Advert", "AdvertWrapper", "AnalyticEventObserver",
          "PlaybackPolicy", "PlaybackPolicyHandler", "ResourceSource", "TrackingErrors", "VastPayload",
          "Stream", "EventMachine", "PollingResponseHandler", "SessionProperties", "ManagementApi"]:
    w(f"{YO}/{n}", stub(f"{YO}/{n}"))
w(f"{YO}/AnalyticEventObserver", stub(f"{YO}/AnalyticEventObserver", interface=True))

# FreeWheel + OneTrust (consent) type names
w("tv/freewheel/ad/AdManager", stub("tv/freewheel/ad/AdManager"))
w("com/onetrust/otpublishers/headless/Public/OTPublishersHeadlessSDK",
  stub("com/onetrust/otpublishers/headless/Public/OTPublishersHeadlessSDK"))

# comScore / Nielsen (telemetry) type names
w("com/comscore/Analytics", stub("com/comscore/Analytics"))
w("com/nielsen/app/sdk/AppSdk", stub("com/nielsen/app/sdk/AppSdk"))

# ---------------------------------------------------------------- app classes (com.example.streamtv)
APP = "com/example/streamtv"

# DAI: app-owned stream-id / DAI-url request boundary  (brief: FoxImaStreamIdLoader)
w(f"{APP}/player/FoxImaStreamIdLoader", cls(f"{APP}/player/FoxImaStreamIdLoader", methods=[
    """
.method public requestImaStreamId(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    const-string v0, "https://dai.google.com/ondemand/v1/streamid"
    return-object v0
.end method""",
    """
.method public requestVODDAIUrl(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    const-string v0, "https://pubads.g.doubleclick.net/ondemand/dash/content/vod/stream"
    return-object v0
.end method""",
]))

# DAI: app VideoStreamPlayer impl (adapter + break detection)
w(f"{APP}/player/FoxImaVideoStreamPlayer", cls(
    f"{APP}/player/FoxImaVideoStreamPlayer",
    interfaces=[f"{IMA_PLAYER}/VideoStreamPlayer"], methods=[
        """
.method public loadUrl(Ljava/lang/String;Ljava/util/List;)V
    .locals 0
    return-void
.end method""",
        """
.method public onAdBreakStarted()V
    .locals 1
    const-string v0, "ad break started"
    return-void
.end method""",
        """
.method public onAdBreakEnded()V
    .locals 0
    return-void
.end method""",
    ]))

# break-start dispatcher (brief: FoxPlayer.dispatchAdPodStart)
w(f"{APP}/player/FoxPlayer", cls(f"{APP}/player/FoxPlayer", methods=[
    """
.method public dispatchAdPodStart(I)V
    .locals 0
    return-void
.end method""",
    """
.method public seekOverAd(J)V
    .locals 0
    return-void
.end method""",
]))

# CSAI: app requests client VAST ads + reads cue points
w(f"{APP}/ads/CsaiAdsRequester", cls(f"{APP}/ads/CsaiAdsRequester", methods=[
    """
.method public requestAds(Lcom/google/ads/interactivemedia/v3/api/AdsLoader;Ljava/lang/String;)V
    .locals 1
    const-string v0, "https://pubads.g.doubleclick.net/gampad/ads?output=vast"
    invoke-virtual {p1, p2}, Lcom/google/ads/interactivemedia/v3/api/AdsLoader;->requestAds(Ljava/lang/String;)V
    return-void
.end method""",
]))

# CSAI scheduling: ad-schedule accessor + AdsLoaded listener (gated)
w(f"{APP}/ads/AdScheduleProvider", cls(
    f"{APP}/ads/AdScheduleProvider",
    interfaces=[f"{IMA}/AdsLoader$AdsLoadedListener"],
    fields=["private cuePoints:Ljava/util/List;"], methods=[
        """
.method public getAdBreaks()Ljava/util/List;
    .locals 1
    iget-object v0, p0, Lcom/example/streamtv/ads/AdScheduleProvider;->cuePoints:Ljava/util/List;
    return-object v0
.end method""",
        """
.method public onAdsManagerLoaded(Lcom/google/ads/interactivemedia/v3/api/AdsManagerLoadedEvent;)V
    .locals 1
    invoke-interface {p1}, Lcom/google/ads/interactivemedia/v3/api/AdsManagerLoadedEvent;->getAdsManager()Lcom/google/ads/interactivemedia/v3/api/AdsManager;
    move-result-object v0
    return-void
.end method""",
        """
.method public isAdsEnabled()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method""",
    ]))

# media3: app wraps content in AdsMediaSource
w(f"{APP}/player/ContentMediaSourceFactory", cls(f"{APP}/player/ContentMediaSourceFactory", methods=[
    """
.method public wrapWithAds(Landroidx/media3/exoplayer/source/MediaSource;)Landroidx/media3/exoplayer/source/ads/AdsMediaSource;
    .locals 1
    new-instance v0, Landroidx/media3/exoplayer/source/ads/AdsMediaSource;
    invoke-direct {v0}, Landroidx/media3/exoplayer/source/ads/AdsMediaSource;-><init>()V
    return-object v0
.end method""",
]))

# resume/fallback: IMA AdError listener
w(f"{APP}/ads/ImaAdErrorHandler", cls(
    f"{APP}/ads/ImaAdErrorHandler",
    interfaces=[f"{IMA}/AdErrorEvent$AdErrorListener"], methods=[
        """
.method public onAdError(Lcom/google/ads/interactivemedia/v3/api/AdErrorEvent;)V
    .locals 1
    const-string v0, "ad error - resume content"
    return-void
.end method""",
    ]))

# pause ads: UI class with an obfuscated render method 'm' (brief: ImagePauseAds.m)
w(f"{APP}/ads/ImagePauseAds", cls(f"{APP}/ads/ImagePauseAds", methods=[
    f"""
.method public m(Landroid/view/View;)V
    .locals 1
    const-string v0, "pauseAd shown"
{filler(24)}
    return-void
.end method""",
    """
.method public hidePauseAd()V
    .locals 0
    return-void
.end method""",
]))

# ---------------------------------------------------------------- regional controls (OBFUSCATED chain)
# Models the real-Tubi sudoCountryOverride chain under R8 renaming: the getter is `u()`, the setter
# `e0()`, the consumer `e()`, the comparator `p()` — none readable. Reconstruction must follow the key
# STRING + SharedPreferences / field edges, not the names. (See brief: data-flow correlation.)

# LWh/b;  — stores the override in field `a`, read via SharedPreferences.getString, written via putString
w("Wh/b", """
.class public LWh/b;
.super Ljava/lang/Object;
.source "b.java"

.field private a:Ljava/lang/String;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public u(Landroid/content/SharedPreferences;)Ljava/lang/String;
    .locals 2
    const-string v0, "sudoCountryOverride"
    const-string v1, "Default"
    invoke-interface {p1, v0, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    iput-object v0, p0, LWh/b;->a:Ljava/lang/String;
    return-object v0
.end method

.method public e0(Landroid/content/SharedPreferences;Ljava/lang/String;)V
    .locals 2
    invoke-virtual {p2}, Ljava/lang/String;->toUpperCase()Ljava/lang/String;
    move-result-object p2
    iput-object p2, p0, LWh/b;->a:Ljava/lang/String;
    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    const-string v1, "sudoCountryOverride"
    invoke-interface {v0, v1, p2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V
    return-void
.end method
""")

# Lbi/q$a;  — RemoteConfig.getCountryCode(): consumes the override getter by edge (calls LWh/b;->u)
w("bi/q$a", """
.class public Lbi/q$a;
.super Ljava/lang/Object;
.source "q.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public e()Ljava/lang/String;
    .locals 2
    new-instance v0, LWh/b;
    invoke-direct {v0}, LWh/b;-><init>()V
    const/4 v1, 0x0
    invoke-virtual {v0, v1}, LWh/b;->u(Landroid/content/SharedPreferences;)Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
""")

# LUh/g;  — isCountry(): compares the country code (references region value "US"); caller of the consumer
w("Uh/g", """
.class public LUh/g;
.super Ljava/lang/Object;
.source "g.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public p(Ljava/lang/String;)Z
    .locals 2
    new-instance v0, Lbi/q$a;
    invoke-direct {v0}, Lbi/q$a;-><init>()V
    invoke-virtual {v0}, Lbi/q$a;->e()Ljava/lang/String;
    move-result-object v0
    const-string v1, "US"
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1
    return v1
.end method
""")

# LXk/a;  — experiment region (mockRegion), a separate key: must NOT be merged with the country override
w("Xk/a", """
.class public LXk/a;
.super Ljava/lang/Object;
.source "a.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public r(Landroid/content/SharedPreferences;)Ljava/lang/String;
    .locals 2
    const-string v0, "mockRegion"
    const-string v1, "control"
    invoke-interface {p1, v0, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
""")

# SSAI: app session manager that drives Yospace (many vendor-internal call sites -> dedup to 1 summary)
_yo_calls = "\n".join(
    f"""    new-instance v0, L{YO}/{n};
    invoke-direct {{v0}}, L{YO}/{n};-><init>()V"""
    for n in ["Session", "AdBreak", "Advert", "PlaybackPolicy", "VastPayload", "Stream",
              "EventMachine", "TrackingErrors", "SessionProperties", "ResourceSource"])
w(f"{APP}/ssai/SsaiSessionManager", cls(f"{APP}/ssai/SsaiSessionManager", methods=[
    f"""
.method public startSession(Ljava/lang/String;)V
    .locals 1
    const-string v0, "https://csm-e.cds.yospace.com/csm/access"
{_yo_calls}
    return-void
.end method""",
    """
.method public getSsaiConfig()Ljava/lang/String;
    .locals 1
    const-string v0, "yospace ssai config"
    return-object v0
.end method""",
]))

# ---------------------------------------------------------------- telemetry
w(f"{APP}/analytics/ComscoreTracker", cls(f"{APP}/analytics/ComscoreTracker", methods=[
    """
.method public fireAdImpression()V
    .locals 1
    const-string v0, "https://sb.scorecardresearch.com/b?c1=1"
    return-void
.end method""",
    """
.method public trackQuartile(I)V
    .locals 0
    return-void
.end method""",
]))

print("smali classes written under", SMALI)

# Build with apktool into tests/fixtures/tubi_like.apk (needs `apktool` and Java 11+ on PATH).
import shutil  # noqa: E402

_out = os.path.join(HERE, "tubi_like.apk")
_apktool = shutil.which("apktool") or shutil.which("apktool.bat") or shutil.which("apktool.cmd")
try:
    if not _apktool:
        raise FileNotFoundError("apktool not on PATH")
    # a .bat/.cmd shim needs the shell on Windows; a bare launcher does not
    shell = _apktool.lower().endswith((".bat", ".cmd"))
    subprocess.run([_apktool, "b", "-f", "-o", _out, PROJ], check=True, shell=shell)
    print("built", _out)
except (FileNotFoundError, subprocess.CalledProcessError) as e:
    print(f"apktool build skipped ({e}); run: apktool b -f -o {_out} {PROJ}")
