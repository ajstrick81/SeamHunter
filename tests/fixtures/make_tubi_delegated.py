#!/usr/bin/env python3
"""Second synthetic regional fixture: a **Kotlin delegated property** country override.

Models the real-Tubi structure the direct-field fixture does not reproduce: the property name string
lives only in `<clinit>` (KProperty metadata), and the obfuscated getter `u()` / setter `e0()` reach
the value through a *delegate field* (`LWh/b;->s`) and a `KProperty[]` slot via
`getValue`/`setValue` — not through a direct field or SharedPreferences call. The regional detector
must reconstruct the chain from the delegate field + Kotlin accessor edges, and must NOT classify
`<clinit>` as the setter. Fully synthetic (`com.example.streamtv2`), no third-party code.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.streamtv2" android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>
    <uses-feature android:name="android.software.leanback" android:required="false"/>
    <application android:label="@string/app_name">
        <activity android:name="com.example.streamtv2.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LEANBACK_LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
APKTOOL_YML = """version: 2.12.1
apkFileName: tubi_delegated.apk
usesFramework:
  ids:
  - 1
sdkInfo:
  minSdkVersion: 21
  targetSdkVersion: 34
packageInfo:
  forcedPackageId: 127
versionInfo:
  versionCode: 1
  versionName: 1.0
"""
STRINGS = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Delegated Fixture</string>
</resources>
"""
PUBLIC = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <public type="string" name="app_name" id="0x7f010000" />
</resources>
"""

SMALI = {
    # the delegate instance type (holds a String value)
    "Wh/c": """
.class public LWh/c;
.super Ljava/lang/Object;
.source "c.java"

.field private v:Ljava/lang/String;

.method public constructor <init>(Ljava/lang/String;)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, LWh/c;->v:Ljava/lang/String;
    return-void
.end method
""",
    # the delegate HELPER family (obfuscated get/set — NOT literally named getValue/setValue)
    "Wh/d": """
.class public LWh/d;
.super Ljava/lang/Object;
.source "d.java"

.method public static c(LWh/c;Lkotlin/reflect/KProperty;)Ljava/lang/Object;
    .locals 1
    const-string v0, "x"
    return-object v0
.end method

.method public static d(LWh/c;Lkotlin/reflect/KProperty;Ljava/lang/String;)V
    .locals 0
    return-void
.end method
""",
    # the owner: <clinit> carries each property's name + getter-signature metadata into the (renamed)
    # KProperty[] array `b`; <init> seeds the delegates. THREE delegated properties live here:
    #   sudoCountryOverride -> u()/e0() via delegate field s   (the one we want)
    #   someOtherSetting    -> v()/f0() via delegate field t   (unrelated String property)
    #   a Lazy<File>        -> s()      via field d            (decoy; returns File)
    # The detector must bind "sudoCountryOverride" to u()/e0() via the getter-signature, not pick any
    # delegated/Lazy accessor it finds.
    "Wh/b": """
.class public LWh/b;
.super Ljava/lang/Object;
.source "b.java"

.field static b:[Lkotlin/reflect/KProperty;
.field private final s:LWh/c;
.field private final t:LWh/c;
.field private final d:Lkotlin/Lazy;

.method static constructor <clinit>()V
    .locals 6
    const/4 v0, 0x3
    new-array v0, v0, [Lkotlin/reflect/KProperty;
    const-class v2, LWh/b;
    # country property at slot 0 — metadata keeps the ORIGINAL name; the method is renamed to u()
    new-instance v1, Lkotlin/jvm/internal/x;
    const-string v3, "sudoCountryOverride"
    const-string v4, "getSudoCountryOverride()Ljava/lang/String;"
    invoke-direct {v1, v2, v3, v4}, Lkotlin/jvm/internal/x;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;)V
    const/4 v5, 0x0
    aput-object v1, v0, v5
    # unrelated String property at slot 1 — method renamed to v()
    new-instance v1, Lkotlin/jvm/internal/x;
    const-string v3, "someOtherSetting"
    const-string v4, "getSomeOtherSetting()Ljava/lang/String;"
    invoke-direct {v1, v2, v3, v4}, Lkotlin/jvm/internal/x;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;)V
    const/4 v5, 0x1
    aput-object v1, v0, v5
    sput-object v0, LWh/b;->b:[Lkotlin/reflect/KProperty;
    return-void
.end method

.method public constructor <init>()V
    .locals 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    new-instance v0, LWh/c;
    const-string v1, ""
    invoke-direct {v0, v1}, LWh/c;-><init>(Ljava/lang/String;)V
    iput-object v0, p0, LWh/b;->t:LWh/c;
    new-instance v0, LWh/c;
    const-string v1, "Default"
    invoke-direct {v0, v1}, LWh/c;-><init>(Ljava/lang/String;)V
    iput-object v0, p0, LWh/b;->s:LWh/c;
    return-void
.end method

.method public u()Ljava/lang/String;
    .locals 3
    iget-object v0, p0, LWh/b;->s:LWh/c;
    sget-object v1, LWh/b;->b:[Lkotlin/reflect/KProperty;
    const/4 v2, 0x0
    aget-object v1, v1, v2
    invoke-static {v0, v1}, LWh/d;->c(LWh/c;Lkotlin/reflect/KProperty;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Ljava/lang/String;
    return-object v0
.end method

.method public e0(Ljava/lang/String;)V
    .locals 3
    iget-object v0, p0, LWh/b;->s:LWh/c;
    sget-object v1, LWh/b;->b:[Lkotlin/reflect/KProperty;
    const/4 v2, 0x0
    aget-object v1, v1, v2
    invoke-static {v0, v1, p1}, LWh/d;->d(LWh/c;Lkotlin/reflect/KProperty;Ljava/lang/String;)V
    return-void
.end method

.method public v()Ljava/lang/String;
    .locals 3
    iget-object v0, p0, LWh/b;->t:LWh/c;
    sget-object v1, LWh/b;->b:[Lkotlin/reflect/KProperty;
    const/4 v2, 0x1
    aget-object v1, v1, v2
    invoke-static {v0, v1}, LWh/d;->c(LWh/c;Lkotlin/reflect/KProperty;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Ljava/lang/String;
    return-object v0
.end method

.method public f0(Ljava/lang/String;)V
    .locals 3
    iget-object v0, p0, LWh/b;->t:LWh/c;
    sget-object v1, LWh/b;->b:[Lkotlin/reflect/KProperty;
    const/4 v2, 0x1
    aget-object v1, v1, v2
    invoke-static {v0, v1, p1}, LWh/d;->d(LWh/c;Lkotlin/reflect/KProperty;Ljava/lang/String;)V
    return-void
.end method

.method public s()Ljava/io/File;
    .locals 1
    iget-object v0, p0, LWh/b;->d:Lkotlin/Lazy;
    invoke-interface {v0}, Lkotlin/Lazy;->getValue()Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Ljava/io/File;
    return-object v0
.end method
""",
    # RemoteConfig.getCountryCode(): calls the override getter u() and compares with "Default"
    "bi/q$a": """
.class public Lbi/q$a;
.super Ljava/lang/Object;
.source "q.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public e()Ljava/lang/String;
    .locals 3
    new-instance v0, LWh/b;
    invoke-direct {v0}, LWh/b;-><init>()V
    invoke-virtual {v0}, LWh/b;->u()Ljava/lang/String;
    move-result-object v0
    const-string v1, "Default"
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    return-object v0
.end method
""",
    # isCountry(): calls the RemoteConfig method and compares a region value ("US")
    "Uh/g": """
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
    const-string v1, "countryCode"
    invoke-static {p1, v1}, Lkotlin/jvm/internal/r;->h(Ljava/lang/Object;Ljava/lang/String;)V
    invoke-static {p1, v0}, Lkotlin/jvm/internal/r;->c(Ljava/lang/Object;Ljava/lang/Object;)Z
    move-result v1
    return v1
.end method
""",
}


def build_project(proj):
    os.makedirs(os.path.join(proj, "res", "values"), exist_ok=True)
    smali_dir = os.path.join(proj, "smali")
    for rel, text in [("AndroidManifest.xml", MANIFEST), ("apktool.yml", APKTOOL_YML),
                      ("res/values/strings.xml", STRINGS), ("res/values/public.xml", PUBLIC)]:
        with open(os.path.join(proj, rel.replace("/", os.sep)), "w", encoding="utf-8") as fh:
            fh.write(text)
    for path, body in SMALI.items():
        full = os.path.join(smali_dir, path.replace("/", os.sep) + ".smali")
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(body.lstrip("\n"))


PROJ = sys.argv[1] if len(sys.argv) > 1 else os.path.join(tempfile.mkdtemp(prefix="tubi-delegated-"), "d")
os.makedirs(PROJ, exist_ok=True)
build_project(PROJ)
print("project written to", PROJ)

_out = os.path.join(HERE, "tubi_delegated.apk")
_apktool = shutil.which("apktool") or shutil.which("apktool.bat") or shutil.which("apktool.cmd")
try:
    if not _apktool:
        raise FileNotFoundError("apktool not on PATH")
    shell = _apktool.lower().endswith((".bat", ".cmd"))
    subprocess.run([_apktool, "b", "-f", "-o", _out, PROJ], check=True, shell=shell)
    print("built", _out)
except (FileNotFoundError, subprocess.CalledProcessError) as e:
    print(f"apktool build skipped ({e}); run: apktool b -f -o {_out} {PROJ}")
