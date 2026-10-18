"""Optional external helpers. The autopsy itself needs none of these.

- jadx     : `autopsy java` decompiles ONE class (fast; only the dex that holds it).
- apktool  : full smali tree (for external smali diffing / drift checks).

`autopsy tools install` downloads pinned releases (SHA-256 checked) into ~/.apk-autopsy/tools.
Both need Java 11+ on PATH.
"""
from __future__ import annotations

import glob
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

HOME = os.path.join(os.path.expanduser("~"), ".apk-autopsy", "tools")
PINNED = {
    "jadx": ("https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip",
             "12fd966431903b8e15c36e5007f19343475be7d8f2a55f082e7a929eeabc937e"),
    "apktool": ("https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar",
                "c0350abbab5314248dfe2ee0c907def4edd14f6faef1f5d372d3d4abd28f0431"),
}
WIN = sys.platform.startswith("win")


def which() -> dict:
    jadx = os.environ.get("JADX") or shutil.which("jadx")
    local = os.path.join(HOME, "jadx", "bin", "jadx.bat" if WIN else "jadx")
    if not jadx and os.path.exists(local):
        jadx = local
    for cand in (r"E:\Tools\jadx\bin\jadx.bat", r"C:\Tools\jadx\bin\jadx.bat"):
        if not jadx and os.path.exists(cand):
            jadx = cand
    apktool = os.environ.get("APKTOOL_JAR")
    if not apktool and os.path.exists(os.path.join(HOME, "apktool.jar")):
        apktool = os.path.join(HOME, "apktool.jar")
    return {"java": shutil.which("java"), "jadx": jadx, "apktool": apktool or shutil.which("apktool")}


def _download(url, sha, dest):
    print(f"downloading {url}")
    tmp = dest + ".part"
    h = hashlib.sha256()
    with urllib.request.urlopen(url) as r, open(tmp, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            f.write(chunk)
    if h.hexdigest() != sha:
        os.remove(tmp)
        raise SystemExit(f"SHA-256 mismatch for {url}: got {h.hexdigest()}")
    os.replace(tmp, dest)


def install():
    os.makedirs(HOME, exist_ok=True)
    w = which()
    if not w["jadx"]:
        url, sha = PINNED["jadx"]
        z = os.path.join(HOME, "jadx.zip")
        _download(url, sha, z)
        with zipfile.ZipFile(z) as zf:
            zf.extractall(os.path.join(HOME, "jadx"))
        os.remove(z)
        if not WIN:
            os.chmod(os.path.join(HOME, "jadx", "bin", "jadx"), 0o755)
    if not w["apktool"]:
        url, sha = PINNED["apktool"]
        _download(url, sha, os.path.join(HOME, "apktool.jar"))
    if not shutil.which("java"):
        print("NOTE: jadx/apktool need Java 11+ on PATH (e.g. Temurin JDK).")


def jadx_cmd(jadx: str) -> list[str]:
    """Command prefix that runs jadx WITHOUT a shell.

    jadx.bat via cmd.exe would split on characters like `&` in paths (and is the BatBadBut
    argument-injection class of bug), so when the jadx-*-all.jar sits next to the launcher we
    run `java -cp <jar> jadx.cli.JadxCLI` directly.
    """
    home = os.path.dirname(os.path.dirname(os.path.abspath(jadx)))
    jars = sorted(glob.glob(os.path.join(home, "lib", "jadx-*-all.jar")))
    java = shutil.which("java")
    if jars and java:
        return [java, "-Xmx2g", "-cp", jars[-1], "jadx.cli.JadxCLI"]
    return [jadx]


def _run(cmd, **kw):
    # only a bare .bat/.cmd launcher (no jar found) needs the shell on Windows
    shell = WIN and cmd[0].lower().endswith((".bat", ".cmd"))
    return subprocess.run(cmd, shell=shell, **kw)


def jadx_class(out_dir, cls, tool=None):
    from .index import Index
    idx = Index(out_dir)
    row = idx.class_row(cls if cls.startswith("L") else "L" + cls.replace(".", "/") + ";")
    if not row:
        print("no such class in the index")
        return 1
    jadx = tool or which()["jadx"]
    if not jadx:
        print("jadx not found: run `autopsy tools install`, put jadx on PATH, or set JADX=<path to jadx(.bat)>")
        return 1
    (dex_path,) = idx.q("SELECT path FROM dexfiles WHERE id=?", row["dex"])[0]
    java_name = row["name"][1:-1].replace("/", ".")
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "out.java")
        cmd = jadx_cmd(jadx) + ["--single-class", java_name, "--single-class-output", out, "--no-debug-info",
                                "--show-bad-code", os.path.join(idx.root, dex_path)]
        r = _run(cmd, capture_output=True, text=True)
        if not os.path.exists(out):
            print(r.stdout[-2000:], r.stderr[-2000:])
            return 1
        with open(out, encoding="utf-8", errors="replace") as f:
            print(f.read())
    print("// NOTE: jadx invents names for obfuscated members — verify in smali (`autopsy show`) before "
          "writing a fingerprint.")
    return 0


def jadx_source(idx, cls, jadx=None):
    """Java source of one class (str) or None. Used by the scan for top classes."""
    jadx = jadx or which()["jadx"]
    row = idx.class_row(cls)
    if not jadx or not row:
        return None
    (dex_path,) = idx.q("SELECT path FROM dexfiles WHERE id=?", row["dex"])[0]
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "out.java")
        cmd = jadx_cmd(jadx) + ["--single-class", row["name"][1:-1].replace("/", "."), "--single-class-output", out,
                                "--show-bad-code", os.path.join(idx.root, dex_path)]
        try:
            _run(cmd, capture_output=True, text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if not os.path.exists(out):
            return None
        with open(out, encoding="utf-8", errors="replace") as f:
            return re.sub(r"/\* loaded from: .*?\*/\n", "", f.read())


def apktool_tree(apk, out_dir):
    jar = which()["apktool"]
    if not jar:
        raise SystemExit("apktool not found: run `autopsy tools install`")
    cmd = ["java", "-jar", jar, "d", "-f", "-r", "-o", out_dir, apk] if jar.endswith(".jar") else \
        [jar, "d", "-f", "-r", "-o", out_dir, apk]
    subprocess.run(cmd, check=True, shell=WIN and not jar.endswith(".jar"))
    return out_dir
