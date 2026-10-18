"""`autopsy update` — install a newer apk-autopsy zip over this install, keeping a backup.

    autopsy update                 newest apk-autopsy*.zip in ~/Downloads (or pass a path)
    autopsy update --rollback      restore the previous version
    autopsy version                show installed version and install path

Backups live in <install>/../versions/. Results folders (*.autopsy) and ~/.apk-autopsy/tools
are never touched.
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

from . import __version__

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # folder holding autopsy/
VERSIONS = os.path.join(os.path.dirname(APP_DIR), "versions")
PAYLOAD = ("autopsy", "tests", "docs", "assets", "README.md", "CHANGELOG.md", "autopsy_main.py", "autopsy.bat",
           "autopsy.sh", "pyproject.toml", "install.ps1", "install.cmd", ".gitignore")


def _ver(s: str):
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])


def _zip_version(zf: zipfile.ZipFile):
    for n in zf.namelist():
        if n.endswith("autopsy/__init__.py") and n.count("/") <= 2:
            m = re.search(r'__version__\s*=\s*"([^"]+)"', zf.read(n).decode("utf-8", "replace"))
            if m:
                return m.group(1), n[: -len("autopsy/__init__.py")]
    return None, None


def find_zip(path=None):
    if path:
        return path
    dl = os.path.join(os.path.expanduser("~"), "Downloads")
    cands = sorted(glob.glob(os.path.join(dl, "apk-autopsy*.zip")), key=os.path.getmtime, reverse=True)
    if not cands:
        raise SystemExit(f"no apk-autopsy*.zip in {dl} — download the new version or pass its path")
    return cands[0]


def _backup():
    os.makedirs(VERSIONS, exist_ok=True)
    dest = os.path.join(VERSIONS, f"{__version__}-{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(dest)
    for item in PAYLOAD:
        src = os.path.join(APP_DIR, item)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(dest, item), ignore=shutil.ignore_patterns("__pycache__"))
        elif os.path.isfile(src):
            shutil.copy2(src, dest)
    return dest


def _install_from(root):
    for item in PAYLOAD:
        src = os.path.join(root, item)
        dst = os.path.join(APP_DIR, item)
        if not os.path.exists(src):
            continue
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        if os.path.isdir(src):
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, dst)


def _git_commit(msg):
    if shutil.which("git") and os.path.isdir(os.path.join(APP_DIR, ".git")):
        subprocess.run(["git", "-C", APP_DIR, "add", "-A"], capture_output=True)
        subprocess.run(["git", "-C", APP_DIR, "commit", "-q", "-m", msg], capture_output=True)


def _selftest():
    r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"], cwd=APP_DIR,
                       capture_output=True, text=True)
    ok = r.returncode == 0
    print("self-test:", "OK" if ok else "FAILED\n" + r.stderr[-1500:])
    return ok


def update(path=None, force=False):
    z = find_zip(path)
    with zipfile.ZipFile(z) as zf:
        new, prefix = _zip_version(zf)
        if not new:
            raise SystemExit(f"{z} does not look like an apk-autopsy release")
        if _ver(new) <= _ver(__version__) and not force:
            print(f"installed {__version__} is already >= {new} ({os.path.basename(z)}). Use --force to reinstall.")
            return 0
        with tempfile.TemporaryDirectory() as td:
            zf.extractall(td)
            root = os.path.join(td, prefix) if prefix else td
            bak = _backup()
            _install_from(root)
    print(f"updated {__version__} -> {new}  (backup: {bak})")
    _git_commit(f"update to {new} from {os.path.basename(z)}")
    if not _selftest():
        print("Self-test failed — `autopsy update --rollback` restores the previous version.")
        return 1
    return 0


def rollback():
    if not os.path.isdir(VERSIONS):
        raise SystemExit("no backups yet")
    backups = sorted(os.listdir(VERSIONS), key=lambda d: os.path.getmtime(os.path.join(VERSIONS, d)), reverse=True)
    if not backups:
        raise SystemExit("no backups yet")
    src = os.path.join(VERSIONS, backups[0])
    _install_from(src)
    shutil.rmtree(src)
    _git_commit(f"rollback to {backups[0]}")
    print(f"rolled back to {backups[0]}")
    return 0


def version():
    print(f"apk-autopsy {__version__}\ninstall: {APP_DIR}\nbackups: {VERSIONS}")
    return 0
