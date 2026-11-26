"""Open .apk / .apkm / .xapk / .apks / .zip bundles and expose every split as a zip.

APKMirror's .apkm is a zip of split APKs plus info.json (old releases were encrypted
for the APKMirror Installer; those are detected and reported, not guessed at).
XAPK is a zip of splits (or one APK) plus manifest.json and sometimes OBBs.
"""
from __future__ import annotations

import io
import json
import os
import zipfile
import zlib
from dataclasses import dataclass, field

DEX_MAGIC = b"dex\n"
# Nested splits are decompressed into memory. Real splits are stored or barely compressible
# (an APK is already a zip), so a split that inflates far past its stored size is a zip bomb.
MAX_SPLIT_BYTES = 4 << 30      # 4 GiB: well past any real split
BOMB_MIN_BYTES = 256 << 20     # only judge the ratio once a split would exceed 256 MiB
BOMB_RATIO = 50
# What zipfile/zlib raise for a damaged archive or entry (bad CRC or central directory, truncated
# stream, unsupported version/method, corrupt deflate data).
ZIP_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, ValueError, NotImplementedError, OverflowError,
              RuntimeError, OSError)


@dataclass
class Split:
    name: str            # "base.apk", "split_config.armeabi_v7a.apk", ...
    zf: zipfile.ZipFile
    size: int

    def names(self):
        return self.zf.namelist()

    def read(self, name: str) -> bytes:
        return self.zf.read(name)


@dataclass
class Bundle:
    path: str
    kind: str                       # apk | apkm | xapk | apks | zip
    splits: list[Split] = field(default_factory=list)
    info: dict = field(default_factory=dict)   # info.json / manifest.json
    warnings: list[str] = field(default_factory=list)
    extra_files: list[str] = field(default_factory=list)

    @property
    def base(self) -> Split:
        for s in self.splits:
            if s.name in ("base.apk",) or s.name.endswith("/base.apk"):
                return s
        # the split holding AndroidManifest + classes.dex is the base
        for s in self.splits:
            n = set(s.names())
            if "classes.dex" in n and "AndroidManifest.xml" in n:
                return s
        return self.splits[0]

    def dex_entries(self):
        """(split, entry-name) for every classes*.dex in every split, base first."""
        base = self.base
        order = sorted(self.splits, key=lambda s: s is not base)
        for s in order:
            for n in sorted(s.names(), key=_dex_sort):
                if n.startswith("classes") and n.endswith(".dex") and "/" not in n:
                    yield s, n

    def iter_files(self):
        """(split, entry) for every file in every split."""
        for s in self.splits:
            for zi in s.zf.infolist():
                if not zi.is_dir():
                    yield s, zi


def _dex_sort(n: str):
    if n == "classes.dex":
        return 0
    digits = "".join(c for c in n if c.isdigit())
    return int(digits) if digits else 999


def _is_zip(data_or_path) -> bool:
    try:
        if isinstance(data_or_path, (bytes, bytearray)):
            return zipfile.is_zipfile(io.BytesIO(data_or_path))
        return zipfile.is_zipfile(data_or_path)
    except OSError:
        return False


def open_bundle(path: str) -> Bundle:
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if not os.path.isfile(path):
        raise SystemExit(f"No such file: {path}")
    size = os.path.getsize(path)
    if not _is_zip(path):
        with open(path, "rb") as f:
            head = f.read(16)
        b = Bundle(path=path, kind=ext or "unknown")
        if head.startswith(DEX_MAGIC):
            raise SystemExit(f"{path} is a bare DEX file; wrap it or pass the APK instead")
        if size == 0:
            raise SystemExit(f"{path} is empty (0 bytes) — the download probably failed; download it again.")
        if head.startswith(b"PK"):
            raise SystemExit(f"{path} is a damaged/incomplete zip ({size:,} bytes) — the download was probably cut off; "
                             f"download it again.")
        b.warnings.append(
            "Not a zip. Older APKMirror .apkm files are encrypted for the APKMirror Installer; "
            "re-download the current release (plain zip) or export the installed splits with "
            "`adb shell pm path <pkg>` + `adb pull`.")
        raise SystemExit(b.warnings[0])
    outer = zipfile.ZipFile(path)
    names = outer.namelist()
    if "AndroidManifest.xml" in names:
        return Bundle(path=path, kind="apk", splits=[Split(os.path.basename(path), outer, size)])
    b = Bundle(path=path, kind=ext if ext in ("apkm", "xapk", "apks") else "zip")
    for meta in ("info.json", "manifest.json"):
        if meta in names:
            try:
                b.info = json.loads(outer.read(meta).decode("utf-8", "replace"))
            except ValueError:
                b.warnings.append(f"{meta} is not valid JSON")
    for n in names:
        if n.lower().endswith(".apk"):
            zi = outer.getinfo(n)
            if (zi.file_size > MAX_SPLIT_BYTES or
                    (zi.file_size > BOMB_MIN_BYTES and zi.file_size > BOMB_RATIO * max(zi.compress_size, 1))):
                b.warnings.append(f"{n}: claims {zi.file_size:,} bytes from {zi.compress_size:,} stored "
                                  f"(zip bomb or damaged entry) — skipped")
                continue
            try:
                data = outer.read(n)
            except ZIP_ERRORS as e:
                b.warnings.append(f"{n}: unreadable ({type(e).__name__}: {str(e)[:80]}) — skipped")
                continue
            if not _is_zip(data):
                b.warnings.append(f"{n}: not a zip (encrypted split?) — skipped")
                continue
            try:
                split_zip = zipfile.ZipFile(io.BytesIO(data))
            except ZIP_ERRORS as e:
                b.warnings.append(f"{n}: damaged zip ({type(e).__name__}: {str(e)[:80]}) — skipped")
                continue
            b.splits.append(Split(n, split_zip, len(data)))
        elif not n.endswith("/"):
            b.extra_files.append(n)
    if not b.splits:
        raise SystemExit(f"{path}: no APKs inside (entries: {names[:10]})")
    if not any("AndroidManifest.xml" in s.names() and any(n.endswith(".dex") for n in s.names()) for s in b.splits):
        raise SystemExit(f"{path}: no base APK inside (only config splits: {[s.name for s in b.splits][:6]}). "
                         f"Download the full bundle, or pull base.apk from the device (`adb shell pm path <pkg>`).")
    base = b.base  # list.sort empties the list while sorting, so resolve first
    b.splits.sort(key=lambda s: (s is not base, s.name))
    return b
