"""App art for the GUI: the bundle's icon.png (APKMirror/XAPK) and the manifest's TV banner / icon.

Best effort and never fatal: adaptive-icon XML and vector drawables are skipped (no rasteriser),
so an app can end up with an icon but no banner, or neither (the GUI falls back to a monogram).
"""
from __future__ import annotations

import os
import zipfile

RASTER = (".png", ".webp", ".jpg", ".jpeg")


def _outer_icon(bundle):
    """APKMirror .apkm / .xapk keep a store icon at the zip root."""
    if bundle.kind not in ("apkm", "xapk", "apks", "zip"):
        return None
    try:
        with zipfile.ZipFile(bundle.path) as z:
            for n in ("icon.png", "icon.webp"):
                if n in z.namelist():
                    return n[-4:], z.read(n)
    except (OSError, zipfile.BadZipFile):
        return None
    return None


def _res_file(bundle, res, ref):
    """Resolve '@0x7f08019f' to raster bytes, looking in every split (density splits hold them)."""
    if not res or not ref:
        return None
    try:
        path = res.file_for(ref)
    except Exception:  # noqa: BLE001
        return None
    if not path or not path.lower().endswith(RASTER):
        return None
    # the table points at one density; the same file name exists per density (often in config splits):
    # take the biggest raster, i.e. the sharpest
    base = os.path.basename(path)
    best = None
    for split in bundle.splits:
        for zi in split.zf.infolist():
            n = zi.filename
            if n.startswith("res/") and os.path.basename(n) == base and n.lower().endswith(RASTER):
                if best is None or zi.file_size > best[2]:
                    best = (split, n, zi.file_size)
    if best:
        return os.path.splitext(best[1])[1], best[0].read(best[1])
    return None


def extract(bundle, res, app_attrs: dict, out_dir: str) -> dict:
    """Write icon.* / banner.* into out_dir; return {"icon": file, "banner": file} for what was found."""
    found = {}
    for key, getter in (("icon", lambda: _outer_icon(bundle) or _res_file(bundle, res, app_attrs.get("icon"))),
                        ("banner", lambda: _res_file(bundle, res, app_attrs.get("banner")))):
        try:
            got = getter()
        except Exception:  # noqa: BLE001 - art is cosmetic
            got = None
        if got:
            ext, data = got
            name = key + ext.lower()
            with open(os.path.join(out_dir, name), "wb") as fh:
                fh.write(data)
            found[key] = name
    return found
