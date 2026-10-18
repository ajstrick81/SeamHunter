"""Binary XML (AXML) and resources.arsc readers — enough to read the manifest, the
network-security config, and map resource ids (0x7f......) to `type/name`."""
from __future__ import annotations

import struct

# Android framework attribute ids, used when a hardened app blanks attribute names.
ANDROID_ATTRS = {
    0x01010003: "name", 0x0101021B: "versionCode", 0x0101021C: "versionName",
    0x0101020C: "minSdkVersion", 0x01010270: "targetSdkVersion", 0x01010010: "exported",
    0x010104EA: "extractNativeLibs", 0x01010527: "networkSecurityConfig",
    0x0101000F: "debuggable", 0x010104EC: "usesCleartextTraffic", 0x01010280: "allowBackup",
    0x01010024: "value", 0x01010025: "resource", 0x01010000: "theme", 0x01010001: "label",
    0x01010002: "icon",
}

TYPE_REFERENCE, TYPE_STRING, TYPE_FLOAT = 0x01, 0x03, 0x04
TYPE_INT_DEC, TYPE_INT_HEX, TYPE_BOOLEAN = 0x10, 0x11, 0x12


class StringPool:
    def __init__(self, data: bytes, off: int):
        _t, hsize, size, count, _styles, flags, sstart, _st = struct.unpack_from("<HHIIIIII", data, off)
        self.utf8 = bool(flags & 0x100)
        self.offs = struct.unpack_from(f"<{count}I", data, off + hsize) if count else ()
        self.base = off + sstart
        self.data = data
        self.cache: dict[int, str] = {}
        self.size = size

    def __len__(self):
        return len(self.offs)

    def get(self, i: int) -> str:
        if i < 0 or i >= len(self.offs):
            return ""
        s = self.cache.get(i)
        if s is not None:
            return s
        d, o = self.data, self.base + self.offs[i]
        try:
            if self.utf8:
                n = d[o]
                o += 2 if n & 0x80 else 1
                n = d[o]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | d[o + 1]
                    o += 2
                else:
                    o += 1
                s = d[o:o + n].decode("utf-8", "replace")
            else:
                (n,) = struct.unpack_from("<H", d, o)
                o += 2
                if n & 0x8000:
                    (lo,) = struct.unpack_from("<H", d, o)
                    n = ((n & 0x7FFF) << 16) | lo
                    o += 2
                s = d[o:o + 2 * n].decode("utf-16-le", "replace")
        except (IndexError, struct.error):
            s = ""
        self.cache[i] = s
        return s


def _typed(pool: StringPool, raw: int, dtype: int, data: int):
    if raw != 0xFFFFFFFF and dtype == TYPE_STRING:
        return pool.get(raw)
    if dtype == TYPE_STRING:
        return pool.get(data)
    if dtype == TYPE_BOOLEAN:
        return data != 0
    if dtype == TYPE_INT_DEC:
        return struct.unpack("<i", struct.pack("<I", data))[0]
    if dtype == TYPE_INT_HEX:
        return hex(data)
    if dtype == TYPE_REFERENCE:
        return f"@0x{data:08x}"
    if dtype == TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<I", data))[0]
    if raw != 0xFFFFFFFF:
        return pool.get(raw)
    return data


def parse_axml(data: bytes) -> dict:
    """Parse binary XML into {'tag', 'attrs', 'children'} (root element). Never raises on malformed
    input (protectors mangle manifests on purpose): returns what could be read, plus '_error'."""
    try:
        return _parse_axml(data)
    except Exception as e:  # noqa: BLE001
        return {"tag": "manifest", "attrs": {}, "children": [], "_error": f"{type(e).__name__}: {str(e)[:100]}"}


def _parse_axml(data: bytes) -> dict:
    if len(data) < 8:
        raise ValueError("AXML too short")
    t, hsize, _size = struct.unpack_from("<HHI", data, 0)
    if t != 0x0003:
        # Plain-text XML (some tools leave it) — minimal fallback.
        import xml.etree.ElementTree as ET
        root = ET.fromstring(data)

        def conv(e):
            return {"tag": e.tag, "attrs": {k.split("}")[-1]: v for k, v in e.attrib.items()},
                    "children": [conv(c) for c in e]}
        return conv(root)
    off = hsize
    pool = None
    resmap: list[int] = []
    stack = [{"tag": "#root", "attrs": {}, "children": []}]
    while off + 8 <= len(data):
        ct, chs, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8:
            break
        if ct == 0x0001:
            pool = StringPool(data, off)
        elif ct == 0x0180:
            n = (csize - chs) // 4
            resmap = list(struct.unpack_from(f"<{n}I", data, off + chs))
        elif ct == 0x0102 and pool is not None:
            _ns, name, astart, asize, acount = struct.unpack_from("<IIHHH", data, off + 16)
            attrs = {}
            base = off + 16 + astart
            for k in range(acount):
                a_ns, a_name, a_raw, _vs, _r0, a_type, a_data = struct.unpack_from(
                    "<IIIHBBI", data, base + k * (asize or 20))
                key = pool.get(a_name) if a_name != 0xFFFFFFFF else ""
                if (not key or not key.isprintable()) and a_name < len(resmap):
                    key = ANDROID_ATTRS.get(resmap[a_name], f"attr_0x{resmap[a_name]:08x}")
                attrs[key] = _typed(pool, a_raw, a_type, a_data)
            node = {"tag": pool.get(name), "attrs": attrs, "children": []}
            stack[-1]["children"].append(node)
            stack.append(node)
        elif ct == 0x0103:
            if len(stack) > 1:
                stack.pop()
        off += csize
    kids = stack[0]["children"]
    return kids[0] if kids else stack[0]


def walk(node, tag=None):
    if tag is None or node.get("tag") == tag:
        yield node
    for c in node.get("children", []) or []:
        yield from walk(c, tag)


# ---------------------------------------------------------------- resources.arsc

def _scalar(dtype: int, vdata: int):
    if dtype == 0x12:
        return vdata != 0
    return vdata - (1 << 32) if dtype == 0x10 and vdata & 0x80000000 else vdata


class ResourceTable:
    def __init__(self, data: bytes):
        self.names: dict[int, str] = {}        # 0x7f010001 -> "layout/pause_ad"
        self.values: dict[int, object] = {}    # default-config simple values (strings, file paths)
        self.package = None
        t, hsize, size, _npk = struct.unpack_from("<HHII", data, 0)
        if t != 0x0002:
            raise ValueError("not a resource table")
        off = hsize
        gpool = None
        while off + 8 <= len(data):
            ct, chs, csize = struct.unpack_from("<HHI", data, off)
            if csize < 8:
                break
            if ct == 0x0001:
                gpool = StringPool(data, off)
            elif ct == 0x0200:
                self._package(data, off, chs, csize, gpool)
            off += csize

    def _package(self, data, off, chs, csize, gpool):
        pid = struct.unpack_from("<I", data, off + 8)[0]
        name = data[off + 12:off + 12 + 256].decode("utf-16-le", "replace").split("\0")[0]
        if self.package is None or pid == 0x7F:
            self.package = name
        type_off, _lpt, key_off, _lpk = struct.unpack_from("<IIII", data, off + 268)
        tpool = StringPool(data, off + type_off)
        kpool = StringPool(data, off + key_off)
        p = off + chs
        end = off + csize
        while p + 8 <= end:
            ct, ths, tsize = struct.unpack_from("<HHI", data, p)
            if tsize < 8:
                break
            if ct == 0x0201:
                self._type(data, p, ths, pid, tpool, kpool, gpool)
            p += tsize

    def _type(self, data, p, ths, pid, tpool, kpool, gpool):
        tid, tflags, _res, count, estart = struct.unpack_from("<BBHII", data, p + 8)
        csize = struct.unpack_from("<I", data, p + 20)[0]
        cfg = data[p + 20:p + 20 + csize]
        is_default = not any(cfg[4:])
        tname = tpool.get(tid - 1)
        sparse = tflags & 0x01
        off16 = tflags & 0x02
        entries = []
        if sparse:
            for k in range(count):
                idx, o = struct.unpack_from("<HH", data, p + ths + 4 * k)
                entries.append((idx, o * 4))
        elif off16:
            for k in range(count):
                (o,) = struct.unpack_from("<H", data, p + ths + 2 * k)
                if o != 0xFFFF:
                    entries.append((k, o * 4))
        else:
            for k in range(count):
                (o,) = struct.unpack_from("<I", data, p + ths + 4 * k)
                if o != 0xFFFFFFFF:
                    entries.append((k, o))
        base = p + estart
        for idx, o in entries:
            e = base + o
            try:
                esize, eflags = struct.unpack_from("<HH", data, e)
                resid = (pid << 24) | (tid << 16) | idx
                if eflags & 0x0008:  # compact entry
                    key = esize
                    dtype = eflags >> 8
                    (vdata,) = struct.unpack_from("<I", data, e + 4)
                    self.names.setdefault(resid, f"{tname}/{kpool.get(key)}")
                    if is_default and dtype == TYPE_STRING and gpool:
                        self.values.setdefault(resid, gpool.get(vdata))
                    elif is_default and dtype in (0x10, 0x11, 0x12):
                        self.values.setdefault(resid, _scalar(dtype, vdata))
                    continue
                (key,) = struct.unpack_from("<I", data, e + 4)
                self.names.setdefault(resid, f"{tname}/{kpool.get(key)}")
                if not eflags & 0x0001 and gpool is not None:
                    _vs, _r0, dtype, vdata = struct.unpack_from("<HBBI", data, e + esize)
                    if dtype == TYPE_STRING and (is_default or resid not in self.values):
                        self.values[resid] = gpool.get(vdata)
                    elif is_default and dtype in (0x10, 0x11, 0x12):  # int dec / int hex / bool (kill switches)
                        self.values[resid] = _scalar(dtype, vdata)
            except struct.error:
                continue

    def name(self, resid: int) -> str | None:
        return self.names.get(resid)

    def file_for(self, ref) -> str | None:
        """'@0x7f150002' -> 'res/xml/network_security_config.xml'."""
        if isinstance(ref, str) and ref.startswith("@0x"):
            ref = int(ref[1:], 16)
        v = self.values.get(ref)
        return v if isinstance(v, str) and v.startswith("res/") else None
