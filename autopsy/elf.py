"""Minimal ELF reader for Android .so files: arch, DT_NEEDED, dynamic symbols
(exports/imports), build-id, and printable strings — no readelf/objdump needed."""
from __future__ import annotations

import hashlib
import re
import struct

MACHINES = {3: "x86", 40: "arm (armeabi-v7a)", 62: "x86_64", 183: "arm64 (arm64-v8a)"}


class ElfInfo:
    def __init__(self, data: bytes, name: str = ""):
        self.name = name
        self.size = len(data)
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.ok = data[:4] == b"\x7fELF"
        self.bits = 0
        self.machine = "?"
        self.needed: list[str] = []
        self.soname = None
        self.exports: list[str] = []
        self.imports: list[str] = []
        self.sections: list[str] = []
        self.build_id = None
        self.stripped = True
        self.error = None
        if not self.ok:
            return
        try:
            self._parse(data)
        except (struct.error, IndexError, ValueError, OverflowError, KeyError, MemoryError) as e:
            self.error = f"parse error: {e}"

    def _parse(self, d: bytes):
        cls, ei_data = d[4], d[5]
        if ei_data != 1:
            raise ValueError("big-endian ELF")
        self.bits = 64 if cls == 2 else 32
        if self.bits == 64:
            (e_type, e_machine, _v, _entry, phoff, shoff, _fl, _eh, phes, phn, shes, shn,
             shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
        else:
            (e_type, e_machine, _v, _entry, phoff, shoff, _fl, _eh, phes, phn, shes, shn,
             shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", d, 16)
        self.machine = MACHINES.get(e_machine, str(e_machine))
        secs = []
        for i in range(shn if shoff else 0):
            o = shoff + i * shes
            if self.bits == 64:
                nm, typ, _f, _a, off, size, link, _inf, _al, entsize = struct.unpack_from("<IIQQQQIIQQ", d, o)
            else:
                nm, typ, _f, _a, off, size, link, _inf, _al, entsize = struct.unpack_from("<IIIIIIIIII", d, o)
            secs.append((nm, typ, off, size, link, entsize))
        names = {}
        if secs and shstrndx < len(secs):
            so = secs[shstrndx][2]
            for i, s in enumerate(secs):
                names[i] = _cstr(d, so + s[0])
        self.sections = [names.get(i, "") for i in range(len(secs))]
        if ".symtab" in self.sections:
            self.stripped = False
        for i, (nm, typ, off, size, link, entsize) in enumerate(secs):
            sname = names.get(i, "")
            if typ == 11 and entsize:  # SHT_DYNSYM
                stro = secs[link][2]
                n = size // entsize
                for k in range(1, n):
                    o = off + k * entsize
                    if self.bits == 64:
                        st_name, st_info, _oth, st_shndx, _val, _sz = struct.unpack_from("<IBBHQQ", d, o)
                    else:
                        st_name, _val, _sz, st_info, _oth, st_shndx = struct.unpack_from("<IIIBBH", d, o)
                    sym = _cstr(d, stro + st_name)
                    if not sym:
                        continue
                    bind = st_info >> 4
                    if st_shndx == 0:
                        self.imports.append(sym)
                    elif bind in (1, 2):
                        self.exports.append(sym)
            elif typ == 6:  # SHT_DYNAMIC
                stro = secs[link][2]
                step = 16 if self.bits == 64 else 8
                fmt = "<qQ" if self.bits == 64 else "<iI"
                for o in range(off, off + size, step):
                    tag, val = struct.unpack_from(fmt, d, o)
                    if tag == 0:
                        break
                    if tag == 1:
                        self.needed.append(_cstr(d, stro + val))
                    elif tag == 14:
                        self.soname = _cstr(d, stro + val)
            elif sname == ".note.gnu.build-id":
                namesz, descsz, _t = struct.unpack_from("<III", d, off)
                desc = off + 12 + ((namesz + 3) & ~3)
                self.build_id = d[desc:desc + descsz].hex()


def _cstr(d: bytes, o: int) -> str:
    e = d.find(b"\0", o)
    return d[o:e if e >= 0 else o + 256].decode("utf-8", "replace")


_PRINTABLE = re.compile(rb"[\x20-\x7e\t]{6,}")


def strings(data: bytes, min_len: int = 6):
    """Printable ASCII runs (like `strings -n 6`)."""
    pat = _PRINTABLE if min_len == 6 else re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
    for m in pat.finditer(data):
        yield m.start(), m.group().decode("ascii")
