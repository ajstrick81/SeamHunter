"""Pure-Python DEX reader + Dalvik disassembler.

No jadx/apktool needed for the core scan. The parser walks every method body once
and records what an ad-seam hunt actually needs: const-strings, invoked methods,
field refs, type refs and resource-id literals. `disassemble()` renders one method
as baksmali-style text on demand (p-registers, labels, payloads), so a single
method can be read without decompiling the whole app.
"""
from __future__ import annotations

import struct
import sys
from array import array

NO_INDEX = 0xFFFFFFFF

# ---------------------------------------------------------------- opcode table
# (name, format, reference kind). Reference kinds: s=string t=type f=field m=method
# c=call-site h=method-handle p=proto; None = no reference.
_OPS: list[tuple[str, str, str | None]] = [("unused", "10x", None)] * 256


def _set(op, name, fmt, ref=None):
    _OPS[op] = (name, fmt, ref)


for _i, (_n, _f) in enumerate([
    ("nop", "10x"), ("move", "12x"), ("move/from16", "22x"), ("move/16", "32x"),
    ("move-wide", "12x"), ("move-wide/from16", "22x"), ("move-wide/16", "32x"),
    ("move-object", "12x"), ("move-object/from16", "22x"), ("move-object/16", "32x"),
    ("move-result", "11x"), ("move-result-wide", "11x"), ("move-result-object", "11x"),
    ("move-exception", "11x"), ("return-void", "10x"), ("return", "11x"),
    ("return-wide", "11x"), ("return-object", "11x"), ("const/4", "11n"),
    ("const/16", "21s"), ("const", "31i"), ("const/high16", "21h"),
    ("const-wide/16", "21s"), ("const-wide/32", "31i"), ("const-wide", "51l"),
    ("const-wide/high16", "21h"),
]):
    _set(_i, _n, _f)
_set(0x1A, "const-string", "21c", "s")
_set(0x1B, "const-string/jumbo", "31c", "s")
_set(0x1C, "const-class", "21c", "t")
_set(0x1D, "monitor-enter", "11x")
_set(0x1E, "monitor-exit", "11x")
_set(0x1F, "check-cast", "21c", "t")
_set(0x20, "instance-of", "22c", "t")
_set(0x21, "array-length", "12x")
_set(0x22, "new-instance", "21c", "t")
_set(0x23, "new-array", "22c", "t")
_set(0x24, "filled-new-array", "35c", "t")
_set(0x25, "filled-new-array/range", "3rc", "t")
_set(0x26, "fill-array-data", "31t")
_set(0x27, "throw", "11x")
_set(0x28, "goto", "10t")
_set(0x29, "goto/16", "20t")
_set(0x2A, "goto/32", "30t")
_set(0x2B, "packed-switch", "31t")
_set(0x2C, "sparse-switch", "31t")
for _i, _n in enumerate(["cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long"]):
    _set(0x2D + _i, _n, "23x")
for _i, _n in enumerate(["eq", "ne", "lt", "ge", "gt", "le"]):
    _set(0x32 + _i, "if-" + _n, "22t")
    _set(0x38 + _i, "if-" + _n + "z", "21t")
_KINDS = ["", "-wide", "-object", "-boolean", "-byte", "-char", "-short"]
for _i, _k in enumerate(_KINDS):
    _set(0x44 + _i, "aget" + _k, "23x")
    _set(0x4B + _i, "aput" + _k, "23x")
    _set(0x52 + _i, "iget" + _k, "22c", "f")
    _set(0x59 + _i, "iput" + _k, "22c", "f")
    _set(0x60 + _i, "sget" + _k, "21c", "f")
    _set(0x67 + _i, "sput" + _k, "21c", "f")
for _i, _n in enumerate(["virtual", "super", "direct", "static", "interface"]):
    _set(0x6E + _i, "invoke-" + _n, "35c", "m")
    _set(0x74 + _i, "invoke-" + _n + "/range", "3rc", "m")
for _i, _n in enumerate([
    "neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double", "int-to-long",
    "int-to-float", "int-to-double", "long-to-int", "long-to-float", "long-to-double",
    "float-to-int", "float-to-long", "float-to-double", "double-to-int", "double-to-long",
    "double-to-float", "int-to-byte", "int-to-char", "int-to-short",
]):
    _set(0x7B + _i, _n, "12x")
_BIN = []
for _t in ["int", "long"]:
    _BIN += [f"{o}-{_t}" for o in ["add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"]]
for _t in ["float", "double"]:
    _BIN += [f"{o}-{_t}" for o in ["add", "sub", "mul", "div", "rem"]]
for _i, _n in enumerate(_BIN):
    _set(0x90 + _i, _n, "23x")
    _set(0xB0 + _i, _n + "/2addr", "12x")
for _i, _n in enumerate(["add-int", "rsub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int", "xor-int"]):
    _set(0xD0 + _i, _n + "/lit16" if _n != "rsub-int" else "rsub-int", "22s")
for _i, _n in enumerate(["add-int", "rsub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int",
                         "xor-int", "shl-int", "shr-int", "ushr-int"]):
    _set(0xD8 + _i, _n + "/lit8", "22b")
_set(0xFA, "invoke-polymorphic", "45cc", "m")
_set(0xFB, "invoke-polymorphic/range", "4rcc", "m")
_set(0xFC, "invoke-custom", "35c", "c")
_set(0xFD, "invoke-custom/range", "3rc", "c")
_set(0xFE, "const-method-handle", "21c", "h")
_set(0xFF, "const-method-type", "21c", "p")

_WIDTH = {"10x": 1, "12x": 1, "11n": 1, "11x": 1, "10t": 1, "20t": 2, "22x": 2, "21t": 2, "21s": 2,
          "21h": 2, "21c": 2, "23x": 2, "22b": 2, "22t": 2, "22s": 2, "22c": 2, "32x": 3, "30t": 3,
          "31t": 3, "31i": 3, "31c": 3, "35c": 3, "3rc": 3, "45cc": 4, "4rcc": 4, "51l": 5}
WIDTH = [_WIDTH[f] for (_, f, _) in _OPS]
REF = [r for (_, _, r) in _OPS]
NAME = [n for (n, _, _) in _OPS]
FMT = [f for (_, f, _) in _OPS]

ACC = [(0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"), (0x10, "final"),
       (0x20, "synchronized"), (0x40, "bridge"), (0x80, "varargs"), (0x100, "native"),
       (0x200, "interface"), (0x400, "abstract"), (0x800, "strictfp"), (0x1000, "synthetic"),
       (0x2000, "annotation"), (0x4000, "enum"), (0x10000, "constructor"),
       (0x20000, "declared-synchronized")]


def flags_str(flags: int, method: bool = True) -> str:
    out = []
    for bit, name in ACC:
        if not flags & bit:
            continue
        if method and bit == 0x40:
            name = "bridge"
        elif not method and bit == 0x40:
            name = "volatile"
        if method and bit == 0x80:
            name = "varargs"
        elif not method and bit == 0x80:
            name = "transient"
        out.append(name)
    return " ".join(out)


def _uleb(buf, off):
    result = shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, off
        shift += 7


def _mutf8(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    raw = raw.replace(b"\xc0\x80", b"\x00")
    try:
        s = raw.decode("utf-8", errors="surrogatepass")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")  # malformed MUTF-8 (fuzzing / protectors)
    try:
        return s.encode("utf-16", "surrogatepass").decode("utf-16")
    except UnicodeDecodeError:
        return s.encode("utf-8", "replace").decode("utf-8", "replace")


_ESC = {"\n": "\\n", "\t": "\\t", "\r": "\\r", '"': '\\"',
        "'": "\\'", "\\": "\\\\"}


def smali_escape(s: str) -> str:
    out = []
    for ch in s:
        e = _ESC.get(ch)
        if e:
            out.append(e)
        elif 0x20 <= ord(ch) < 0x7F:
            out.append(ch)
        elif ord(ch) > 0xFFFF:
            v = ord(ch) - 0x10000
            out.append(f"\\u{0xD800 + (v >> 10):04x}\\u{0xDC00 + (v & 0x3FF):04x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out)


class DexError(Exception):
    pass


class Dex:
    """One classes*.dex file."""

    def __init__(self, data: bytes, name: str = "classes.dex"):
        try:
            self._init(data, name)
        except DexError:
            raise
        except (struct.error, IndexError, ValueError, OverflowError, MemoryError) as e:
            raise DexError(f"{name}: malformed header/tables ({type(e).__name__}: {str(e)[:80]})") from None

    def _init(self, data: bytes, name: str):
        if len(data) < 0x70 or data[:4] != b"dex\n":
            raise DexError(f"{name}: not a DEX file")
        self.data = data
        self.name = name
        self.version = data[4:7].decode("ascii", "replace")
        h = struct.unpack_from("<20I", data, 32)
        (self.file_size, _hs, endian, _ls, _lo, _mo, ns, so, nt, to, np_, po, nf, fo, nm, mo,
         nc, co, _ds, _do) = h
        if endian != 0x12345678:
            raise DexError(f"{name}: unsupported endianness")
        # DEX 041 "container" files can hold several dex sections; only the first is parsed here
        self.container_rest = max(0, len(data) - self.file_size) if self.version >= "041" else 0
        self._so = so
        self.n_strings = ns
        self.string_offs = struct.unpack_from(f"<{ns}I", data, so) if ns else ()
        self._strings: list[str | None] = [None] * ns
        self.type_desc_idx = struct.unpack_from(f"<{nt}I", data, to) if nt else ()
        self.protos = [struct.unpack_from("<3I", data, po + 12 * i) for i in range(np_)]
        self.fields = [struct.unpack_from("<HHI", data, fo + 8 * i) for i in range(nf)]
        self.methods = [struct.unpack_from("<HHI", data, mo + 8 * i) for i in range(nm)]
        self.class_defs = [struct.unpack_from("<8I", data, co + 32 * i) for i in range(nc)]
        self._type_cache: dict[int, str] = {}
        self._proto_cache: dict[int, tuple[tuple[str, ...], str]] = {}
        self._mref_cache: dict[int, str] = {}
        self._fref_cache: dict[int, str] = {}
        # 16-bit view for fast instruction walking (code items are 4-byte aligned).
        even = data if len(data) % 2 == 0 else data + b"\0"
        self.u16 = array("H")
        self.u16.frombytes(even)
        if sys.byteorder != "little":
            self.u16.byteswap()

    # ------------------------------------------------------------ ids
    def string(self, idx: int) -> str:
        s = self._strings[idx]
        if s is None:
            off = self.string_offs[idx]
            _, off = _uleb(self.data, off)
            end = self.data.index(b"\0", off)
            s = _mutf8(self.data[off:end])
            self._strings[idx] = s
        return s

    def type(self, idx: int) -> str:
        t = self._type_cache.get(idx)
        if t is None:
            t = self.string(self.type_desc_idx[idx])
            self._type_cache[idx] = t
        return t

    def type_list(self, off: int) -> tuple[str, ...]:
        if not off:
            return ()
        (n,) = struct.unpack_from("<I", self.data, off)
        return tuple(self.type(i) for i in struct.unpack_from(f"<{n}H", self.data, off + 4))

    def proto(self, idx: int) -> tuple[tuple[str, ...], str]:
        p = self._proto_cache.get(idx)
        if p is None:
            _shorty, ret, params_off = self.protos[idx]
            p = (self.type_list(params_off), self.type(ret))
            self._proto_cache[idx] = p
        return p

    def method_parts(self, idx: int) -> tuple[str, str, tuple[str, ...], str]:
        cls, proto, name = self.methods[idx]
        params, ret = self.proto(proto)
        return self.type(cls), self.string(name), params, ret

    def method_ref(self, idx: int) -> str:
        r = self._mref_cache.get(idx)
        if r is None:
            cls, name, params, ret = self.method_parts(idx)
            r = f"{cls}->{name}({''.join(params)}){ret}"
            self._mref_cache[idx] = r
        return r

    def field_ref(self, idx: int) -> str:
        r = self._fref_cache.get(idx)
        if r is None:
            cls, typ, name = self.fields[idx]
            r = f"{self.type(cls)}->{self.string(name)}:{self.type(typ)}"
            self._fref_cache[idx] = r
        return r

    # ------------------------------------------------------------ classes
    def iter_classes(self):
        """Yield dicts describing each class and its methods (no bytecode walk yet)."""
        self.bad_classes = 0
        for cd in self.class_defs:
            try:
                yield self._class(cd)
            except (struct.error, IndexError, ValueError, OverflowError, KeyError):
                self.bad_classes += 1  # malformed class_def/class_data: skip it, keep the rest

    def _class(self, cd):
        data = self.data
        (cidx, flags, sup, ifoff, src, _ann, cdoff, _sv) = cd
        if True:
            cls = {
                "name": self.type(cidx),
                "flags": flags,
                "super": self.type(sup) if sup != NO_INDEX else None,
                "interfaces": self.type_list(ifoff),
                "source": self.string(src) if src != NO_INDEX else None,
                "fields": [],
                "methods": [],
            }
            if cdoff:
                off = cdoff
                nsf, off = _uleb(data, off)
                nif, off = _uleb(data, off)
                ndm, off = _uleb(data, off)
                nvm, off = _uleb(data, off)
                idx = 0
                for i in range(nsf + nif):
                    if i == nsf:
                        idx = 0
                    d, off = _uleb(data, off)
                    idx += d
                    af, off = _uleb(data, off)
                    fc, ft, fn = self.fields[idx]
                    cls["fields"].append((self.string(fn), self.type(ft), af))
                idx = 0
                for i in range(ndm + nvm):
                    if i == ndm:
                        idx = 0
                    d, off = _uleb(data, off)
                    idx += d
                    af, off = _uleb(data, off)
                    code, off = _uleb(data, off)
                    cls["methods"].append((idx, af, code))
            return cls

    # ------------------------------------------------------------ bytecode
    def code_header(self, code_off: int):
        regs, ins, outs, tries, dbg, n = struct.unpack_from("<4HII", self.data, code_off)
        return regs, ins, outs, tries, n

    def scan_code(self, code_off: int):
        """Walk one method body. Returns (n_insns, strings, methods, fields, types, literals).

        Indices are this dex's own ids. `literals` holds 32-bit constants that look like
        Android resource ids (0x7fXXXXXX) so layouts/strings can be linked to code.
        """
        u = self.u16
        base = (code_off + 16) >> 1
        (n,) = struct.unpack_from("<I", self.data, code_off + 12)
        end = base + n
        i = base
        strs, meths, flds, typs, lits = [], [], [], [], []
        count = 0
        W, R = WIDTH, REF
        while i < end:
            unit = u[i]
            op = unit & 0xFF
            if op == 0 and unit:
                # payload pseudo-instruction
                ident = unit
                if ident == 0x0100:
                    i += u[i + 1] * 2 + 4
                elif ident == 0x0200:
                    i += u[i + 1] * 4 + 2
                elif ident == 0x0300:
                    width = u[i + 1]
                    size = u[i + 2] | (u[i + 3] << 16)
                    i += (size * width + 1) // 2 + 4
                else:
                    i += 1
                continue
            count += 1
            r = R[op]
            if r is not None:
                if r == "s":
                    strs.append(u[i + 1] | (u[i + 2] << 16) if op == 0x1B else u[i + 1])
                elif r == "m":
                    meths.append(u[i + 1])
                elif r == "f":
                    # writes (iput*/sput*) flagged by setting bit 31
                    flds.append(u[i + 1] | (0x80000000 if (0x59 <= op <= 0x5F or 0x67 <= op <= 0x6D) else 0))
                elif r == "t":
                    typs.append(u[i + 1])
            elif op == 0x14:  # const vAA, #+BBBBBBBB
                v = u[i + 1] | (u[i + 2] << 16)
                if (v >> 24) == 0x7F:
                    lits.append(v)
            i += W[op]
        return count, strs, meths, flds, typs, lits

    # ------------------------------------------------------------ disassembly
    def disassemble(self, code_off: int, method_idx: int, flags: int) -> str:
        cls, name, params, ret = self.method_parts(method_idx)
        head = f".method {flags_str(flags)} {name}({''.join(params)}){ret}".replace("  ", " ")
        if not code_off:
            return head + "\n.end method"
        regs, ins, _outs, tries, n = self.code_header(code_off)
        first_param = regs - ins

        def reg(r):
            return f"p{r - first_param}" if r >= first_param else f"v{r}"

        u = self.u16
        base = (code_off + 16) >> 1
        end = base + n
        # first pass: decode and collect branch targets
        insns = []
        targets: dict[int, str] = {}
        payload_kind: dict[int, str] = {}
        i = base
        while i < end:
            unit = u[i]
            op = unit & 0xFF
            pc = i - base
            if op == 0 and unit in (0x0100, 0x0200, 0x0300):
                if unit == 0x0100:
                    size = u[i + 1]
                    first = struct.unpack("<i", struct.pack("<HH", u[i + 2], u[i + 3]))[0]
                    tg = [struct.unpack("<i", struct.pack("<HH", u[i + 4 + 2 * k], u[i + 5 + 2 * k]))[0]
                          for k in range(size)]
                    insns.append((pc, "packed-payload", (first, tg)))
                    i += size * 2 + 4
                elif unit == 0x0200:
                    size = u[i + 1]
                    keys = [struct.unpack("<i", struct.pack("<HH", u[i + 2 + 2 * k], u[i + 3 + 2 * k]))[0]
                            for k in range(size)]
                    o = i + 2 + 2 * size
                    tg = [struct.unpack("<i", struct.pack("<HH", u[o + 2 * k], u[o + 1 + 2 * k]))[0]
                          for k in range(size)]
                    insns.append((pc, "sparse-payload", (keys, tg)))
                    i += size * 4 + 2
                else:
                    width = u[i + 1]
                    size = u[i + 2] | (u[i + 3] << 16)
                    raw = self.data[(i + 4) * 2:(i + 4) * 2 + size * width]
                    insns.append((pc, "array-payload", (width, raw)))
                    i += (size * width + 1) // 2 + 4
                continue
            w = WIDTH[op]
            insns.append((pc, op, tuple(u[i:i + w])))
            i += w

        def s16(x):
            return x - 0x10000 if x & 0x8000 else x

        def s32(lo, hi):
            v = lo | (hi << 16)
            return v - 0x100000000 if v & 0x80000000 else v

        for pc, op, units in insns:
            if isinstance(op, str):
                continue
            fmt = FMT[op]
            nm = NAME[op]
            if fmt in ("10t", "20t", "30t", "21t", "22t"):
                if fmt == "10t":
                    off = (units[0] >> 8)
                    off = off - 0x100 if off & 0x80 else off
                elif fmt == "30t":
                    off = s32(units[1], units[2])
                else:
                    off = s16(units[1])
                targets.setdefault(pc + off, f":{'goto' if 'goto' in nm else 'cond'}_{pc + off:x}")
            elif fmt == "31t":
                off = s32(units[1], units[2])
                kind = {"fill-array-data": "array", "packed-switch": "pswitch_data",
                        "sparse-switch": "sswitch_data"}[nm]
                targets.setdefault(pc + off, f":{kind}_{pc + off:x}")
                payload_kind[pc + off] = pc
        # switch case targets are relative to the switch instruction
        switch_at = {}
        for pc, op, units in insns:
            if not isinstance(op, str) and NAME[op] in ("packed-switch", "sparse-switch"):
                switch_at[pc + s32(units[1], units[2])] = pc
        for pc, op, data in insns:
            if op in ("packed-payload", "sparse-payload"):
                sw = switch_at.get(pc, pc)
                for t in data[1]:
                    targets.setdefault(sw + t, f":sswitch_{sw + t:x}" if op == "sparse-payload"
                                       else f":pswitch_{sw + t:x}")

        out = [head, f"    .registers {regs}"]
        for pc, op, units in insns:
            if pc in targets:
                out.append("")
                out.append(f"    {targets[pc]}")
            if op == "packed-payload":
                first, tg = units
                sw = switch_at.get(pc, pc)
                out.append(f"    .packed-switch 0x{first & 0xFFFFFFFF:x}")
                out += [f"        {targets[sw + t]}" for t in tg]
                out.append("    .end packed-switch")
                continue
            if op == "sparse-payload":
                keys, tg = units
                sw = switch_at.get(pc, pc)
                out.append("    .sparse-switch")
                out += [f"        0x{k & 0xFFFFFFFF:x} -> {targets[sw + t]}" for k, t in zip(keys, tg)]
                out.append("    .end sparse-switch")
                continue
            if op == "array-payload":
                width, raw = units
                out.append(f"    .array-data {width}")
                for k in range(0, len(raw), width):
                    out.append(f"        0x{int.from_bytes(raw[k:k + width], 'little'):x}")
                out.append("    .end array-data")
                continue
            out.append("    " + self._fmt_insn(pc, op, units, reg, targets))
        out.append(".end method")
        return "\n".join(out)

    def _ref(self, kind, idx):
        try:
            if kind == "s":
                return '"' + smali_escape(self.string(idx)) + '"'
            if kind == "t":
                return self.type(idx)
            if kind == "f":
                return self.field_ref(idx)
            if kind == "m":
                return self.method_ref(idx)
        except (IndexError, struct.error):
            pass
        return f"{kind}@{idx}"

    def _fmt_insn(self, pc, op, u, reg, targets):
        fmt, nm, ref = FMT[op], NAME[op], REF[op]
        a8 = u[0] >> 8
        a4 = (u[0] >> 8) & 0xF
        b4 = u[0] >> 12

        def s16(x):
            return x - 0x10000 if x & 0x8000 else x

        def s32(lo, hi):
            v = lo | (hi << 16)
            return v - 0x100000000 if v & 0x80000000 else v

        if fmt == "10x":
            return nm
        if fmt == "12x":
            return f"{nm} {reg(a4)}, {reg(b4)}"
        if fmt == "11n":
            lit = b4 - 16 if b4 & 8 else b4
            return f"{nm} {reg(a4)}, {hex(lit) if lit >= 0 else '-' + hex(-lit)}"
        if fmt == "11x":
            return f"{nm} {reg(a8)}"
        if fmt == "10t":
            off = a8 - 0x100 if a8 & 0x80 else a8
            return f"{nm} {targets.get(pc + off, off)}"
        if fmt == "20t":
            return f"{nm} {targets.get(pc + s16(u[1]))}"
        if fmt == "30t":
            return f"{nm} {targets.get(pc + s32(u[1], u[2]))}"
        if fmt == "22x":
            return f"{nm} {reg(a8)}, {reg(u[1])}"
        if fmt == "32x":
            return f"{nm} {reg(u[1])}, {reg(u[2])}"
        if fmt == "21t":
            return f"{nm} {reg(a8)}, {targets.get(pc + s16(u[1]))}"
        if fmt == "22t":
            return f"{nm} {reg(a4)}, {reg(b4)}, {targets.get(pc + s16(u[1]))}"
        if fmt == "21s":
            v = s16(u[1])
            return f"{nm} {reg(a8)}, {hex(v) if v >= 0 else '-' + hex(-v)}"
        if fmt == "21h":
            if "wide" in nm:
                v = u[1] << 48
                v = v - (1 << 64) if v & (1 << 63) else v
                return f"{nm} {reg(a8)}, {hex(v) if v >= 0 else '-' + hex(-v)}L"
            v = u[1] << 16
            v = v - (1 << 32) if v & (1 << 31) else v
            return f"{nm} {reg(a8)}, {hex(v) if v >= 0 else '-' + hex(-v)}"
        if fmt == "31i":
            v = s32(u[1], u[2])
            return f"{nm} {reg(a8)}, {hex(v) if v >= 0 else '-' + hex(-v)}"
        if fmt == "51l":
            v = u[1] | (u[2] << 16) | (u[3] << 32) | (u[4] << 48)
            if v & (1 << 63):
                v -= 1 << 64
            return f"{nm} {reg(a8)}, {hex(v) if v >= 0 else '-' + hex(-v)}L"
        if fmt == "21c":
            return f"{nm} {reg(a8)}, {self._ref(ref, u[1])}"
        if fmt == "31c":
            return f"{nm} {reg(a8)}, {self._ref(ref, u[1] | (u[2] << 16))}"
        if fmt == "31t":
            return f"{nm} {reg(a8)}, {targets.get(pc + s32(u[1], u[2]))}"
        if fmt == "23x":
            return f"{nm} {reg(a8)}, {reg(u[1] & 0xFF)}, {reg(u[1] >> 8)}"
        if fmt == "22b":
            lit = u[1] >> 8
            lit = lit - 0x100 if lit & 0x80 else lit
            return f"{nm} {reg(a8)}, {reg(u[1] & 0xFF)}, {hex(lit) if lit >= 0 else '-' + hex(-lit)}"
        if fmt == "22s":
            v = s16(u[1])
            return f"{nm} {reg(a4)}, {reg(b4)}, {hex(v) if v >= 0 else '-' + hex(-v)}"
        if fmt == "22c":
            return f"{nm} {reg(a4)}, {reg(b4)}, {self._ref(ref, u[1])}"
        if fmt in ("35c", "45cc"):
            cnt = b4
            g = a4
            c, d, e, f = u[2] & 0xF, (u[2] >> 4) & 0xF, (u[2] >> 8) & 0xF, u[2] >> 12
            regs = [c, d, e, f, g][:cnt]
            tail = f", proto@{u[3]}" if fmt == "45cc" else ""
            return f"{nm} {{{', '.join(reg(r) for r in regs)}}}, {self._ref(ref, u[1])}{tail}"
        if fmt in ("3rc", "4rcc"):
            cnt, first = a8, u[2]
            rr = f"{reg(first)} .. {reg(first + cnt - 1)}" if cnt else ""
            tail = f", proto@{u[3]}" if fmt == "4rcc" else ""
            return f"{nm} {{{rr}}}, {self._ref(ref, u[1])}{tail}"
        return nm
