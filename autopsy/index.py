"""Build and query the SQLite code index for one bundle.

One pass over every method body stores: const-strings, invoked method refs, field refs,
type refs and resource-id literals. After that every question ("who calls X", "which
methods use string Y", "show me method Z") is a millisecond query instead of a tree grep.
"""
from __future__ import annotations

import os
import sqlite3
import struct
import time

from .dex import Dex, DexError, flags_str
from .kb.sdks import FRAMEWORK_PREFIXES, PREFIXES

SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE dexfiles(id INTEGER PRIMARY KEY, split TEXT, entry TEXT, path TEXT, n_classes INT, n_methods INT, version TEXT);
CREATE TABLE classes(id INTEGER PRIMARY KEY, name TEXT, super TEXT, interfaces TEXT, source TEXT,
                     flags INT, dex INT, sdk TEXT, category TEXT, is_app INT, n_methods INT);
CREATE TABLE fields(class INT, name TEXT, type TEXT, flags INT);
CREATE TABLE methods(id INTEGER PRIMARY KEY, class INT, name TEXT, params TEXT, ret TEXT, flags INT,
                     dex INT, midx INT, code_off INT, insns INT);
CREATE TABLE strings(id INTEGER PRIMARY KEY, value TEXT UNIQUE);
CREATE TABLE refs(id INTEGER PRIMARY KEY, ref TEXT UNIQUE, cls TEXT, name TEXT);
CREATE TABLE frefs(id INTEGER PRIMARY KEY, ref TEXT UNIQUE, cls TEXT);
CREATE TABLE m_str(m INT, s INT);
CREATE TABLE m_call(m INT, r INT);
CREATE TABLE m_field(m INT, f INT, w INT);
CREATE TABLE m_type(m INT, t TEXT);
CREATE TABLE m_res(m INT, res INT);
"""
POST_INDEX = """
CREATE INDEX i_cls_name ON classes(name);
CREATE INDEX i_cls_src ON classes(source);
CREATE INDEX i_m_class ON methods(class);
CREATE INDEX i_m_name ON methods(name);
CREATE INDEX i_ms_s ON m_str(s);
CREATE INDEX i_ms_m ON m_str(m);
CREATE INDEX i_mc_r ON m_call(r);
CREATE INDEX i_mc_m ON m_call(m);
CREATE INDEX i_mf_f ON m_field(f);
CREATE INDEX i_mf_m ON m_field(m);
CREATE INDEX i_cls_super ON classes(super);
CREATE INDEX i_mt_t ON m_type(t);
CREATE INDEX i_mr_r ON m_res(res);
CREATE INDEX i_refs_cls ON refs(cls);
CREATE INDEX i_f_class ON fields(class);
"""

# anything a malformed/fuzzed DEX can raise while resolving ids
BAD_DEX = (IndexError, KeyError, ValueError, OverflowError, UnicodeError, struct.error)

_SORTED_PREFIXES = sorted(PREFIXES, key=lambda p: -len(p[0]))


def classify(name: str):
    """(sdk_name, category, is_app) for a class descriptor."""
    for pfx, sdk, cat, _note in _SORTED_PREFIXES:
        if name.startswith(pfx):
            return sdk, cat, 0
    if name.startswith(FRAMEWORK_PREFIXES):
        return None, "framework", 0
    return None, None, 1


def build(bundle, out_dir: str, log=print, extra_dex: list[tuple[str, str, bytes]] | None = None) -> str:
    """Index all DEX in the bundle (plus `extra_dex` (split, entry, bytes) found in assets)."""
    os.makedirs(out_dir, exist_ok=True)
    dex_dir = os.path.join(out_dir, "dex")
    os.makedirs(dex_dir, exist_ok=True)
    db_path = os.path.join(out_dir, "index.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)
    db = sqlite3.connect(db_path)
    db.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;")
    db.executescript(SCHEMA)
    str_ids: dict[str, int] = {}
    ref_ids: dict[str, int] = {}
    fref_ids: dict[str, int] = {}
    seen_classes: set[str] = set()
    class_id = 0
    method_id = 0
    t0 = time.time()
    sources = [(s.name, n, s.read(n)) for s, n in bundle.dex_entries()]
    sources += extra_dex or []
    total_insns = 0
    total_bad = 0
    for dex_id, (split, entry, data) in enumerate(sources):
        try:
            dx = Dex(data, entry)
        except (DexError, MemoryError) as e:
            log(f"  ! {split}:{entry}: {e}")
            continue
        path = os.path.join(dex_dir, f"{dex_id:02d}_{os.path.basename(split)}_{entry.replace('/', '_')}")
        with open(path, "wb") as f:
            f.write(data)
        # per-dex local->global id caches
        s_local: dict[int, int] = {}
        m_local: dict[int, int] = {}
        f_local: dict[int, int] = {}
        cls_rows, fld_rows, m_rows = [], [], []
        ms_rows, mc_rows, mf_rows, mt_rows, mr_rows = [], [], [], [], []
        n_methods = 0
        bad_methods = 0
        for c in dx.iter_classes():
            name = c["name"]
            if name in seen_classes:
                continue  # first definition wins, like the runtime
            seen_classes.add(name)
            class_id += 1
            sdk, cat, is_app = classify(name)
            cls_rows.append((class_id, name, c["super"], " ".join(c["interfaces"]), c["source"], c["flags"],
                             dex_id, sdk, cat, is_app, len(c["methods"])))
            for fname, ftype, fflags in c["fields"]:
                fld_rows.append((class_id, fname, ftype, fflags))
            for midx, mflags, code in c["methods"]:
                try:
                    _cls, mname, params, ret = dx.method_parts(midx)
                except BAD_DEX as e:
                    bad_methods += 1
                    if bad_methods <= 3:
                        log(f"  ! {entry}: skipped malformed method ref ({type(e).__name__})")
                    continue
                method_id += 1
                n_methods += 1
                insns = 0
                if code:
                    try:
                        insns, strs, meths, flds, typs, lits = dx.scan_code(code)
                    except Exception:  # noqa: BLE001 - one bad method must not sink the scan
                        bad_methods += 1
                        insns, strs, meths, flds, typs, lits = 0, (), (), (), (), ()
                    for si in set(strs):
                        gid = s_local.get(si)
                        if gid is None:
                            try:
                                val = dx.string(si)[:4096]
                            except BAD_DEX:
                                continue
                            gid = str_ids.get(val)
                            if gid is None:
                                gid = len(str_ids) + 1
                                str_ids[val] = gid
                            s_local[si] = gid
                        ms_rows.append((method_id, gid))
                    for mi in set(meths):
                        gid = m_local.get(mi)
                        if gid is None:
                            try:
                                r = dx.method_ref(mi)
                            except BAD_DEX:
                                continue
                            gid = ref_ids.get(r)
                            if gid is None:
                                gid = len(ref_ids) + 1
                                ref_ids[r] = gid
                            m_local[mi] = gid
                        mc_rows.append((method_id, gid))
                    for fw in set(flds):
                        fi = fw & 0x7FFFFFFF
                        gid = f_local.get(fi)
                        if gid is None:
                            try:
                                r = dx.field_ref(fi)
                            except BAD_DEX:
                                continue
                            gid = fref_ids.get(r)
                            if gid is None:
                                gid = len(fref_ids) + 1
                                fref_ids[r] = gid
                            f_local[fi] = gid
                        mf_rows.append((method_id, gid, 1 if fw & 0x80000000 else 0))
                    for ti in set(typs):
                        try:
                            mt_rows.append((method_id, dx.type(ti)))
                        except BAD_DEX:
                            pass
                    for lit in set(lits):
                        mr_rows.append((method_id, lit))
                total_insns += insns
                m_rows.append((method_id, class_id, mname, "".join(params), ret, mflags, dex_id, midx, code, insns))
        db.executemany("INSERT INTO classes VALUES (?,?,?,?,?,?,?,?,?,?,?)", cls_rows)
        db.executemany("INSERT INTO fields VALUES (?,?,?,?)", fld_rows)
        db.executemany("INSERT INTO methods VALUES (?,?,?,?,?,?,?,?,?,?)", m_rows)
        db.executemany("INSERT INTO m_str VALUES (?,?)", ms_rows)
        db.executemany("INSERT INTO m_call VALUES (?,?)", mc_rows)
        db.executemany("INSERT INTO m_field VALUES (?,?,?)", mf_rows)
        db.executemany("INSERT INTO m_type VALUES (?,?)", mt_rows)
        db.executemany("INSERT INTO m_res VALUES (?,?)", mr_rows)
        db.execute("INSERT INTO dexfiles VALUES (?,?,?,?,?,?,?)",
                   (dex_id, split, entry, os.path.relpath(path, out_dir), len(cls_rows), n_methods, dx.version))
        if getattr(dx, "container_rest", 0):
            log(f"  ! {entry}: DEX {dx.version} container has {dx.container_rest:,} bytes past the first section "
                f"— not indexed yet (tell Claude: add multi-section support)")
            total_bad += 1
        log(f"  {split}:{entry}  dex {dx.version}  {len(dx.class_defs):,} classes  {n_methods:,} methods" +
            (f"  (skipped {dx.bad_classes} malformed classes, {bad_methods} methods)" if dx.bad_classes or bad_methods else ""))
        total_bad += dx.bad_classes + bad_methods
    db.executemany("INSERT INTO strings VALUES (?,?)", ((i, v) for v, i in str_ids.items()))
    db.executemany("INSERT INTO refs VALUES (?,?,?,?)",
                   ((i, r, r.split("->", 1)[0], r.split("->", 1)[1].split("(", 1)[0]) for r, i in ref_ids.items()))
    db.executemany("INSERT INTO frefs VALUES (?,?,?)", ((i, r, r.split("->", 1)[0]) for r, i in fref_ids.items()))
    db.executescript(POST_INDEX)
    db.execute("INSERT INTO meta VALUES ('insns', ?)", (str(total_insns),))
    db.execute("INSERT INTO meta VALUES ('skipped_malformed', ?)", (str(total_bad),))
    db.execute("INSERT INTO meta VALUES ('index_seconds', ?)", (f"{time.time() - t0:.1f}",))
    db.commit()
    db.close()
    log(f"  indexed {class_id:,} classes, {method_id:,} methods, {total_insns:,} instructions in {time.time() - t0:.1f}s")
    return db_path


# ---------------------------------------------------------------- queries

def esc_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def like(text: str) -> str:
    """LIKE pattern for a literal substring: `_` and `%` (common in Android names) are not wildcards."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Index:
    def __init__(self, path: str):
        if os.path.isdir(path):
            path = os.path.join(path, "index.sqlite")
        if not os.path.exists(path):
            raise SystemExit(f"no index at {path} — run `autopsy scan` first")
        self.path = path
        self.root = os.path.dirname(path)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        # R8 emits class names that differ only by case (e.g. Lsf/c; vs LSf/c;)
        self.db.execute("PRAGMA case_sensitive_like = ON")
        self._dex_cache: dict[int, Dex] = {}

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        self._dex_cache.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def q(self, sql, *args):
        return self.db.execute(sql, args).fetchall()

    def meta(self, key, default=None):
        r = self.q("SELECT value FROM meta WHERE key=?", key)
        return r[0][0] if r else default

    # ---- method helpers
    METHOD_SQL = ("SELECT m.id, c.name AS cls, m.name, m.params, m.ret, m.flags, m.insns, c.is_app, c.sdk, "
                  "c.source, m.dex, m.midx, m.code_off FROM methods m JOIN classes c ON c.id=m.class ")

    @staticmethod
    def sig(row) -> str:
        return f"{row['cls']}->{row['name']}({row['params']}){row['ret']}"

    def method(self, mid: int):
        r = self.q(self.METHOD_SQL + "WHERE m.id=?", mid)
        return r[0] if r else None

    def find_methods(self, spec: str, limit: int = 50):
        """spec: 'Lcls;->name(params)ret' | 'Lcls;->name' | 'Lcls;' | 'name' | '#id'."""
        spec = spec.strip()
        if spec.startswith("#") and spec[1:].isdigit():
            r = self.method(int(spec[1:]))
            return [r] if r else []
        if "->" in spec:
            cls, rest = spec.split("->", 1)
            if "(" in rest:
                name, tail = rest.split("(", 1)
                params, ret = tail.split(")", 1)
                return self.q(self.METHOD_SQL + "WHERE c.name=? AND m.name=? AND m.params=? AND (?='' OR m.ret=?) LIMIT ?",
                              cls, name, params, ret, ret, limit)
            return self.q(self.METHOD_SQL + "WHERE c.name=? AND m.name=? LIMIT ?", cls, rest, limit)
        if spec.startswith("L") and spec.endswith(";"):
            return self.q(self.METHOD_SQL + "WHERE c.name=? LIMIT ?", spec, limit)
        return self.q(self.METHOD_SQL + "WHERE m.name=? LIMIT ?", spec, limit)

    def dex(self, dex_id: int) -> Dex:
        d = self._dex_cache.get(dex_id)
        if d is None:
            (path,) = self.q("SELECT path FROM dexfiles WHERE id=?", dex_id)[0]
            with open(os.path.join(self.root, path), "rb") as f:
                d = Dex(f.read(), path)
            self._dex_cache[dex_id] = d
        return d

    def smali(self, row) -> str:
        d = self.dex(row["dex"])
        return d.disassemble(row["code_off"], row["midx"], row["flags"])

    def strings_of(self, mid):
        return [r[0] for r in self.q("SELECT s.value FROM m_str x JOIN strings s ON s.id=x.s WHERE x.m=?", mid)]

    def fields_of(self, mid):
        return [r[0] for r in self.q("SELECT f.ref FROM m_field x JOIN frefs f ON f.id=x.f WHERE x.m=?", mid)]

    def calls_of(self, mid):
        return [r[0] for r in self.q("SELECT r.ref FROM m_call x JOIN refs r ON r.id=x.r WHERE x.m=?", mid)]

    def callers(self, ref_like: str, limit=200, exact=False):
        op = "=" if exact else "LIKE"
        esc = "" if exact else " ESCAPE '\\'"
        pat = ref_like if exact else like(ref_like)
        return self.q(self.METHOD_SQL + f"JOIN m_call x ON x.m=m.id JOIN refs r ON r.id=x.r WHERE r.ref {op} ?{esc} LIMIT ?",
                      pat, limit)

    def string_users(self, text: str, limit=200, exact=False):
        op = "=" if exact else "LIKE"
        esc = "" if exact else " ESCAPE '\\'"
        pat = text if exact else like(text)
        return self.q("SELECT s.value, " + self.METHOD_SQL[7:] +
                      f"JOIN m_str x ON x.m=m.id JOIN strings s ON s.id=x.s WHERE s.value {op} ?{esc} LIMIT ?", pat, limit)

    def string_count(self, value: str) -> int:
        r = self.q("SELECT COUNT(DISTINCT x.m) FROM m_str x JOIN strings s ON s.id=x.s WHERE s.value=?", value)
        return r[0][0]

    def ref_count(self, ref: str) -> int:
        r = self.q("SELECT COUNT(DISTINCT x.m) FROM m_call x JOIN refs r ON r.id=x.r WHERE r.ref=?", ref)
        return r[0][0]

    def field_access(self, mid):
        """(field ref, is_write) touched by one method."""
        return [(r[0], bool(r[1])) for r in self.q(
            "SELECT f.ref, x.w FROM m_field x JOIN frefs f ON f.id=x.f WHERE x.m=?", mid)]

    def field_users(self, fref_like, write=None, limit=200, exact=False):
        op = "=" if exact else "LIKE"
        esc = "" if exact else " ESCAPE '\\'"
        pat = fref_like if exact else like(fref_like)
        extra = "" if write is None else f" AND x.w={1 if write else 0}"
        return self.q("SELECT f.ref AS fref, x.w AS w, " + self.METHOD_SQL[7:] +
                      f"JOIN m_field x ON x.m=m.id JOIN frefs f ON f.id=x.f WHERE f.ref {op} ?{esc}{extra} LIMIT ?", pat, limit)

    def subclasses(self, name, limit=500):
        """Classes that extend or implement `name`, transitively through app code."""
        out, frontier, seen = [], [name], {name}
        while frontier and len(out) < limit:
            nxt = []
            for n in frontier:
                for r in self.q("SELECT name FROM classes WHERE super=? OR (' ' || interfaces || ' ') LIKE ? ESCAPE '\\'",
                                n, f"% {esc_like(n)} %"):
                    if r[0] not in seen:
                        seen.add(r[0])
                        out.append(r[0])
                        nxt.append(r[0])
            frontier = nxt
        return out

    def class_row(self, name):
        r = self.q("SELECT * FROM classes WHERE name=?", name)
        return r[0] if r else None

    def describe_flags(self, flags):
        return flags_str(flags)
