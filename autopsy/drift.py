"""Known-app drift check: test the repo's shipped fingerprints against a new build.

A pure-Python known-app fingerprint check that works on the SQLite index
(no apktool tree needed). Statuses match the original:
OK · SIGNATURE_CHANGED · FLAGS_CHANGED · STRINGS_MISSING · METHOD_MISSING ·
CLASS_MISSING (+ candidates) · UNVERIFIABLE (custom matcher only) · FOUND_BY_STRINGS
"""
from __future__ import annotations

import json
import os
import re

from .index import esc_like
from .seams import is_obfuscated_name, simple_class

KB_FILE = os.path.join(os.path.dirname(__file__), "kb", "known_apps.json")


def load_known():
    try:
        with open(KB_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"apps": {}}


def app_for_package(pkg: str):
    kb = load_known()
    for key, app in kb.get("apps", {}).items():
        if pkg in app.get("packages", []):
            return key, app
    return None, None


FLAG_BITS = {"PUBLIC": 0x1, "PRIVATE": 0x2, "PROTECTED": 0x4, "STATIC": 0x8, "FINAL": 0x10,
             "SYNCHRONIZED": 0x20, "BRIDGE": 0x40, "VARARGS": 0x80, "NATIVE": 0x100, "ABSTRACT": 0x400,
             "SYNTHETIC": 0x1000, "CONSTRUCTOR": 0x10000}


def _judge(idx, fp, row):
    issues = []
    want_ret = fp.get("returnType")
    # a fingerprint source sometimes drops the trailing ';'
    if want_ret and want_ret.startswith("L") and not want_ret.endswith(";"):
        want_ret += ";"
    want_params = "".join(fp["parameters"]) if fp.get("parameters") is not None else None
    status = "OK"
    if want_ret and row["ret"] != want_ret:
        issues.append(f"returns {row['ret']} (want {want_ret})")
    if want_params is not None and row["params"] != want_params:
        issues.append(f"params ({row['params']}) (want ({want_params}))")
    if issues:
        status = "SIGNATURE_CHANGED"
    flags = fp.get("accessFlags") or []
    missing_flags = [f for f in flags if not row["flags"] & FLAG_BITS.get(f.upper(), 0)]
    if missing_flags:
        issues.append(f"flags lack {missing_flags}")
        if status == "OK":
            status = "FLAGS_CHANGED"
    strs = set(idx.strings_of(row["id"]))
    if fp.get("strings"):
        cls_strs = {r[0] for r in idx.q(
            "SELECT s.value FROM methods m JOIN classes c ON c.id=m.class JOIN m_str x ON x.m=m.id "
            "JOIN strings s ON s.id=x.s WHERE c.name=?", row["cls"])}
        miss = [s for s in fp["strings"] if s not in strs and s not in cls_strs]
        if miss:
            issues.append(f"strings missing: {miss}")
            if status == "OK":
                status = "STRINGS_MISSING"
    return status, issues


def _candidates(idx, fp, limit=5):
    want_ret = fp.get("returnType")
    if want_ret and want_ret.startswith("L") and not want_ret.endswith(";"):
        want_ret += ";"
    params = "".join(fp["parameters"]) if fp.get("parameters") is not None else None
    sql = idx.METHOD_SQL + "WHERE 1=1"
    args = []
    if want_ret:
        sql += " AND m.ret=?"
        args.append(want_ret)
    if params is not None:
        sql += " AND m.params=?"
        args.append(params)
    name = fp.get("name")
    if name and not is_obfuscated_name(name):
        sql += " AND m.name=?"
        args.append(name)
    rows = idx.q(sql + " LIMIT 5000", *args)
    want_src = None
    if fp.get("definingClass"):
        base = simple_class(fp["definingClass"]).split("$")[0]
        want_src = {base + ".kt", base + ".java"}
    scored = []
    for r in rows:
        s = 0
        if fp.get("strings"):
            have = set(idx.strings_of(r["id"]))
            if not all(x in have for x in fp["strings"]):
                continue
            s += 5
        if want_src and r["source"] in want_src:
            s += 10
        if fp.get("definingClass"):
            want_pkg = fp["definingClass"].rsplit("/", 1)[0]
            if r["cls"].startswith(want_pkg):
                s += 3
        scored.append((s, idx.sig(r)))
    scored.sort(key=lambda x: -x[0])
    if not fp.get("strings") and not want_src and len(scored) > 20:
        return [f"({len(scored)} methods share this signature — too many to rank)"]
    return [f"{sig}  [score {s}]" for s, sig in scored[:limit]]


def _by_anchors(idx, fp):
    """Evaluate a custom matcher from its extracted literal anchors."""
    a = {k: v for k, v in (fp.get("customAnchors") or {}).items() if k != "unparsed"}
    if not a:
        return None
    want_ret = fp.get("returnType")
    if want_ret and want_ret.startswith("L") and not want_ret.endswith(";"):
        want_ret += ";"
    if list(a) == ["refName"] and not want_ret and not fp.get("strings"):
        # only a referenced-method name: search callers instead of every method
        return [r for r in idx.callers(f"->{a['refName']}(", limit=50)]
    sql, args = idx.METHOD_SQL + "WHERE m.code_off != 0", []
    if want_ret:
        sql += " AND m.ret=?"
        args.append(want_ret)
    if fp.get("parameters") is not None:
        sql += " AND m.params=?"
        args.append("".join(fp["parameters"]))
    if a.get("name"):
        sql += " AND m.name=?"
        args.append(a["name"])
    if a.get("classExact"):
        sql += " AND c.name=?"
        args.append(a["classExact"])
    if a.get("classSuffix"):
        sql += " AND c.name LIKE ? ESCAPE '\\'"
        args.append("%" + esc_like(a["classSuffix"]))
    if a.get("classPrefix"):
        sql += " AND c.name LIKE ? ESCAPE '\\'"
        args.append(esc_like(a["classPrefix"]) + "%")
    rows = idx.q(sql + " LIMIT 5000", *args)
    if a.get("names"):
        rows = [r for r in rows if r["name"] in a["names"]]
    if a.get("paramType"):
        rows = [r for r in rows if all(t in r["params"] for t in a["paramType"])]
    if a.get("nameStartsWith"):
        rows = [r for r in rows if r["name"].startswith(a["nameStartsWith"])]
    if a.get("classContains"):
        rows = [r for r in rows if a["classContains"] in r["cls"]]
    if a.get("returnExact"):
        rows = [r for r in rows if r["ret"] == a["returnExact"]]
    if a.get("stringRef"):
        rows = [r for r in rows if all(s in idx.strings_of(r["id"]) for s in a["stringRef"])]
    if a.get("classStringRef"):
        holders = None
        for s in a["classStringRef"]:
            cls = {u["cls"] for u in idx.string_users(s, exact=True, limit=5000)}
            holders = cls if holders is None else holders & cls
        rows = [r for r in rows if r["cls"] in (holders or set())]
    if a.get("paramAt"):
        from .seams import split_params
        rows = [r for r in rows if all(len(split_params(r["params"])) > int(i) and split_params(r["params"])[int(i)] == t
                                       for i, t in a["paramAt"].items())]
    if "paramCount" in a:
        from .seams import split_params
        rows = [r for r in rows if len(split_params(r["params"])) == a["paramCount"]]
    if a.get("refName"):
        # `(ref as? MethodReference)?.name` or `(ref as? FieldReference)?.name` — the extractor can't
        # tell which, so accept either (a constructor may write an isAdDisabled FIELD, for example)
        def _ref_names(mid):
            for c in idx.calls_of(mid):
                yield c.split("->")[1].split("(")[0]
            for f in idx.fields_of(mid):
                yield f.split("->")[1].split(":")[0]
        rows = [r for r in rows if a["refName"] in set(_ref_names(r["id"]))]
    if a.get("classHasMethodReturning"):
        want = a["classHasMethodReturning"]
        rows = [r for r in rows if idx.q("SELECT 1 FROM methods m JOIN classes c ON c.id=m.class WHERE c.name=? AND m.ret=? LIMIT 1",
                                         r["cls"], want)]
    if fp.get("strings"):
        rows = [r for r in rows if all(s in idx.strings_of(r["id"]) for s in fp["strings"])]
    if a.get("refContains"):
        rows = [r for r in rows if all(any(x in c for c in idx.calls_of(r["id"])) for x in a["refContains"])]
    return rows


def _kt_fingerprint(fp_id, fp, anchors) -> dict:
    """Build a framework-agnostic matcher descriptor (JSON) from anchors."""
    ret = fp.get("returnType")
    if ret and ret.startswith("L") and not ret.endswith(";"):
        ret += ";"
    d = {"id": fp_id, "returnType": ret, "parameters": fp.get("parameters"),
         "accessFlags": fp.get("accessFlags"), "strings": fp.get("strings") or None, "anchors": {}}
    a = d["anchors"]
    if anchors.get("name"):
        a["methodName"] = anchors["name"]
    if "paramCount" in anchors:
        a["paramCount"] = anchors["paramCount"]
    if anchors.get("paramAt"):
        a["paramAt"] = {str(i): t for i, t in sorted(anchors["paramAt"].items())}
    if anchors.get("classExact"):
        a["classExact"] = anchors["classExact"]
    if anchors.get("classSuffix"):
        a["classSuffix"] = anchors["classSuffix"]
    return {k: v for k, v in d.items() if v not in (None, {}, [])}


MIN_FIX_SCORE = 3  # a rename candidate needs real evidence (strings / .source / same package), not just shape


def _cand_score(cand: str):
    m = re.search(r"\[score (\d+(?:\.\d+)?)\]$", cand)
    return float(m.group(1)) if m else None


def propose_fix(idx, fp, res, claimed=frozenset()):
    """For a drifted fingerprint: re-point the class anchor at the best rename candidate, keep every
    other anchor as the repo wrote it, and prove the result matches exactly one method.

    Only EVIDENCED candidates qualify: a shape-only match (score 0) or a tie with the runner-up is
    a guess, and a "FIX READY" built on a guess is worse than no fix. A method another fingerprint of
    the same app already matches is never a rename target."""
    a = dict(fp.get("customAnchors") or {})
    cands = [c for c in res.get("candidates", []) if "->" in c.split("  [")[0]]
    for i, cand in enumerate(cands[:3]):
        sig = cand.split("  [")[0]
        sc = _cand_score(cand)
        if sc is None or sc < MIN_FIX_SCORE:
            continue
        nxt = _cand_score(cands[i + 1]) if i + 1 < len(cands) else None
        if nxt is not None and nxt >= sc:
            continue  # ambiguous: as good as the next one
        if sig in claimed:
            continue
        new_cls, rest = sig.split("->", 1)
        new_name = rest.split("(")[0]
        trial = dict(a)
        if trial.get("classExact"):
            trial["classExact"] = new_cls
        elif trial.get("classSuffix"):
            trial["classSuffix"] = "/" + new_cls.rstrip(";").rsplit("/", 1)[-1] + ";"
        else:
            trial["classSuffix"] = "/" + new_cls.rstrip(";").rsplit("/", 1)[-1] + ";"
        if a.get("name") and a["name"] != new_name:
            trial["name"] = new_name
        rows = _by_anchors(idx, {**fp, "customAnchors": trial})
        if rows is not None and len(rows) == 1 and idx.sig(rows[0]) == sig:
            changed = {k: (a.get(k), v) for k, v in trial.items() if a.get(k) != v}
            return {"target": sig, "changed": changed, "anchors": trial,
                    "descriptor": _kt_fingerprint(fp["id"], fp, trial), "matches": 1}
    return None


GENERIC_SOURCE = re.compile(r"^(|SourceFile|r8-map-id-.*|R8\$\$.*)$")


def _plain_kt(fp_id, fp, cls, name) -> dict:
    """A plain matcher descriptor (definingClass + name + signature) with the re-pinned class/name."""
    ret = fp.get("returnType")
    if ret and ret.startswith("L") and not ret.endswith(";"):
        ret += ";"
    d = {"id": fp_id, "definingClass": cls, "name": name, "returnType": ret,
         "parameters": fp.get("parameters"), "accessFlags": fp.get("accessFlags"),
         "strings": fp.get("strings") or None}
    return {k: v for k, v in d.items() if v is not None}


def repin_plain(idx, fp, ref=None, claimed=frozenset()):
    """Re-pin a plain (class + name + signature) fingerprint after an R8 rename. Three strategies,
    strongest evidence first; each must land on exactly ONE method:
      A. class unchanged, method renamed: the only method in the class with the declared signature
         (e.g. a renamed method l -> m in the same class);
      B. readable name unique app-wide with the declared signature (suspendGetAdBreaks);
      C. reference scan: the class carrying the same .source file as the class that held it in an
         earlier scan of this app (TvWebFragment.kt: Po/C$c -> Ap/C$c)."""
    if fp.get("hasCustomMatcher") or not fp.get("definingClass") or not fp.get("name"):
        return None
    want_ret = fp.get("returnType")
    if want_ret and want_ret.startswith("L") and not want_ret.endswith(";"):
        want_ret += ";"
    want_params = "".join(fp["parameters"]) if fp.get("parameters") is not None else None

    def shape_ok(r):
        return (want_ret is None or r["ret"] == want_ret) and (want_params is None or r["params"] == want_params)

    def done(r, evidence):
        sig = idx.sig(r)
        if sig in claimed:
            return None
        changed = {}
        if r["cls"] != fp["definingClass"]:
            changed["definingClass"] = (fp["definingClass"], r["cls"])
        if r["name"] != fp["name"]:
            changed["name"] = (fp["name"], r["name"])
        if not changed:
            return None
        return {"target": sig, "changed": changed, "evidence": evidence, "matches": 1,
                "descriptor": _plain_kt(fp["id"], fp, r["cls"], r["name"])}

    cls = fp["definingClass"]
    if idx.class_row(cls) and want_params is not None:
        rows = [r for r in idx.q(idx.METHOD_SQL + "WHERE c.name=?", cls)
                if shape_ok(r) and r["name"] != fp["name"] and not r["name"].startswith("<")]
        if len(rows) == 1:
            return done(rows[0], f"the only method in {cls} with the declared signature (R8 renamed the method)")
    if not is_obfuscated_name(fp["name"]) and want_params is not None:
        rows = [r for r in idx.q(idx.METHOD_SQL + "WHERE m.name=?", fp["name"]) if shape_ok(r)]
        if len(rows) == 1:
            return done(rows[0], f"the only {fp['name']}({want_params}) in the app")
    if ref and ref.get("where", {}).get(fp["id"]):
        old_cls = ref["where"][fp["id"]].split("->")[0]
        crow = ref["idx"].class_row(old_cls)
        src = crow["source"] if crow else None
        if src and not GENERIC_SOURCE.match(src):
            classes = [r[0] for r in idx.q("SELECT name FROM classes WHERE source=?", src)]
            rows = [r for c in classes for r in idx.q(idx.METHOD_SQL + "WHERE c.name=? AND m.name=?", c, fp["name"])
                    if shape_ok(r)]
            if not rows and want_params is not None:  # the method name churned as well
                rows = [r for c in classes for r in idx.q(idx.METHOD_SQL + "WHERE c.name=?", c)
                        if shape_ok(r) and not r["name"].startswith("<")]
            if len(rows) == 1:
                return done(rows[0], f'.source "{src}" — the file {old_cls} came from in {ref.get("version")}')
    return None


def find_reference(out_dir: str, package: str, fp_ids: set, max_scans: int = 300):
    """An earlier (or other) scan of the same app in which these fingerprints matched — the rename
    oracle for repin_plain. Looks in the scan's folder and its parent (results/<app>/<ver>.autopsy)."""
    here = os.path.abspath(out_dir)
    self_key = os.path.normcase(here)
    roots = [os.path.dirname(os.path.dirname(here)), os.path.dirname(here)]
    best, seen = None, 0
    needle = f'"package": "{package}"'
    for root in dict.fromkeys(roots):
        if not os.path.isdir(root):
            continue
        base = root.rstrip("\\/").count(os.sep)
        for dp, dirs, files in os.walk(root):
            if "report.json" in files and "index.sqlite" in files:
                dirs[:] = []
                if os.path.normcase(os.path.abspath(dp)) == self_key or os.path.basename(dp).startswith("."):
                    continue
                seen += 1
                if seen > max_scans:
                    break
                try:
                    with open(os.path.join(dp, "report.json"), encoding="utf-8") as fh:
                        raw = fh.read()
                    if needle not in raw:
                        continue
                    f = json.loads(raw)
                except (OSError, ValueError):
                    continue
                where = {r["id"]: r["where"] for r in (f.get("known_app") or {}).get("results", [])
                         if r.get("status") == "OK" and r.get("where") and "; " not in r["where"]}
                score = len(set(where) & fp_ids)
                key = (score, int((f.get("manifest") or {}).get("versionCode") or 0))
                if score and (best is None or key > best[0]):
                    best = (key, dp, where, (f.get("manifest") or {}).get("versionName"))
                continue
            dirs[:] = [d for d in dirs if d not in ("dex", "draft", "java", "apktool") and not d.startswith(".")]
            if dp.count(os.sep) - base >= 2:
                dirs[:] = []
    if not best:
        return None
    from .index import Index
    return {"idx": Index(best[1]), "where": best[2], "version": best[3], "dir": best[1]}


def check_injected(idx, app, ref=None) -> list[dict]:
    """Obfuscated app classes used inside a patch's injected smali must still exist, or the patch applies
    and then throws NoClassDefFoundError at runtime. A missing one is re-pinned through the reference
    scan: same .source file, same inner-class suffix, same constructor signatures."""
    out = []
    for it in app.get("injectedTypes", []):
        t = it["type"]
        r = {"type": t, "file": it.get("file"), "status": "OK" if idx.class_row(t) else "CLASS_MISSING"}
        if r["status"] != "OK" and ref:
            old = ref["idx"].class_row(t)
            src = old["source"] if old else None
            if src and not GENERIC_SOURCE.match(src):
                inits = sorted(x["params"] for x in ref["idx"].q(
                    ref["idx"].METHOD_SQL + "WHERE c.name=? AND m.name='<init>'", t))
                suffix = t[t.index("$"):] if "$" in t else ""
                cands = []
                for (c,) in idx.q("SELECT name FROM classes WHERE source=?", src):
                    if suffix and not c.endswith(suffix):
                        continue
                    if "$" not in t and "$" in c:
                        continue
                    ci = sorted(x["params"] for x in idx.q(idx.METHOD_SQL + "WHERE c.name=? AND m.name='<init>'", c))
                    if ci == inits:
                        cands.append(c)
                if len(cands) == 1:
                    r["fix"] = {"target": cands[0],
                                "evidence": f'.source "{src}", same inner suffix "{suffix}" and constructors as '
                                            f'{t} in {ref.get("version")}'}
        out.append(r)
    return out


def check(idx, app_key, app, ref=None) -> list[dict]:
    results = []
    for fp in app.get("fingerprints", []):
        res = {"id": fp["id"], "usedBy": fp.get("usedBy", []), "status": None, "issues": [], "candidates": [],
               "where": None}
        cls = fp.get("definingClass")
        name = fp.get("name")
        rows = None if (cls and name) else _by_anchors(idx, fp)
        if rows is not None:
            anchors = fp["customAnchors"]
            res["anchors"] = anchors
            if len(rows) == 1:
                res["status"] = "OK"
                res["where"] = idx.sig(rows[0])
                res["issues"].append("custom matcher evaluated from its anchors " + json.dumps(
                    {k: v for k, v in anchors.items() if k != "unparsed"}))
                if anchors.get("unparsed"):
                    res["partial"] = True
                    res["issues"].append("PARTIAL: not evaluated: " + " | ".join(anchors["unparsed"][:3]))
            elif not rows:
                res["status"] = "METHOD_MISSING"
                res["issues"].append("no method satisfies the custom anchors " + json.dumps(anchors))
                res["candidates"] = _candidates(idx, {**fp, "name": anchors.get("name")})
            else:
                res["status"] = "AMBIGUOUS"
                res["where"] = "; ".join(idx.sig(r) for r in rows[:3])
                res["issues"].append(f"{len(rows)} methods satisfy the custom anchors — a matcher would take the first; tighten it")
            results.append(res)
            continue
        if cls and not cls.endswith(";"):
            # fingerprints may store partial class paths like 'listeners/SomeAdListeners'
            like = idx.q("SELECT name FROM classes WHERE name LIKE ? ESCAPE '\\'", f"%/{esc_like(cls)};")
            cls = like[0][0] if len(like) == 1 else None
        if cls:
            crow = idx.class_row(cls)
            if not crow:
                res["status"] = "CLASS_MISSING"
                res["candidates"] = _candidates(idx, fp)
            elif name:
                rows = idx.find_methods(f"{cls}->{name}")
                if not rows:
                    res["status"] = "METHOD_MISSING"
                    res["candidates"] = _candidates(idx, {**fp, "name": None, "definingClass": cls})
                else:
                    best = None
                    for r in rows:
                        st, iss = _judge(idx, fp, r)
                        if best is None or st == "OK":
                            best = (st, iss, r)
                        if st == "OK":
                            break
                    res["status"], res["issues"], r = best
                    res["where"] = idx.sig(r)
            else:
                res["status"] = "UNVERIFIABLE"
                res["issues"].append("class found; method matched by custom lambda")
        elif fp.get("strings"):
            found = None
            for s in fp["strings"]:
                ids = {r["id"] for r in idx.string_users(s, exact=True, limit=500)}
                found = ids if found is None else found & ids
            if found:
                res["status"] = "FOUND_BY_STRINGS"
                rows = [idx.method(m) for m in list(found)[:3]]
                res["where"] = "; ".join(idx.sig(r) for r in rows)
                if len(found) > 1:
                    res["issues"].append(f"{len(found)} methods hold these strings")
            else:
                res["status"] = "STRINGS_MISSING"
                res["issues"].append(f"no method holds all of {fp['strings']}")
        else:
            res["status"] = "UNVERIFIABLE"
            n = None
            if fp.get("returnType"):
                n = len(_candidates(idx, fp, limit=1000))
            res["issues"].append("custom matcher only" + (f"; {n} method(s) share the declared shape" if n else ""))
        results.append(res)
    claimed = set()
    for res in results:
        if res["status"] == "OK" and res.get("where"):
            claimed.add(res["where"])
    for res, fp in zip(results, app.get("fingerprints", [])):
        res["hard"] = bool(fp.get("hard"))
        if res["status"] in ("METHOD_MISSING", "CLASS_MISSING") and res.get("candidates"):
            fix = propose_fix(idx, fp, res, frozenset(claimed))
            if fix:
                res["fix"] = fix
        if res["status"] in ("METHOD_MISSING", "CLASS_MISSING", "SIGNATURE_CHANGED") and not res.get("fix"):
            fix = repin_plain(idx, fp, ref, frozenset(claimed))
            if fix:
                res["fix"] = fix
                claimed.add(fix["target"])
        if res["status"] not in ("OK", "FOUND_BY_STRINGS", "UNVERIFIABLE"):
            res["impact"] = ("PATCH ABORTS (used via .method)" if res["hard"] else
                             "caught by try/catch — usually skipped, may still abort if resolved eagerly "
                             "(methodOrNull is the reliable form)" if fp.get("caught") else
                             "hook silently skipped (methodOrNull)")
    return results
