"""Command line: `python -m autopsy <command> ...` (or the autopsy.bat / autopsy.sh wrappers)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser

from . import __version__


def _out_for(path: str) -> str:
    base = os.path.splitext(os.path.basename(path))[0]
    return os.path.join(os.path.dirname(os.path.abspath(path)), f"{base}.autopsy")


def cmd_scan(a):
    from .analyze import Autopsy
    from . import report_html, report_md
    out = a.out or _out_for(a.input)
    f = Autopsy(a.input, out, log=(lambda *x: None) if a.quiet else print,
                deep_native=not a.fast, java=not a.no_java, apktool=a.apktool).run()
    md = report_md.render(f, full=False)
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(os.path.join(out, "report-full.md"), "w", encoding="utf-8") as fh:
        fh.write(report_md.render(f, full=True))
    html_path = os.path.join(out, "report.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(report_html.render(f))
    print(f"\nreport.md ({len(md) // 1024} KB, for Claude) · report-full.md · report.html · report.json · index.sqlite")
    print(f"  -> {out}")
    if a.open:
        import pathlib
        webbrowser.open(pathlib.Path(html_path).resolve().as_uri())


def _idx(path):
    from .index import Index
    return Index(path)


def cmd_show(a):
    idx = _idx(a.out)
    rows = idx.find_methods(a.method, limit=20)
    if not rows:
        print("no such method (spec: 'Lcls;->name(params)ret', 'Lcls;->name', 'Lcls;' or '#id')")
        return 1
    for r in rows[: a.limit]:
        print(f"# #{r['id']}  {idx.sig(r)}  [{r['sdk'] or ('app' if r['is_app'] else 'lib')}] source={r['source']}")
        print(idx.smali(r))
        print()


def cmd_xref(a):
    idx = _idx(a.out)
    rows = idx.callers(a.ref, limit=a.limit, exact=a.exact)
    for r in rows:
        print(f"#{r['id']:<7} {'app ' if r['is_app'] else 'lib '} {idx.sig(r)}")
    print(f"({len(rows)} caller(s))")


def cmd_strings(a):
    idx = _idx(a.out)
    rows = idx.string_users(a.text, limit=a.limit, exact=a.exact)
    for r in rows:
        v = r["value"] if len(r["value"]) < 100 else r["value"][:97] + "..."
        print(f"#{r['id']:<7} {'app ' if r['is_app'] else 'lib '} {idx.sig(r)}\n          \"{v}\"")
    print(f"({len(rows)} hit(s))")


def cmd_search(a):
    idx = _idx(a.out)
    pat = f"%{a.pattern}%"
    if a.what in ("class", "all"):
        for r in idx.q("SELECT name, source, sdk, is_app, n_methods FROM classes WHERE lower(name) LIKE lower(?) OR lower(source) LIKE lower(?) LIMIT ?",
                       pat, pat, a.limit):
            print(f"class  {r['name']}  source={r['source']} {r['sdk'] or ('app' if r['is_app'] else 'lib')} ({r['n_methods']} methods)")
    if a.what in ("method", "all"):
        for r in idx.q(idx.METHOD_SQL + "WHERE lower(m.name) LIKE lower(?) LIMIT ?", pat, a.limit):
            print(f"method #{r['id']:<7} {idx.sig(r)}")
    if a.what in ("field", "all"):
        for r in idx.q("SELECT c.name AS cls, f.name, f.type FROM fields f JOIN classes c ON c.id=f.class WHERE lower(f.name) LIKE lower(?) LIMIT ?",
                       pat, a.limit):
            print(f"field  {r['cls']}->{r['name']}:{r['type']}")


def cmd_class(a):
    idx = _idx(a.out)
    c = idx.class_row(a.cls)
    if not c:
        print("no such class")
        return 1
    print(f"{c['name']}  extends {c['super']}  implements {c['interfaces'] or '-'}")
    print(f"source={c['source']}  sdk={c['sdk']}  app={bool(c['is_app'])}  flags={idx.describe_flags(c['flags'])}")
    for fr in idx.q("SELECT name, type, flags FROM fields WHERE class=?", c["id"]):
        print(f"  .field {idx.describe_flags(fr['flags'])} {fr['name']}:{fr['type']}")
    for r in idx.q(idx.METHOD_SQL + "WHERE c.id=?", c["id"]):
        print(f"  #{r['id']:<7} {idx.describe_flags(r['flags']):<28} {r['name']}({r['params']}){r['ret']}  [{r['insns']} insns]")


def cmd_fp(a):
    idx = _idx(a.out)
    from .seams import SeamHunter
    rows = idx.find_methods(a.method, limit=5)
    if not rows:
        print("no such method")
        return 1
    h = SeamHunter(idx)
    for r in rows:
        fp = h.fingerprint(r["id"])
        print(f"// {idx.sig(r)}")
        print(f"// matches {fp['matches']} method(s){' (unique)' if fp['unique'] else ' — tighten before shipping'}")
        for n in fp["notes"]:
            print(f"// {n}")
        print(json.dumps(fp["descriptor"], indent=2))
        print()


def cmd_fxref(a):
    idx = _idx(a.out)
    rows = idx.field_users(a.field, write=(True if a.writes else False if a.reads else None), limit=a.limit)
    for r in rows:
        print(f"#{r['id']:<7} {'WRITE' if r['w'] else 'read '} {r['fref']}\n          in {idx.sig(r)}")
    print(f"({len(rows)} access(es))")


def cmd_impl(a):
    idx = _idx(a.out)
    for n in idx.subclasses(a.type):
        c = idx.class_row(n)
        print(f"{n}  source={c['source']}  {c['sdk'] or ('app' if c['is_app'] else 'lib')}")


def cmd_java(a):
    from .tools import jadx_class
    return jadx_class(a.out, a.cls, a.tool)


def cmd_diff(a):
    from .diff import diff, render
    d = diff(a.old, a.new)
    txt = render(d)
    print(txt)
    if a.write:
        with open(a.write, "w", encoding="utf-8") as fh:
            fh.write(txt)


def cmd_serve(a):
    from .serve import serve
    serve(a.out, a.port, open_browser=not a.no_browser)


def cmd_gui(a):
    from .gui import run
    run(port=a.port, window=not a.no_window)


def cmd_tools(a):
    from .tools import install, which
    if a.action == "install":
        install()
    for k, v in which().items():
        print(f"{k:8} {v or '(not found)'}")


def cmd_update(a):
    from . import selfupdate
    return selfupdate.rollback() if a.rollback else selfupdate.update(a.zip, force=a.force)


def cmd_version(a):
    from . import selfupdate
    return selfupdate.version()


def cmd_stream(a):
    from .stream import analyze_file
    print(analyze_file(a.file))


def cmd_report(a):
    from . import report_html, report_md
    if not os.path.exists(os.path.join(a.out, "report.json")):
        raise SystemExit(f"no report.json in {a.out} — run `autopsy scan` first")
    with open(os.path.join(a.out, "report.json"), encoding="utf-8") as fh:
        f = json.load(fh)
    for name, text in (("report.md", report_md.render(f)), ("report-full.md", report_md.render(f, full=True)),
                       ("report.html", report_html.render(f))):
        with open(os.path.join(a.out, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    print("re-rendered reports in", a.out)


def main(argv=None):
    # piped output (how a Claude session reads it) defaults to cp1252 on Windows: → · — became ?/�
    for stream in (sys.stdout, sys.stderr):  # None under pythonw (the GUI shortcut)
        if stream is not None and hasattr(stream, "reconfigure") and not stream.isatty():
            stream.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="autopsy", description="Deep static ad-seam analyzer for APK/APKM/XAPK bundles "
                                                            "(analysis only — it never patches).")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="full autopsy of an .apk/.apkm/.xapk/.apks")
    s.add_argument("input")
    s.add_argument("-o", "--out", help="output dir (default: <input>.autopsy next to the input)")
    s.add_argument("--fast", action="store_true", help="skip native string scanning (big .so files)")
    s.add_argument("--open", action="store_true", help="open report.html when done")
    s.add_argument("--no-java", action="store_true", help="skip jadx Java excerpts even if jadx is installed")
    s.add_argument("--apktool", action="store_true", help="also write an apktool smali tree")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(fn=cmd_scan)

    for name, fn, helptext, argname in (
            ("show", cmd_show, "smali of a method: 'Lcls;->name(params)ret' | 'Lcls;->name' | 'Lcls;' | '#id'", "method"),
            ("fp", cmd_fp, "draft a method matcher/fingerprint and count how many methods it matches", "method")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("out", help="autopsy output dir")
        s.add_argument(argname)
        s.add_argument("-n", "--limit", type=int, default=5)
        s.set_defaults(fn=fn)

    s = sub.add_parser("xref", help="callers of a method ref (substring, or --exact full ref)")
    s.add_argument("out"); s.add_argument("ref")
    s.add_argument("--exact", action="store_true"); s.add_argument("-n", "--limit", type=int, default=200)
    s.set_defaults(fn=cmd_xref)

    s = sub.add_parser("strings", help="methods that use a const-string (substring, or --exact)")
    s.add_argument("out"); s.add_argument("text")
    s.add_argument("--exact", action="store_true"); s.add_argument("-n", "--limit", type=int, default=200)
    s.set_defaults(fn=cmd_strings)

    s = sub.add_parser("fxref", help="who reads/writes a field (substring of 'Lcls;->name:type')")
    s.add_argument("out"); s.add_argument("field")
    s.add_argument("--writes", action="store_true"); s.add_argument("--reads", action="store_true")
    s.add_argument("-n", "--limit", type=int, default=200)
    s.set_defaults(fn=cmd_fxref)

    s = sub.add_parser("impl", help="classes extending/implementing a type (transitive)")
    s.add_argument("out"); s.add_argument("type")
    s.set_defaults(fn=cmd_impl)

    s = sub.add_parser("search", help="find classes / methods / fields by name (substring)")
    s.add_argument("out"); s.add_argument("pattern")
    s.add_argument("-w", "--what", choices=["class", "method", "field", "all"], default="all")
    s.add_argument("-n", "--limit", type=int, default=100)
    s.set_defaults(fn=cmd_search)

    s = sub.add_parser("class", help="outline one class (fields, methods, ids)")
    s.add_argument("out"); s.add_argument("cls")
    s.set_defaults(fn=cmd_class)

    s = sub.add_parser("java", help="decompile ONE class to Java with jadx (needs `autopsy tools install` or jadx on PATH)")
    s.add_argument("out"); s.add_argument("cls")
    s.add_argument("--tool", help="path to jadx / jadx.bat")
    s.set_defaults(fn=cmd_java)

    s = sub.add_parser("diff", help="compare two autopsies (old -> new build): renames, drifted seams, new ad code")
    s.add_argument("old"); s.add_argument("new")
    s.add_argument("-w", "--write", help="also write the diff to this .md file")
    s.set_defaults(fn=cmd_diff)

    s = sub.add_parser("serve", help="local web explorer for an autopsy (search, smali, xrefs)")
    s.add_argument("out"); s.add_argument("-p", "--port", type=int, default=8765)
    s.add_argument("--no-browser", action="store_true")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("gui", help="SeamHunter desktop app: library, scan with progress, reports, explorer, compare")
    s.add_argument("-p", "--port", type=int, default=0, help="port on 127.0.0.1 (default: a free one)")
    s.add_argument("--no-window", action="store_true", help="just serve; open the printed URL yourself")
    s.set_defaults(fn=cmd_gui)

    s = sub.add_parser("report", help="re-render report.md/html from report.json")
    s.add_argument("out")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("tools", help="show (or install) optional helpers: jadx, apktool")
    s.add_argument("action", nargs="?", choices=["which", "install"], default="which")
    s.set_defaults(fn=cmd_tools)

    s = sub.add_parser("update", help="install a newer apk-autopsy zip (default: newest in Downloads), with backup")
    s.add_argument("zip", nargs="?")
    s.add_argument("--rollback", action="store_true", help="restore the previous version")
    s.add_argument("--force", action="store_true", help="reinstall even if not newer")
    s.set_defaults(fn=cmd_update)

    s = sub.add_parser("version", help="installed version and install path")
    s.set_defaults(fn=cmd_version)

    s = sub.add_parser("stream", help="scan a captured HLS/DASH manifest (.m3u8/.mpd) for ad markers")
    s.add_argument("file")
    s.set_defaults(fn=cmd_stream)

    a = p.parse_args(argv)
    for attr in ("out", "old", "new"):
        v = getattr(a, attr, None)
        if v and a.cmd not in ("scan",) and not os.path.exists(v):
            raise SystemExit(f"not found: {v}")
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass
    rc = a.fn(a)
    sys.exit(rc or 0)
