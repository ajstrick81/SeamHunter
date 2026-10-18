"""Seamhunter desktop GUI: `autopsy gui`.

A local app window (Edge/Chrome `--app` mode, falling back to the default browser) over a stdlib
HTTP server bound to 127.0.0.1 on a random port. Every API call carries a per-session token, the
Host header must be local (DNS-rebinding guard), and nothing is fetched from the network: fonts,
icons and branding ship in gui_static/.

Scans run as child processes (`autopsy scan`), one at a time from a queue, so a crash or a 2-minute
index build never blocks the window. The server exits when the window closes (or, in a plain
browser tab, when the page stops sending heartbeats) and no scan is running.
"""
from __future__ import annotations

import html
import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

from . import __version__

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "gui_static")
APP_ROOT = os.path.dirname(HERE)
MAIN = os.path.join(APP_ROOT, "autopsy_main.py")
# APK_AUTOPSY_GUI_HOME: a separate settings/port/profile folder (a second, test instance)
CONF_DIR = os.environ.get("APK_AUTOPSY_GUI_HOME") or os.path.join(os.path.expanduser("~"), ".apk-autopsy")
SETTINGS_PATH = os.path.join(CONF_DIR, "gui.json")
PORT_FILE = os.path.join(CONF_DIR, "gui.port")
WIN = os.name == "nt"
NO_WINDOW = 0x08000000 if WIN else 0  # CREATE_NO_WINDOW: no console flash for child processes
EXTS = (".apk", ".apkm", ".xapk", ".apks")
SCAN_DIR_SUFFIXES = (".autopsy", ".seamhunter")
STEPS = ["Opening the bundle", "Manifest + resources", "Scanning assets", "Indexing DEX bytecode",
         "Native libraries", "SDKs, protections, hosts", "Hunting ad seams", "Known-app drift check",
         "Writing findings"]
SCAN_FILES = {"icon.png", "icon.webp", "icon.jpg", "banner.png", "banner.webp", "banner.jpg", "report.html",
              "report.md", "report-full.md"}
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".png": "image/png", ".webp": "image/webp", ".jpg": "image/jpeg", ".svg": "image/svg+xml",
        ".ttf": "font/ttf", ".ico": "image/x-icon", ".md": "text/markdown; charset=utf-8", ".json": "application/json"}

DEFAULTS = {
    "results_dirs": [os.path.join(os.path.expanduser("~"), "Seamhunter", "scans")],
    "library_dirs": [],
    "scan": {"fast": False, "java": False, "apktool": False},
}


# ------------------------------------------------------------------ settings
def load_settings() -> dict:
    s = json.loads(json.dumps(DEFAULTS))
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            got = json.load(f)
        for k in DEFAULTS:
            if k in got:
                s[k] = got[k]
    except (OSError, ValueError):
        pass
    return s


def save_settings(s: dict):
    os.makedirs(CONF_DIR, exist_ok=True)
    clean = {
        "results_dirs": [os.path.normpath(p) for p in s.get("results_dirs", []) if isinstance(p, str) and p.strip()],
        "library_dirs": [os.path.normpath(p) for p in s.get("library_dirs", []) if isinstance(p, str) and p.strip()],
        "scan": {k: bool((s.get("scan") or {}).get(k)) for k in DEFAULTS["scan"]},
    }
    if not clean["results_dirs"]:
        clean["results_dirs"] = DEFAULTS["results_dirs"]
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=1)
    os.replace(tmp, SETTINGS_PATH)
    return clean


# ------------------------------------------------------------------ scans on disk
def _within(path: str, roots) -> bool:
    rp = os.path.normcase(os.path.realpath(path))
    for r in roots:
        rr = os.path.normcase(os.path.realpath(r))
        if rp == rr or rp.startswith(rr.rstrip("\\/") + os.sep):
            return True
    return False


def find_scans(roots, max_depth=4):
    for root in roots:
        if not os.path.isdir(root):
            continue
        base = root.rstrip("\\/").count(os.sep)
        for dp, dirs, files in os.walk(root):
            if "report.json" in files and "index.sqlite" in files:
                dirs[:] = []
                yield dp
                continue
            dirs[:] = [d for d in dirs if not d.startswith((".", "_uploads")) and d not in ("dex", "draft", "java", "apktool")]
            if dp.count(os.sep) - base >= max_depth:
                dirs[:] = []


_summary_cache: dict[str, tuple[float, dict]] = {}


def _clean_name(n: str | None) -> str | None:
    if not n:
        return None
    n = html.unescape(n)
    n = re.sub(r"\s*\((Android TV|TV)\)\s*$", "", n)
    return n.split(":")[0].strip() or None


def summarize(d: str) -> dict | None:
    rp = os.path.join(d, "report.json")
    try:
        mt = os.path.getmtime(rp)
    except OSError:
        return None
    hit = _summary_cache.get(d)
    if hit and hit[0] == mt:
        return hit[1]
    try:
        with open(rp, encoding="utf-8") as f:
            r = json.load(f)
    except (OSError, ValueError):
        return None
    m = r.get("manifest") or {}
    b = r.get("bundle") or {}
    info = b.get("info") or {}
    ka = r.get("known_app") or None
    art = {}
    for k in ("icon", "banner"):
        for ext in (".png", ".webp", ".jpg"):
            if os.path.exists(os.path.join(d, k + ext)):
                art[k] = k + ext
                break
    src = None
    try:
        with open(os.path.join(d, ".source"), encoding="utf-8") as f:
            src = f.read().strip()
    except OSError:
        pass
    drift = None
    if ka:
        res = ka.get("results") or []
        bad = [x for x in res if x.get("status") not in ("OK", "FOUND_BY_STRINGS", "UNVERIFIABLE", "AMBIGUOUS")]
        n_cm = sum(x.get("status") == "CLASS_MISSING" for x in res)
        drift = {"total": len(res), "ok": sum(x.get("status") == "OK" for x in res), "bad": len(bad),
                 "hard": sum(1 for x in bad if x.get("hard")), "fixes": sum(1 for x in res if x.get("fix")),
                 "lineage": n_cm >= 3 and n_cm >= 0.7 * len(res) and (
                     any(x.get("status") == "CLASS_MISSING" and x.get("hard") for x in res)
                     or not any(x.get("status") == "OK" for x in res))}
    code = r.get("code") or {}
    s = {
        "dir": d, "package": m.get("package") or "?", "version": m.get("versionName") or "?",
        "code": m.get("versionCode"), "name": _clean_name(info.get("app_name")), "tool": r.get("tool"),
        "scanned": mt, "input": r.get("input"), "source": src, "kind": b.get("kind"),
        "size": b.get("size"), "known": ka.get("key") if ka else None,
        "target": bool(ka and ka.get("version_is_target")), "drift": drift,
        "engine": (r.get("engine_guess") or [None])[0], "art": art,
        "classes": code.get("classes"), "elapsed": r.get("elapsed_seconds"),
        "candidates": len((r.get("seams") or {}).get("candidates") or []),
        "hooks": len((r.get("drafts") or {}).get("hooks") or []),
        "trackers": (r.get("trackers") or {}).get("count"),
        "tv": bool(m.get("tv")),
        "md_kb": round(os.path.getsize(os.path.join(d, "report.md")) / 1024) if os.path.exists(os.path.join(d, "report.md")) else None,
    }
    _summary_cache[d] = (mt, s)
    return s


def backfill_art(gui) -> None:
    """Scans made before 1.7 have no icon/banner: find their input (the .source pointer, or the same file
    name in a library folder with a matching package) and extract the art once. Marked with .art-tried."""
    from .art import extract
    from .container import open_bundle
    from .resources import ResourceTable, parse_axml
    todo = []
    for d in find_scans(gui.roots()):
        if any(os.path.exists(os.path.join(d, k + e)) for k in ("icon", "banner") for e in (".png", ".webp", ".jpg")):
            continue
        if not os.path.exists(os.path.join(d, ".art-tried")):
            todo.append(d)
    if not todo:
        return
    gui.art_pending = len(todo)
    by_name: dict[str, list[str]] = {}
    for ld in gui.settings["library_dirs"]:
        for dp, dn, fn in os.walk(ld):
            dn[:] = [x for x in dn if not x.endswith(SCAN_DIR_SUFFIXES)]
            for n in fn:
                if n.lower().endswith(EXTS):
                    by_name.setdefault(n.lower(), []).append(os.path.join(dp, n))
    for d in todo:
        try:
            s = summarize(d) or {}
            src = s.get("source") if s.get("source") and os.path.isfile(s["source"]) else None
            cands = [src] if src else by_name.get((s.get("input") or "").lower(), [])
            for p in cands:
                b = open_bundle(p)
                try:
                    base = b.base
                    man = parse_axml(base.read("AndroidManifest.xml"))
                    if man.get("attrs", {}).get("package") != s.get("package"):
                        continue
                    app = next((c for c in man.get("children", []) if c.get("tag") == "application"), {"attrs": {}})
                    res = ResourceTable(base.read("resources.arsc")) if "resources.arsc" in base.names() else None
                    extract(b, res, app.get("attrs", {}), d)
                    with open(os.path.join(d, ".source"), "w", encoding="utf-8") as fh:
                        fh.write(os.path.abspath(p))
                    break
                finally:
                    for sp in b.splits:
                        try:
                            sp.zf.close()
                        except Exception:  # noqa: BLE001
                            pass
        except Exception:  # noqa: BLE001 - art is cosmetic; never break the app over it
            pass
        try:
            open(os.path.join(d, ".art-tried"), "w").close()
        except OSError:
            pass
        _summary_cache.pop(d, None)
        gui.art_pending -= 1
    gui.art_pending = 0


# ------------------------------------------------------------------ scan jobs
def _child_python() -> str:
    exe = sys.executable
    if exe.lower().endswith("pythonw.exe"):
        alt = exe[:-len("pythonw.exe")] + "python.exe"
        if os.path.exists(alt):
            return alt
    return exe


class Job:
    def __init__(self, path: str, opts: dict, results_root: str, cleanup_input=False, display=None, replace=None):
        self.id = uuid.uuid4().hex[:10]
        self.replace = replace  # an existing scan dir this rescan overwrites
        self.input = path
        self.display = display or os.path.basename(path)
        self.opts = opts
        self.root = results_root
        self.cleanup_input = cleanup_input
        self.status = "queued"
        self.step = 0
        self.step_times: list[float] = []
        self.log: list[str] = []
        self.created = time.time()
        self.started = None
        self.ended = None
        self.out = None
        self.error = None
        self.proc = None
        self.cancelled = False

    def brief(self):
        return {"id": self.id, "input": self.input, "display": self.display, "status": self.status,
                "step": self.step, "steps": len(STEPS), "started": self.started, "ended": self.ended,
                "out": self.out, "error": self.error, "created": self.created}

    def full(self, since=0):
        d = self.brief()
        d["log"] = self.log[since:]
        d["log_total"] = len(self.log)
        d["step_times"] = self.step_times
        d["step_names"] = STEPS
        return d


class Scanner:
    def __init__(self, gui):
        self.gui = gui
        self.q: queue.Queue[Job] = queue.Queue()
        self.jobs: dict[str, Job] = {}
        threading.Thread(target=self._worker, daemon=True).start()

    def submit(self, job: Job):
        self.jobs[job.id] = job
        self.q.put(job)
        return job

    def busy(self) -> bool:
        return any(j.status in ("queued", "running") for j in self.jobs.values())

    def cancel(self, jid):
        j = self.jobs.get(jid)
        if not j:
            return False
        j.cancelled = True
        if j.status == "queued":
            j.status = "cancelled"
        elif j.proc and j.proc.poll() is None:
            j.proc.terminate()
        return True

    def _worker(self):
        while True:
            job = self.q.get()
            if job.status == "cancelled":
                continue
            try:
                self._run(job)
            except Exception as e:  # noqa: BLE001 - a job failure must never kill the worker
                job.status, job.error = "failed", f"{type(e).__name__}: {e}"
            finally:
                job.ended = time.time()
                if job.cleanup_input:
                    try:
                        os.remove(job.input)
                    except OSError:
                        pass

    def _run(self, job: Job):
        os.makedirs(job.root, exist_ok=True)
        tmp = os.path.join(job.root, f".scanning-{job.id}")
        cmd = [_child_python(), "-W", "ignore", MAIN, "scan", job.input, "-o", tmp]
        if job.opts.get("fast"):
            cmd.append("--fast")
        if not job.opts.get("java"):
            cmd.append("--no-java")
        if job.opts.get("apktool"):
            cmd.append("--apktool")
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
        job.status, job.started = "running", time.time()
        job.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    encoding="utf-8", errors="replace", bufsize=1, env=env,
                                    creationflags=NO_WINDOW, cwd=APP_ROOT)
        for line in job.proc.stdout:
            line = line.rstrip("\n")
            m = re.match(r"^\[(\d+)/(\d+)\]", line)
            if m:
                job.step = int(m.group(1))
                job.step_times.append(time.time())
            if line.strip():
                job.log.append(line)
                if len(job.log) > 4000:
                    del job.log[:1000]
        rc = job.proc.wait()
        if job.cancelled:
            job.status = "cancelled"
            shutil.rmtree(tmp, ignore_errors=True)
            return
        if rc != 0 or not os.path.exists(os.path.join(tmp, "report.json")):
            job.status = "failed"
            job.error = next((ln for ln in reversed(job.log) if ln.strip()), f"exit code {rc}")
            shutil.rmtree(tmp, ignore_errors=True)
            return
        job.out = self._place(job, tmp)
        job.step = len(STEPS)
        job.status = "done"

    def _place(self, job: Job, tmp: str) -> str:
        """Move the finished scan to <root>/<package>/<version>.autopsy (replacing a scan of the same input)."""
        if job.replace and os.path.exists(os.path.join(job.replace, "report.json")):
            self.gui.close_explorer(job.replace)
            shutil.rmtree(job.replace)
            os.replace(tmp, job.replace)
            return job.replace
        with open(os.path.join(tmp, "report.json"), encoding="utf-8") as f:
            m = (json.load(f).get("manifest") or {})
        safe = lambda s: re.sub(r"[^\w.+-]", "_", str(s or "unknown"))[:80]  # noqa: E731
        folder = os.path.join(job.root, safe(m.get("package")))
        os.makedirs(folder, exist_ok=True)
        base = os.path.join(folder, safe(m.get("versionName")))
        dest, n = base + ".autopsy", 2
        while os.path.exists(dest):
            same_input = False
            try:
                with open(os.path.join(dest, ".source"), encoding="utf-8") as f:
                    same_input = os.path.normcase(f.read().strip()) == os.path.normcase(os.path.abspath(job.input))
            except OSError:
                pass
            if (same_input or job.cleanup_input) and os.path.exists(os.path.join(dest, "report.json")):
                self.gui.close_explorer(dest)
                shutil.rmtree(dest)
                break
            dest, n = f"{base}-{n}.autopsy", n + 1
        os.replace(tmp, dest)
        if job.cleanup_input:
            # an upload is deleted after the scan: point .source at nothing rather than a dangling temp path
            try:
                os.remove(os.path.join(dest, ".source"))
            except OSError:
                pass
        return dest


# ------------------------------------------------------------------ the app
class Gui:
    def __init__(self):
        self.settings = load_settings()
        self.token = secrets.token_urlsafe(24)
        self.scanner = Scanner(self)
        self.explorers: dict[str, tuple] = {}
        self.exp_lock = threading.Lock()
        self.last_ping = time.time()
        self.window = None
        self.art_pending = 0
        threading.Thread(target=backfill_art, args=(self,), daemon=True).start()

    # --- helpers
    def roots(self):
        return self.settings["results_dirs"]

    def scan_dir(self, d: str) -> str:
        if not d or not _within(d, self.roots()) or not os.path.exists(os.path.join(d, "report.json")):
            raise PermissionError("not a scan inside your results folders")
        return os.path.realpath(d)

    def explorer(self, d: str):
        from .serve import make_api
        d = self.scan_dir(d)
        with self.exp_lock:
            if d not in self.explorers:
                if len(self.explorers) >= 3:
                    old = next(iter(self.explorers))
                    self._close(old)
                self.explorers[d] = make_api(d)
            return self.explorers[d]

    def _close(self, d):
        ex = self.explorers.pop(d, None)
        if ex:
            try:
                ex[2].db.close()
            except Exception:  # noqa: BLE001
                pass

    def close_explorer(self, d):
        with self.exp_lock:
            for k in list(self.explorers):
                if os.path.normcase(k) == os.path.normcase(os.path.realpath(d)):
                    self._close(k)

    # --- API
    def api_get(self, path: str, qs: dict):
        g = lambda k, dflt="": qs.get(k, [dflt])[0]  # noqa: E731
        if path == "/api/ping":
            self.last_ping = time.time()
            return {"ok": True, "busy": self.scanner.busy()}
        if path == "/api/state":
            from .tools import which
            try:
                tools = which()
            except Exception:  # noqa: BLE001
                tools = {}
            return {"version": __version__, "settings": self.settings, "tools": tools, "app_root": APP_ROOT,
                    "conf": SETTINGS_PATH, "art_pending": self.art_pending, "jobs": [j.brief() for j in self.scanner.jobs.values()]}
        if path == "/api/scans":
            out = [s for s in (summarize(d) for d in find_scans(self.roots())) if s]
            return {"scans": out, "roots": self.roots(), "art_pending": self.art_pending}
        if path == "/api/library":
            scans = [s for s in (summarize(d) for d in find_scans(self.roots())) if s]
            by_src = {}
            by_name = {}
            for s in scans:
                if s.get("source"):
                    by_src.setdefault(os.path.normcase(s["source"]), []).append(s["dir"])
                if s.get("input"):
                    by_name.setdefault(s["input"].lower(), []).append(s["dir"])
            dirs = []
            for ld in self.settings["library_dirs"]:
                files = []
                if os.path.isdir(ld):
                    for dp, dn, fn in os.walk(ld):
                        dn[:] = [x for x in dn if not x.startswith(".") and not x.endswith(SCAN_DIR_SUFFIXES)]
                        for n in fn:
                            if n.lower().endswith(EXTS):
                                p = os.path.join(dp, n)
                                try:
                                    st = os.stat(p)
                                except OSError:
                                    continue
                                files.append({"path": p, "name": n, "rel": os.path.relpath(p, ld), "size": st.st_size,
                                              "mtime": st.st_mtime,
                                              "scans": by_src.get(os.path.normcase(p)) or by_name.get(n.lower()) or []})
                        if len(files) > 2000:
                            break
                files.sort(key=lambda x: x["rel"].lower())
                dirs.append({"dir": ld, "exists": os.path.isdir(ld), "files": files})
            return {"dirs": dirs}
        if path == "/api/jobs":
            return {"jobs": [j.brief() for j in sorted(self.scanner.jobs.values(), key=lambda j: -j.created)]}
        if path == "/api/job":
            j = self.scanner.jobs.get(g("id"))
            if not j:
                return {"error": "no such job"}
            return j.full(int(g("since", "0") or 0))
        if path == "/api/report":
            d = self.scan_dir(g("dir"))
            with open(os.path.join(d, "report.json"), encoding="utf-8") as f:
                rep = json.load(f)
            md = ""
            if os.path.exists(os.path.join(d, "report.md")):
                with open(os.path.join(d, "report.md"), encoding="utf-8") as f:
                    md = f.read()
            drafts = {}
            for dp, _dn, fn in os.walk(os.path.join(d, "draft")):
                for n in sorted(fn):
                    p = os.path.join(dp, n)
                    if os.path.getsize(p) < 400_000:
                        with open(p, encoding="utf-8", errors="replace") as f:
                            drafts[os.path.relpath(p, os.path.join(d, "draft")).replace("\\", "/")] = f.read()
            return {"dir": d, "summary": summarize(d), "report": rep, "md": md, "drafts": drafts}
        if path == "/api/diff":
            from .diff import diff, render
            a, b = self.scan_dir(g("a")), self.scan_dir(g("b"))
            dd = diff(a, b)
            return {"diff": dd, "md": render(dd)}
        if path.startswith("/api/x/"):
            api, lock, _idx, _rep = self.explorer(g("dir"))
            with lock:
                return api("/api/" + path[len("/api/x/"):], qs)
        return {"error": "unknown endpoint"}

    def api_post(self, path: str, body: dict):
        if path == "/api/scan":
            p = body.get("path") or ""
            if not os.path.isfile(p) or not p.lower().endswith(EXTS):
                return {"error": "pick an .apk, .apkm, .xapk or .apks file"}
            opts = {**self.settings["scan"], **(body.get("opts") or {})}
            replace = self.scan_dir(body["replace"]) if body.get("replace") else None
            j = self.scanner.submit(Job(os.path.abspath(p), opts, self.roots()[0], replace=replace))
            return {"job": j.brief()}
        if path == "/api/cancel":
            return {"ok": self.scanner.cancel(body.get("id"))}
        if path == "/api/settings":
            self.settings = save_settings({**self.settings, **(body.get("settings") or {})})
            _summary_cache.clear()
            return {"settings": self.settings}
        if path == "/api/open":
            target = body.get("path") or ""
            ok = (os.path.isdir(target) and (_within(target, self.roots()) or _within(target, self.settings["library_dirs"])))
            if not ok:
                return {"error": "only scan / library folders can be opened"}
            if WIN:
                open_folder(target)
            return {"ok": True}
        if path == "/api/delete":
            d = self.scan_dir(body.get("dir"))
            if not d.lower().endswith(SCAN_DIR_SUFFIXES):
                return {"error": "refusing to delete a folder that is not a scan"}
            self.close_explorer(d)
            shutil.rmtree(d)
            _summary_cache.pop(d, None)
            return {"ok": True}
        if path == "/api/pick":
            return {"path": pick(body.get("kind") or "file")}
        return {"error": "unknown endpoint"}

    def upload(self, handler, name: str):
        name = os.path.basename(name or "")
        if not name.lower().endswith(EXTS):
            return {"error": "drop an .apk, .apkm, .xapk or .apks file"}
        n = int(handler.headers.get("Content-Length") or 0)
        if n <= 0:
            return {"error": "empty upload"}
        up = os.path.join(self.roots()[0], "_uploads")
        os.makedirs(up, exist_ok=True)
        dest = os.path.join(up, f"{uuid.uuid4().hex[:8]}-{name}")
        left = n
        with open(dest, "wb") as f:
            while left > 0:
                chunk = handler.rfile.read(min(left, 1 << 20))
                if not chunk:
                    break
                f.write(chunk)
                left -= len(chunk)
        if left:
            os.remove(dest)
            return {"error": "upload interrupted"}
        j = self.scanner.submit(Job(dest, dict(self.settings["scan"]), self.roots()[0], cleanup_input=True, display=name))
        return {"job": j.brief()}


def _explorer_windows() -> set:
    """HWNDs of open File Explorer windows (class CabinetWClass)."""
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    found = set()
    buf = ctypes.create_unicode_buffer(64)

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _lp):
        user32.GetClassNameW(hwnd, buf, 64)
        if buf.value == "CabinetWClass" and user32.IsWindowVisible(hwnd):
            found.add(hwnd)
        return True
    user32.EnumWindows(cb, 0)
    return found


def open_folder(path: str):
    """Open a folder in Explorer IN FRONT of the app window. The server is a background process, so
    Windows' focus-stealing guard would leave a plain os.startfile() window hidden behind SeamHunter."""
    try:
        import ctypes
        user32 = ctypes.windll.user32
        before = _explorer_windows()
        subprocess.Popen(["explorer.exe", os.path.normpath(path)])
        new = None
        for _ in range(40):  # up to ~4 s for the window to appear
            time.sleep(0.1)
            fresh = _explorer_windows() - before
            if fresh:
                new = fresh.pop()
                break
        if new:
            # a synthetic Alt tap satisfies the foreground-lock rules, then raise the window
            user32.keybd_event(0x12, 0, 0, 0)
            user32.keybd_event(0x12, 0, 2, 0)
            user32.ShowWindow(new, 9)  # SW_RESTORE
            user32.SetForegroundWindow(new)
    except Exception:  # noqa: BLE001 - never fail the request over window cosmetics
        os.startfile(path)  # noqa: S606


def pick(kind: str) -> str:
    """Native Open dialog (tkinter, stdlib) in a child process so it never fights the server threads."""
    if kind == "folder":
        call = "f.askdirectory(title='Choose a folder', mustexist=True)"
    else:
        call = ("f.askopenfilename(title='Choose an Android app bundle', "
                "filetypes=[('Android apps', '*.apk *.apkm *.xapk *.apks'), ('All files', '*.*')])")
    code = ("import tkinter as t, tkinter.filedialog as f\n"
            "r = t.Tk(); r.withdraw(); r.attributes('-topmost', True)\n"
            f"p = {call}\n"
            "print(p or '')")
    try:
        out = subprocess.run([_child_python(), "-c", code], capture_output=True, text=True, timeout=600,
                             creationflags=NO_WINDOW)
        return os.path.normpath(out.stdout.strip()) if out.stdout.strip() else ""
    except (OSError, subprocess.SubprocessError):
        return ""


# ------------------------------------------------------------------ HTTP
def _handler(gui: Gui):
    csp = ("default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
           "font-src 'self'; frame-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'")

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, body: bytes, ctype: str, code=200, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, code=200):
            self._send(json.dumps(data, default=str).encode(), "application/json", code)

        def _guard(self, need_token=True) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            if host not in ("127.0.0.1", "localhost"):
                self._send(b"forbidden host", "text/plain", 403)
                return False
            if need_token:
                qs = parse_qs(urlparse(self.path).query)
                tok = self.headers.get("X-Seam-Token") or qs.get("t", [""])[0]
                if not secrets.compare_digest(tok, gui.token):
                    self._send(b"bad token", "text/plain", 403)
                    return False
            return True

        def _static(self, rel: str):
            p = os.path.realpath(os.path.join(STATIC, rel))
            if not p.startswith(os.path.realpath(STATIC) + os.sep) or not os.path.isfile(p):
                return self._send(b"not found", "text/plain", 404)
            with open(p, "rb") as f:
                data = f.read()
            if rel == "index.html":
                data = data.replace(b"__SEAM_TOKEN__", gui.token.encode())
                return self._send(data, MIME[".html"], extra={"Content-Security-Policy": csp})
            return self._send(data, MIME.get(os.path.splitext(p)[1].lower(), "application/octet-stream"),
                              extra={"Cache-Control": "max-age=3600"})

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/api/alive":  # unauthenticated: lets a second launch find this instance
                if not self._guard(need_token=False):
                    return
                return self._send(b"seamhunter", "text/plain")
            if u.path in ("/", "/index.html"):
                if not self._guard(need_token=False):
                    return
                return self._static("index.html")
            if u.path.startswith("/static/"):
                if not self._guard(need_token=False):
                    return
                return self._static(u.path[len("/static/"):])
            if not self._guard():
                return
            qs = parse_qs(u.query)
            if u.path == "/files":
                try:
                    d = gui.scan_dir(qs.get("dir", [""])[0])
                except PermissionError as e:
                    return self._send(str(e).encode(), "text/plain", 403)
                f = qs.get("f", [""])[0]
                if f not in SCAN_FILES or not os.path.isfile(os.path.join(d, f)):
                    return self._send(b"not found", "text/plain", 404)
                with open(os.path.join(d, f), "rb") as fh:
                    data = fh.read()
                extra = {"Cache-Control": "max-age=600"}
                if f.endswith(".html"):
                    extra = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                                        "script-src 'unsafe-inline'; img-src data:"}
                return self._send(data, MIME.get(os.path.splitext(f)[1], "application/octet-stream"), extra=extra)
            if u.path.startswith("/api/"):
                try:
                    return self._json(gui.api_get(u.path, qs))
                except PermissionError as e:
                    return self._json({"error": str(e)}, 403)
                except Exception as e:  # noqa: BLE001 - surface it in the window
                    return self._json({"error": f"{type(e).__name__}: {e}"}, 500)
            return self._send(b"not found", "text/plain", 404)

        def do_POST(self):
            if not self._guard():
                return
            u = urlparse(self.path)
            try:
                if u.path == "/api/upload":
                    return self._json(gui.upload(self, parse_qs(u.query).get("name", [""])[0]))
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
                return self._json(gui.api_post(u.path, body))
            except PermissionError as e:
                return self._json({"error": str(e)}, 403)
            except Exception as e:  # noqa: BLE001
                return self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    return H


# ------------------------------------------------------------------ window + lifetime
def _browser_exe():
    cands = []
    for env in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if base:
            cands += [os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
                      os.path.join(base, "Google", "Chrome", "Application", "chrome.exe")]
    cands += [shutil.which(n) for n in ("msedge", "google-chrome", "chromium", "chromium-browser", "chrome")]
    return next((c for c in cands if c and os.path.exists(c)), None)


def open_window(url: str):
    exe = _browser_exe()
    if exe:
        profile = os.path.join(CONF_DIR, "gui-profile")
        os.makedirs(profile, exist_ok=True)
        try:
            return subprocess.Popen([exe, f"--app={url}", f"--user-data-dir={profile}", "--window-size=1440,920",
                                     "--no-first-run", "--no-default-browser-check", "--disable-sync",
                                     "--disable-features=Translate,msEdgeSidebarV2,msUndersideButton"],
                                    creationflags=NO_WINDOW)
        except OSError:
            pass
    webbrowser.open(url)
    return None


def _existing_instance():
    try:
        with open(PORT_FILE, encoding="utf-8") as f:
            port = int(json.load(f)["port"])
        with urlopen(f"http://127.0.0.1:{port}/api/alive", timeout=1.5) as r:
            if r.read() == b"seamhunter":
                return port
    except (OSError, ValueError, KeyError):
        return None
    return None


def run(port: int = 0, window: bool = True):
    port_in_use = _existing_instance()
    if port_in_use and window:
        open_window(f"http://127.0.0.1:{port_in_use}/")
        return
    gui = Gui()
    srv = ThreadingHTTPServer(("127.0.0.1", port), _handler(gui))
    srv.daemon_threads = True
    port = srv.server_address[1]
    os.makedirs(CONF_DIR, exist_ok=True)
    with open(PORT_FILE, "w", encoding="utf-8") as f:
        json.dump({"port": port, "pid": os.getpid()}, f)
    url = f"http://127.0.0.1:{port}/"
    print(f"Seamhunter {__version__} on {url}  (close the window to quit)", flush=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    if window:
        gui.window = open_window(url)
    gui.last_ping = time.time()
    try:
        while True:
            time.sleep(2)
            if gui.scanner.busy():
                continue
            closed = gui.window is not None and gui.window.poll() is not None
            stale = time.time() - gui.last_ping > (90 if window else 10**9)
            if closed or (gui.window is None and window and stale):
                # the Edge launcher may hand off and exit: fall back to heartbeats before quitting
                if closed and time.time() - gui.last_ping < 25:
                    gui.window = None
                    continue
                break
    except KeyboardInterrupt:
        pass
    srv.shutdown()
    for d in list(gui.explorers):
        gui._close(d)
    try:
        os.remove(PORT_FILE)
    except OSError:
        pass
