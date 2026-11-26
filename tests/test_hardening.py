"""Regression tests for the hardening fixes: damaged/bomb splits, safe DEX file names, the cmd.exe guard,
GUI keep-alive handling and token rules, the sandboxed report frame, and confirmed auto-updates."""
import io
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from autopsy import container, gui, index as indexmod, report_html, selfupdate, tools  # noqa: E402
from autopsy.analyze import Autopsy  # noqa: E402

FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
BASE = open(os.path.join(FX, "base.apk"), "rb").read()


class Bundles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sh-hard-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _apkm(self, name, splits, compression=zipfile.ZIP_STORED):
        p = os.path.join(self.tmp, name)
        with zipfile.ZipFile(p, "w", compression) as z:
            for n, data in splits:
                z.writestr(n, data)
        return p

    def test_split_with_broken_central_directory_is_skipped(self):
        bad = bytearray(BASE)
        eocd = bad.rfind(b"PK\x05\x06")
        cd = int.from_bytes(bad[eocd + 16:eocd + 20], "little")
        bad[cd:cd + 4] = b"XXXX"
        b = container.open_bundle(self._apkm("cd.apkm", [("base.apk", BASE), ("split_config.en.apk", bytes(bad))]))
        self.assertEqual([s.name for s in b.splits], ["base.apk"])
        self.assertTrue(any("split_config.en.apk" in w and "skipped" in w for w in b.warnings))

    def test_split_failing_crc_is_skipped(self):
        p = self._apkm("crc.apkm", [("base.apk", BASE), ("split_config.en.apk", BASE)])
        raw = bytearray(open(p, "rb").read())
        second = raw.find(b"PK\x03\x04", raw.find(b"split_config.en.apk"))  # first local header inside split 2
        raw[second + 40] ^= 0xFF
        open(p, "wb").write(bytes(raw))
        b = container.open_bundle(p)
        self.assertEqual([s.name for s in b.splits], ["base.apk"])
        self.assertTrue(any("split_config.en.apk" in w for w in b.warnings))

    def test_corrupt_dex_inside_a_good_split_does_not_sink_the_scan(self):
        # the split opens fine (intact central directory), but its classes.dex fails the CRC check
        src = zipfile.ZipFile(io.BytesIO(BASE))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            for zi in src.infolist():
                z.writestr(zi.filename, src.read(zi.filename))
        split = bytearray(buf.getvalue())
        hdr = split.find(b"PK\x03\x04")  # walk the local headers to classes.dex
        while hdr != -1 and split[hdr + 30:hdr + 30 + 11] != b"classes.dex":
            hdr = split.find(b"PK\x03\x04", hdr + 4)
        name_len = int.from_bytes(split[hdr + 26:hdr + 28], "little")
        extra_len = int.from_bytes(split[hdr + 28:hdr + 30], "little")
        split[hdr + 30 + name_len + extra_len + 200] ^= 0xFF
        p = self._apkm("dexcrc.apkm", [("base.apk", BASE), ("split_config.en.apk", bytes(split))])
        logs = []
        f = Autopsy(p, os.path.join(self.tmp, "out"), log=logs.append, java=False).run()
        self.assertEqual(f["manifest"].get("package"), "com.example.tvapp")
        self.assertTrue(any("unreadable" in str(x) for x in logs), logs[-10:])

    def test_highly_compressed_split_is_refused_as_a_bomb(self):
        bomb = b"\0" * 2_000_000
        p = self._apkm("bomb.apkm", [("base.apk", BASE), ("split_config.bomb.apk", bomb)], zipfile.ZIP_DEFLATED)
        with mock.patch.object(container, "BOMB_MIN_BYTES", 1_000_000):
            b = container.open_bundle(p)
        self.assertEqual([s.name for s in b.splits], ["base.apk"])
        self.assertTrue(any("zip bomb" in w for w in b.warnings))

    def test_dex_file_names_are_sanitized(self):
        src = zipfile.ZipFile(io.BytesIO(BASE))
        p = os.path.join(self.tmp, "evil.apk")
        with zipfile.ZipFile(p, "w") as z:
            for zi in src.infolist():
                z.writestr(zi.filename, src.read(zi.filename))
            z.writestr("classes2\\..\\..\\evil.dex", src.read("classes.dex"))
        out = os.path.join(self.tmp, "out")
        indexmod.build(container.open_bundle(p), out, log=lambda *a: None)
        written = os.listdir(os.path.join(out, "dex"))
        self.assertTrue(written)
        self.assertFalse([n for n in written if "\\" in n or "/" in n], written)


class ShellGuard(unittest.TestCase):
    def test_cmd_metacharacters_are_refused(self):
        for arg in ("a.b&calc", "x|y", "%PATH%", 'q"r', "a^b"):
            with self.assertRaises(ValueError, msg=arg):
                tools._shell_safe(["jadx.bat", "--single-class", arg])

    def test_ordinary_arguments_pass(self):
        tools._shell_safe(["jadx.bat", "--single-class", "com.example.tvapp.player.AdBreakScheduler$1",
                           "--single-class-output", r"C:\Users\me\AppData\Local\Temp\tmp1\out.java"])


class GuiHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sh-hard-gui-")
        cls.scan = os.path.join(cls.tmp, "results", "sample", "1.0.autopsy")
        f = Autopsy(os.path.join(FX, "sample.apkm"), cls.scan, log=lambda *a: None, java=False).run()
        with open(os.path.join(cls.scan, "report.html"), "w", encoding="utf-8") as fh:  # the CLI writes this
            fh.write(report_html.render(f))
        cls._paths = (gui.SETTINGS_PATH, gui.PORT_FILE)
        gui.SETTINGS_PATH = os.path.join(cls.tmp, "gui.json")
        gui.PORT_FILE = os.path.join(cls.tmp, "gui.port")
        gui.save_settings({"results_dirs": [os.path.join(cls.tmp, "results")], "library_dirs": []})
        cls.g = gui.Gui()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), gui._handler(cls.g))
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        for d in list(cls.g.explorers):
            cls.g._close(d)
        gui.SETTINGS_PATH, gui.PORT_FILE = cls._paths
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _raw(self, request: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(request)
            chunks = []
            while True:
                try:
                    c = s.recv(65536)
                except socket.timeout:
                    break
                if not c:
                    break
                chunks.append(c)
        return b"".join(chunks)

    def test_rejected_post_closes_the_connection(self):
        body = b'GET /api/scans HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'  # must not run as a 2nd request
        req = (f"POST /api/delete HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\n\r\n").encode() + body
        out = self._raw(req)
        self.assertEqual(out.count(b"HTTP/1."), 1, out[:300])
        self.assertIn(b"403", out.split(b"\r\n", 1)[0])
        self.assertIn(b"Connection: close", out)

    def test_post_ignores_query_token(self):
        body = b'{"dir": "x"}'
        req = (f"POST /api/delete?t={self.g.token} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
               f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
        self.assertIn(b"bad token", self._raw(req))

    def test_get_still_accepts_query_token(self):
        q = self.scan.replace("\\", "%5C").replace(":", "%3A")
        out = self._raw((f"GET /files?f=report.html&dir={q}&t={self.g.token} HTTP/1.1\r\n"
                         f"Host: 127.0.0.1:{self.port}\r\nConnection: close\r\n\r\n").encode())
        head = out.split(b"\r\n\r\n", 1)[0]
        self.assertIn(b"200", head.split(b"\r\n", 1)[0])
        self.assertIn(b"sandbox allow-scripts", head)  # report runs in an opaque origin

    def test_keep_alive_survives_a_good_post(self):
        body = b'{"id": "nope"}'
        one = (f"POST /api/cancel HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nX-Seam-Token: {self.g.token}\r\n"
               f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
        two = (f"GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nX-Seam-Token: {self.g.token}\r\n"
               f"Connection: close\r\n\r\n").encode()
        out = self._raw(one + two)
        self.assertEqual(out.count(b"HTTP/1.1 200"), 2, out[:400])


class UpdateConfirm(unittest.TestCase):
    def test_auto_picked_zip_needs_confirmation(self):
        td = tempfile.mkdtemp(prefix="sh-upd-")
        try:
            z = os.path.join(td, "apk-autopsy-99.0.0.zip")
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("apk-autopsy/autopsy/__init__.py", '__version__ = "99.0.0"\n')
            with mock.patch.object(selfupdate, "find_zip", return_value=z), \
                    mock.patch.object(selfupdate, "_backup", side_effect=AssertionError("must not install")), \
                    mock.patch.object(selfupdate.sys, "stdin", io.StringIO("")):
                self.assertEqual(selfupdate.update(None), 1)
        finally:
            shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
