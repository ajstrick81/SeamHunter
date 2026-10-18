"""GUI server: security guards, scan listing, report/explorer endpoints, art. No browser needed."""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from autopsy import gui  # noqa: E402
from autopsy.analyze import Autopsy  # noqa: E402

FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class GuiServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="autopsy-gui-")
        cls.scan = os.path.join(cls.tmp, "results", "sample", "1.0.autopsy")
        Autopsy(os.path.join(FX, "sample.apkm"), cls.scan, log=lambda *a: None, java=False).run()
        # keep the user's real settings untouched
        cls._paths = (gui.SETTINGS_PATH, gui.PORT_FILE)
        gui.SETTINGS_PATH = os.path.join(cls.tmp, "gui.json")
        gui.PORT_FILE = os.path.join(cls.tmp, "gui.port")
        gui.save_settings({"results_dirs": [os.path.join(cls.tmp, "results")], "library_dirs": [FX]})
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

    def req(self, path, token=True, host=None, method="GET", body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if token:
            h["X-Seam-Token"] = self.g.token
        data = json.dumps(body).encode() if body is not None else None
        if data:
            h["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        out = r.status, r.read()
        c.close()
        return out

    def test_page_carries_token_and_csp(self):
        st, body = self.req("/", token=False)
        self.assertEqual(st, 200)
        self.assertIn(self.g.token.encode(), body)
        self.assertNotIn(b"__SEAM_TOKEN__", body)

    def test_api_needs_token(self):
        self.assertEqual(self.req("/api/scans", token=False)[0], 403)
        self.assertEqual(self.req("/api/scan", token=False, method="POST", body={"path": "x"})[0], 403)

    def test_foreign_host_rejected(self):  # DNS rebinding
        self.assertEqual(self.req("/", token=False, host="evil.example:80")[0], 403)
        self.assertEqual(self.req("/api/scans", host="evil.example")[0], 403)

    def test_scans_listed_with_summary(self):
        st, body = self.req("/api/scans")
        self.assertEqual(st, 200)
        scans = json.loads(body)["scans"]
        self.assertEqual(len(scans), 1)
        self.assertEqual(os.path.normcase(scans[0]["dir"]), os.path.normcase(self.scan))

    def test_report_and_explorer(self):
        q = "?dir=" + self.scan.replace("\\", "%5C").replace(":", "%3A")
        st, body = self.req("/api/report" + q)
        self.assertEqual(st, 200)
        self.assertIn("report", json.loads(body))
        st, body = self.req("/api/x/search" + q + "&kind=method&q=Ad")
        self.assertEqual(st, 200)
        self.assertIn("items", json.loads(body))

    def test_paths_outside_results_are_refused(self):
        outside = os.path.dirname(FX).replace("\\", "%5C").replace(":", "%3A")
        self.assertEqual(self.req("/api/report?dir=" + outside)[0], 403)
        self.assertEqual(self.req("/files?f=report.md&dir=" + outside)[0], 403)
        st, body = self.req("/api/delete", method="POST", body={"dir": os.path.dirname(FX)})
        self.assertEqual(st, 403)
        self.assertTrue(os.path.isdir(FX))

    def test_static_traversal_blocked(self):
        self.assertEqual(self.req("/static/../gui.py", token=False)[0], 404)

    def test_library_lists_fixture_apks(self):
        st, body = self.req("/api/library")
        names = [f["name"] for d in json.loads(body)["dirs"] for f in d["files"]]
        self.assertIn("sample.apkm", names)


if __name__ == "__main__":
    unittest.main()
