"""Tracker audit: catalog sanity and synthetic-scan shape (no app-specific ground truth)."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from autopsy.analyze import Autopsy  # noqa: E402
from autopsy.kb.trackers import CATEGORIES, TRACKERS  # noqa: E402

FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class Catalog(unittest.TestCase):
    def test_entries_well_formed(self):
        names = set()
        for name, cat, prefixes, markers, hosts, kills, note in TRACKERS:
            self.assertIn(cat, CATEGORIES, name)
            self.assertNotIn(name, names)
            names.add(name)
            for p in prefixes:
                self.assertTrue(p.startswith("L") and p.endswith("/") or p[-1].isalpha(), p)
            for dom, block in hosts:
                self.assertIn(block, ("safe", "caution", "never"), dom)
                self.assertNotIn("/", dom)
            self.assertTrue(prefixes or markers or hosts, name)


class SyntheticScan(unittest.TestCase):
    def test_audit_present_and_shaped(self):
        out = tempfile.mkdtemp(prefix="autopsy-trk-")
        try:
            f = Autopsy(os.path.join(FX, "sample.apkm"), out, log=lambda *a: None, java=False).run()
            t = f["trackers"]
            for k in ("items", "count", "by_category", "permissions", "blocklist", "kill_switches"):
                self.assertIn(k, t)
            self.assertEqual(t["count"], len(t["items"]))
        finally:
            shutil.rmtree(out, ignore_errors=True)
