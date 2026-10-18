"""Tracker audit: catalog sanity, synthetic scan shape, and (optional) Tubi ground truth."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from autopsy.analyze import Autopsy  # noqa: E402
from autopsy.kb.trackers import CATEGORIES, TRACKERS  # noqa: E402

FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
TUBI = os.environ.get("TUBI_APKM")


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


@unittest.skipUnless(TUBI and os.path.exists(TUBI), "set TUBI_APKM to a Tubi TV .apkm (validated on 10.36)")
class Tubi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp(prefix="autopsy-tubi-")
        cls.t = Autopsy(TUBI, cls.out, log=lambda *a: None, java=False).run()["trackers"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out, ignore_errors=True)

    def test_known_trackers(self):
        names = {i["name"] for i in self.t["items"]}
        for n in ("Google Analytics for Firebase", "Adjust", "Braze", "Sentry", "Conviva", "OneTrust"):
            self.assertIn(n, names)

    def test_kill_switch_resolved_from_resource(self):
        ks = {k["key"]: k for k in self.t["kill_switches"]}
        k = ks["firebase_analytics_collection_deactivated"]
        self.assertIs(k["current"], False)
        self.assertEqual(k["via"], "bool/is_firebase_analytics_deactivated")

    def test_config_hosts_never_in_safe_list(self):
        self.assertIn("firebaseremoteconfig.googleapis.com", self.t["blocklist"]["never"])
        self.assertNotIn("firebaseremoteconfig.googleapis.com", self.t["blocklist"]["safe"])
