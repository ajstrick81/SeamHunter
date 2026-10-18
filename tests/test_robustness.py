"""Hostile-input regression (the 2026-09 audit): corrupted DEX/manifest/resources/native libs must
never crash a scan — at worst a section is empty and the report says so."""
import os
import random
import shutil
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from autopsy.analyze import Autopsy  # noqa: E402
from autopsy.container import open_bundle  # noqa: E402
from autopsy.dex import Dex, DexError  # noqa: E402
from autopsy.elf import ElfInfo  # noqa: E402
from autopsy.resources import parse_axml  # noqa: E402

FX = os.path.join(HERE, "fixtures")


def mutate(rnd, b, n):
    b = bytearray(b)
    for _ in range(n):
        b[rnd.randrange(len(b))] = rnd.randrange(256)
    return bytes(b)


class Robustness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = zipfile.ZipFile(os.path.join(FX, "base.apk"))
        cls.tmp = tempfile.mkdtemp(prefix="autopsy-rob-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_corrupted_bundles_never_crash(self):
        rnd = random.Random(20260928)
        targets = ["classes.dex", "AndroidManifest.xml", "resources.arsc", "lib/armeabi-v7a/libfake.so"]
        for i in range(24):
            target = targets[i % len(targets)]
            p = os.path.join(self.tmp, f"t{i}.apk")
            with zipfile.ZipFile(p, "w") as z:
                for zi in self.src.infolist():
                    d = self.src.read(zi.filename)
                    z.writestr(zi.filename, mutate(rnd, d, rnd.choice([5, 60, 600])) if zi.filename == target else d)
            f = Autopsy(p, os.path.join(self.tmp, f"o{i}"), log=lambda *a: None, java=False).run()
            self.assertIn("plan", f, target)

    def test_parsers_raise_only_their_own_errors(self):
        rnd = random.Random(7)
        dex = self.src.read("classes.dex")
        for _ in range(40):
            try:
                d = Dex(mutate(rnd, dex, 30))
                list(d.iter_classes())
            except DexError:
                pass
        for _ in range(40):
            self.assertIsInstance(parse_axml(mutate(rnd, self.src.read("AndroidManifest.xml"), 30)), dict)
            ElfInfo(mutate(rnd, self.src.read("lib/armeabi-v7a/libfake.so"), 30))

    def test_bad_inputs_get_clear_messages(self):
        empty = os.path.join(self.tmp, "empty.apk")
        open(empty, "wb").close()
        with self.assertRaisesRegex(SystemExit, "empty"):
            open_bundle(empty)
        cut = os.path.join(self.tmp, "cut.apk")
        with open(cut, "wb") as fh:
            fh.write(open(os.path.join(FX, "base.apk"), "rb").read()[:4000])
        with self.assertRaisesRegex(SystemExit, "incomplete"):
            open_bundle(cut)
        so = os.path.join(self.tmp, "splitonly.apkm")
        with zipfile.ZipFile(os.path.join(FX, "sample.apkm")) as src, zipfile.ZipFile(so, "w") as z:
            z.writestr("split_config.armeabi_v7a.apk", src.read("split_config.armeabi_v7a.apk"))
        with self.assertRaisesRegex(SystemExit, "no base APK"):
            open_bundle(so)


if __name__ == "__main__":
    unittest.main()
