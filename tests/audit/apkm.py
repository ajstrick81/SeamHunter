"""Whole scans of .apkm bundles whose config split is a corrupted copy of base.apk.

Covers what e2e.py does not: damaged splits (central directory, CRC, truncation, deflate data)
and damaged entries inside a split that still opens. Every run should report only 'ok'.

    python tests/audit/apkm.py . 150
"""
import sys, os, random, zipfile, tempfile, shutil, collections, traceback
sys.path.insert(0, sys.argv[1])
from autopsy.analyze import Autopsy
base = open(os.path.join(sys.argv[1], 'tests', 'fixtures', 'base.apk'), 'rb').read()
rnd = random.Random(99)
res = collections.Counter(); ex = {}
td = tempfile.mkdtemp()
for t in range(int(sys.argv[2])):
    split = bytearray(base)
    for _ in range(rnd.choice([3, 30, 300])):
        i = rnd.randrange(len(split)); split[i] = rnd.randrange(256)
    if rnd.random() < 0.3:
        split = split[:rnd.randrange(len(split))]
    p = os.path.join(td, f't{t}.apkm')
    with zipfile.ZipFile(p, 'w', rnd.choice([zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])) as z:
        z.writestr('base.apk', base); z.writestr('split_config.en.apk', bytes(split))
    try:
        Autopsy(p, os.path.join(td, f'o{t}'), log=lambda *a: None, java=False).run(); res['ok'] += 1
    except Exception as e:
        k = type(e).__name__; res[k] += 1
        ex.setdefault(k, [l for l in traceback.format_exc().splitlines() if 'autopsy/' in l][-3:])
    shutil.rmtree(os.path.join(td, f'o{t}'), ignore_errors=True); os.remove(p)
shutil.rmtree(td, ignore_errors=True)
print(dict(res))
for k, v in ex.items(): print(k, '|', ' | '.join(x.strip() for x in v)[:400])
