import sys, os, random, zipfile, tempfile, collections, traceback, shutil
sys.path.insert(0, sys.argv[1])
from autopsy.analyze import Autopsy
FX = os.path.join(sys.argv[1], 'tests', 'fixtures')
src = zipfile.ZipFile(os.path.join(FX, 'base.apk'))
rnd = random.Random(7)
def mut(b, n=20):
    b = bytearray(b)
    for _ in range(n):
        i = rnd.randrange(len(b)); b[i] = rnd.randrange(256)
    return bytes(b)
crash = collections.Counter(); ex = {}
td = tempfile.mkdtemp()
for trial in range(int(sys.argv[2])):
    target = rnd.choice(['classes.dex', 'AndroidManifest.xml', 'resources.arsc', 'lib/armeabi-v7a/libfake.so', 'assets/player_config.json'])
    p = os.path.join(td, f't{trial}.apk')
    with zipfile.ZipFile(p, 'w') as z:
        for zi in src.infolist():
            data = src.read(zi.filename)
            if zi.filename == target:
                data = mut(data, rnd.choice([5, 50, 500]))
            z.writestr(zi.filename, data)
    try:
        Autopsy(p, os.path.join(td, f'o{trial}'), log=lambda *a: None, java=False).run()
        crash['ok'] += 1
    except Exception as e:
        k = f"{target}:{type(e).__name__}"
        crash[k] += 1
        ex.setdefault(k, [l for l in traceback.format_exc().strip().splitlines() if 'autopsy/' in l][-4:])
    shutil.rmtree(os.path.join(td, f'o{trial}'), ignore_errors=True); os.remove(p)
print(dict(crash))
for k, v in ex.items(): print(k, '|', ' | '.join(x.strip() for x in v)[:300])
