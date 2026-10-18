import sys, os, random, zipfile, time, signal, collections, traceback
sys.path.insert(0, sys.argv[1])
from autopsy.dex import Dex
from autopsy.resources import parse_axml, ResourceTable
from autopsy.elf import ElfInfo
FX = os.path.join(sys.argv[1], 'tests', 'fixtures')
z = zipfile.ZipFile(os.path.join(FX, 'base.apk'))
DEX = z.read('classes.dex'); AXML = z.read('AndroidManifest.xml'); ARSC = z.read('resources.arsc')
ELF = open('/usr/lib/x86_64-linux-gnu/libz.so.1', 'rb').read() if os.path.exists('/usr/lib/x86_64-linux-gnu/libz.so.1') else z.read('lib/armeabi-v7a/libfake.so')
rnd = random.Random(1234)

class Timeout(Exception): pass
def alarm(*_): raise Timeout()
signal.signal(signal.SIGALRM, alarm)

def mutate(b):
    b = bytearray(b)
    k = rnd.random()
    if k < 0.4:
        for _ in range(rnd.randint(1, 40)):
            i = rnd.randrange(len(b)); b[i] = rnd.randrange(256)
    elif k < 0.6:
        b = b[:rnd.randrange(len(b))]
    elif k < 0.8:  # corrupt header region (counts/offsets)
        for _ in range(rnd.randint(1, 8)):
            i = rnd.randrange(min(len(b), 0x70 if b[:3] == b'dex' else 64)); b[i] = rnd.randrange(256)
    else:
        i = rnd.randrange(len(b)); b[i:i + 4] = rnd.randrange(2**32).to_bytes(4, 'little')
    return bytes(b)

def dex_job(b):
    d = Dex(b)
    n = 0
    for c in d.iter_classes():
        for midx, fl, co in c['methods']:
            d.method_parts(midx)
            if co:
                d.scan_code(co); d.disassemble(co, midx, fl)
            n += 1
            if n > 300: return

jobs = {'dex': (DEX, dex_job), 'axml': (AXML, parse_axml), 'arsc': (ARSC, ResourceTable), 'elf': (ELF, ElfInfo)}
N = int(sys.argv[2])
for name, (seed, fn) in jobs.items():
    exc = collections.Counter(); hangs = 0; examples = {}
    t = time.time()
    for _ in range(N):
        b = mutate(seed)
        signal.alarm(5)
        try:
            fn(b)
        except Timeout:
            hangs += 1
        except Exception as e:
            key = type(e).__name__
            exc[key] += 1
            if key not in examples:
                examples[key] = traceback.format_exc().strip().splitlines()[-3:]
        finally:
            signal.alarm(0)
    print(f"{name}: {N} mutants in {time.time()-t:.0f}s  hangs={hangs}  exceptions={dict(exc)}")
    for k, v in examples.items():
        print(f"   {k}: {' | '.join(x.strip() for x in v)[:260]}")
