<p align="center">
  <img src="assets/branding/seamhunter-readme.png" alt="SeamHunter — find the seam, clip the ad" width="100%">
</p>

# SeamHunter

**A local, offline static analyzer for Android (TV) `APK` / `APKM` / `XAPK` bundles.**
SeamHunter tells you *how an app is built* — where ads and trackers enter, which protections it
ships, what SDKs and native engines it uses, and where the content-relevant "seams" are — and
writes a compact report you can read instead of decompiling by hand.

> **Analysis only.** SeamHunter **never modifies an APK** and never phones home. It reads bundles you
> give it and writes reports to a local folder. The only network access is the explicit, opt-in
> `autopsy tools install` (fetches `jadx` / `apktool`).

## Why

Reverse-engineering an Android app to understand its ad/telemetry/DRM architecture is slow: unzip,
decompile, grep, read smali, repeat. SeamHunter does the mechanical part once and hands you a map —
a report with the manifest facts, the SDK/native inventory, the ad/tracker hosts, the protections,
and a ranked list of candidate "seams" (the methods where an ad schedule crosses into playback),
each with a match-count and the evidence behind it.

It is in the same family as `jadx`, `apktool` and `MobSF`: a tool for understanding software you are
authorized to analyze. What you do with the understanding is up to you and your local laws; see
**Scope & ethics** below.

## Install

```bash
git clone https://github.com/ajstrick81/SeamHunter
cd SeamHunter
pip install -e .              # or run without installing: python -m autopsy ...
seamhunter tools install      # optional: fetches jadx + apktool for Java/smali excerpts
```

Requires Python 3.9+. `jadx` and `apktool` are optional (richer output); everything else is pure
Python with no third-party runtime dependencies. The CLI is `seamhunter` (`autopsy` remains as a
legacy alias, and `python -m autopsy` works without installing).

## Usage

```bash
seamhunter scan app.apkm                 # full scan -> ./app.autopsy/ (report.md, report.json, report.html)
seamhunter scan app.apk --apktool        # also decode a full smali tree
seamhunter gui                           # local web explorer (127.0.0.1 only) for your scans
seamhunter diff old.autopsy new.autopsy  # what changed between two builds (renames, new ad strings...)
seamhunter fp 'Lcom/x/Y;->z()Z'          # draft a method matcher descriptor and count matches
seamhunter stream manifest.m3u8          # decode HLS/DASH/SCTE-35 ad markers
```

## What you get

- **Manifest** — package, version, TV/leanback, permissions, exported components, network-security config.
- **Code index** — a SQLite index of every class/method, obfuscation profile, compiler, native methods.
- **SDK & native inventory** — ad / SSAI / verification / analytics / player / DRM / engine SDKs, and
  native libraries with their embedded engines (V8, QuickJS, WAMR, Hermes, Flutter…).
- **Hosts** — ad / tracker / analytics endpoints and who references them in code.
- **Protections** — signature/root/debug/emulator checks, pinning, packers, dynamic code loading.
- **Seams** — ranked candidate methods where ads cross into playback, with evidence, a match-count,
  data-flow and a `SCOPING.md` that reads like a reviewer's map ("here's the ad gate, here's the
  content-safe place to look, here's what to verify on device").
- **Known-app drift** — if you populate `autopsy/kb/known_apps.json` with your own fingerprints,
  SeamHunter checks whether they still match a new build and re-anchors the ones that drifted.

The shipped knowledge base is **generic** (a taxonomy of ad-delivery mechanisms and SDK/marker
signatures). No app-specific fingerprint catalog is distributed; the `apps` map is empty by design.
The KB does name commercial **SDKs** (Google IMA, FreeWheel, ExoPlayer/media3, OkHttp, …) — that is
factual SDK identification, the core job of an analyzer, and is intentionally retained.

## Scope & ethics

SeamHunter is built for **legitimate reverse engineering**: analyzing apps on devices you own,
interoperability and security research, and education. It is a static *analyzer*, not a patcher, and
it ships no circumvention payloads and no catalog of defeated apps. Use it in accordance with the
terms that apply to you and the software you examine. Don't use it to redistribute others' apps.

## Limitations

- Static analysis can't see code that only exists at runtime (downloaded `.so`/DEX, server-side SSAI,
  values that arrive over the network). SeamHunter flags these cases rather than guessing.
- Heavily packed/encrypted apps expose only a stub statically.
- Seam candidates are *leads*: verify them against the smali/Java and on a device before relying on them.

## License

MIT — see [LICENSE](LICENSE).
