# Test fixtures

A tiny, **fully synthetic** Android app used by the test suite — package `com.example.tvapp`,
built here, containing **no third-party app, SDK, resource or binary**.

- `base.apk` / `v2.apk` — the synthetic app and a simulated R8-renamed next build (`La/b/c;` → `La/b/q;`
  plus one added string). Each was assembled with `apktool` from:
  - a minimal hand-written `AndroidManifest.xml` (`com.example.tvapp`, one leanback launcher activity),
  - a minimal generated `resources.arsc` (one string),
  - a synthetic `classes.dex`: the app's own classes plus **minimal empty stub classes** under
    `com/google/ads/interactivemedia/v3/api/` (type names only, so the IMA SDK is *detected* by name —
    none of Google's compiled code is present),
  - `assets/player_config.json` (synthetic ad config),
  - `lib/armeabi-v7a/libfake.so` — a tiny **original** ELF compiled from `native/strip.c` in this repo
    (exports one JNI function; it is not a real or third-party library).
- `sample.apkm` — APKMirror-style bundle: `base.apk` + a config split carrying the native lib + `info.json`.
- `live.m3u8` — a hand-written HLS manifest with ad markers for the stream tests.
- `src/` — the Java sources the synthetic app classes correspond to (reference only).

To regenerate: edit the smali (or `src/`), rebuild `classes.dex`, and reassemble with `apktool`,
keeping the empty IMA stubs in place of any real SDK classes.
