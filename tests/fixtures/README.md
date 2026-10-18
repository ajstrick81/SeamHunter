# Test fixtures

Small **synthetic** Android app used by the test suite — package `com.example.tvapp`. It is not a
real app and contains **no third-party SDK code**.

- `base.apk` / `v2.apk` — the synthetic app and a simulated R8-renamed next build (`La/b/c;` → `La/b/q;`
  plus one added string). Each `classes.dex` holds only the app's own classes plus **minimal empty
  stub classes** under `com/google/ads/interactivemedia/v3/api/` (just the type names the app
  references, so the IMA SDK is *detected* by name). Google's compiled IMA SDK is **not** bundled.
- `sample.apkm` — APKMirror-style bundle: `base.apk` + one ABI split + `info.json`.
- `live.m3u8` — a hand-written HLS manifest with ad markers for the stream tests.

To regenerate after editing the Java sources in `src/`: compile the app against **stub** IMA classes
(not the real SDK), dex the result, and reassemble — or edit the smali and rebuild the `classes.dex`
with `apktool`/`baksmali`, keeping the stubs in place of any real SDK classes.
