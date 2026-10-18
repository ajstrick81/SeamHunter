# Changelog

## 1.0.0 — first public release
Initial public release of **SeamHunter**, a local static analyzer for Android (TV) APK/APKM bundles.

- Bundle handling (apk / apkm / xapk), manifest + resources (AXML/ARSC), DEX parser + disassembler,
  SQLite code index, ELF/native inspection, SCTE-35 / HLS / DASH stream decoding.
- SDK, native-engine, host, protection and tracker inventories; ranked ad-seam candidates with
  evidence, fingerprint match-counts, data-flow and a neutral `SCOPING.md` + device `VERIFY.md`.
- Multi-signal obfuscation profile; record-local native ad-string corroboration (strict VAST, vendor
  hosts tracked presence-only); advertising-ID vs ad-delivery SDK separation; `loadLibrary` provenance
  (confirmed packaged `.so` vs possible literal).
- Local web explorer (`autopsy gui`, 127.0.0.1 only), build-to-build `diff`, and known-app drift
  checks (ships with an empty fingerprint catalog — populate it locally).

**Analysis only:** SeamHunter never modifies an APK and performs no network access except the opt-in
`autopsy tools install`.
