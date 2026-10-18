# Changelog

## Unreleased — analyst-ready synthesis layer
Turns the flat evidence into a connected, decision-ready profile without changing what SeamHunter
detects. No network, still analysis-only.

- **Delivery-path profiles** (`autopsy/paths.py`): findings grouped by mechanism — IMA client
  (CSAI), IMA DAI, SSAI (Yospace/FreeWheel/MediaTailor), media3 `AdsMediaSource`, pause ads and
  telemetry — each as a connected flow (request/config → scheduling → playback/break detection →
  UI/seek → resume/fallback). Server-stitched paths carry an explicit warning that suppressing an
  event/UI/measurement does not remove stitched ad media.
- **Ownership ranking + subsystem dedup**: app-owned request/scheduling/break-state boundaries rank
  above adapters, UI and telemetry; large vendor subsystems (e.g. hundreds of Yospace internals)
  collapse to one summary with a few app-facing boundaries — the exhaustive sites stay in
  `report-full.md` / `report.json` / `index.sqlite`.
- **Evidence-based confidence model**: every candidate gets a role (confirmed delivery boundary /
  strong intervention / break-state / UI-only / telemetry-only / configuration-testing / requires
  runtime evidence), a confidence that downgrades on string/keyword-only evidence, and a state that
  starts at `candidate` — no static finding is presented as a completed patch.
- **Regional-controls discovery** (`autopsy/regional.py`): reconstructs client-side country/region
  overrides (`sudoCountryOverride` and friends) by **data flow** — the override key string plus the
  field / SharedPreferences `get`/`put` and call edges around it — so it survives R8 renaming (the
  getter is `u()`, the setter `e0()`, the consumer `e()`); it never reports a getter/setter/consumer
  that is not connected to the same key or field by a real edge. Kept distinct from experiment region
  (`mockRegion`) and consent geolocation (OneTrust), with the limitation that these are not a proven
  licensing/geoblock bypass.
- **Paths from the full union**: delivery paths are built from candidates *plus* integration sites
  *plus* implementer overrides (deduplicated by method id, evidence merged), so a boundary that is
  only an integration site (e.g. a media3 `AdsMediaSource` call that never ranked) is not dropped and
  a seam-calling candidate is not wrongly downgraded. Flows display only the stages that carry
  evidence, and each boundary carries a modification-risk note alongside its ownership rank.
- CLI: `seamhunter` is the primary command; `autopsy` is documented as a legacy alias.
- **Kotlin delegated-property regional support (slot-bridged)**: the regional detector reconstructs
  overrides exposed through a Kotlin `by` delegate by bridging the unrenamed property metadata to the
  renamed executable accessors through the actual **`KProperty[]` array slot** — not the getter name
  (R8 keeps the original `getSudoCountryOverride` in metadata while renaming the method to `u()`). It
  taints the key's property-reference through `<clinit>` to its `aput-object` slot index, then selects
  the String getter and `void(String)` setter that load that same slot + a non-metadata delegate field.
  This picks the correct property even when the class holds several delegated properties (including an
  unrelated `Lazy<File>` getter), never treats `<clinit>`/`<init>` as the setter, and excludes the
  `KProperty[]` metadata array by its **type** (so the renamed `$$delegatedProperties` → `b` is caught).
  Second synthetic fixture `tubi_delegated.apk` (+ `make_tubi_delegated.py`) reproduces the real
  metadata↔method name mismatch, the renamed array, and the multi-property / `Lazy<File>` decoy case.
- **`brief.md`**: a new ultra-compact layer (path summaries, top 1–2 app-owned boundaries per populated
  stage, regional controls, principal risks, verification contracts, evidence IDs) — a fraction of
  `report.md`, for tight agent token budgets.
- **Navigation index** (`autopsy/nav.py`, `nav.json`): stable evidence IDs with case-sensitive
  class→smali-file (or queryable) locators, bounded snippets and callers/callees, linked from the
  Markdown and HTML reports.
- **Two output layers**: `report.md` is now a materially smaller connected short brief; the
  exhaustive evidence remains in `report-full.md` / `report.json` / `report.html` / `index.sqlite`.
- New synthetic, public-safe fixture `tests/fixtures/tubi_like.apk` (+ `make_tubi_like.py`) and
  regression coverage for all of the above; the original 38-test baseline is unchanged.

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
