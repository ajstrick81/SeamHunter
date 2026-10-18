# SeamHunter branding

Final design (chosen 2026-09-29): **option B** — vintage wood-cabinet CRT whose screen shows teal
circuit traces + binary, an amber *stitched seam* torn open with 0/1 particles, and a white reticle
locked on it; Matrix-style code rain (hex / smali fragments) in the background.
Tagline: **FIND THE SEAM · CLIP THE AD** · sub-line: *static ad-seam analyzer for Android TV · local · private*.

| File | Use |
|---|---|
| `seamhunter-banner.png/.svg` | 1600×900 — README header, GUI splash |
| `seamhunter-icon.png/.svg` | 1024×1024 rounded tile — large icon, GUI header |
| `seamhunter-icon-small.png/.svg` | TV-only, transparent — 16–32 px use (tile is unreadable that small) |
| `seamhunter.ico` | Windows shortcut icon: 16/24/32 from the small art, 48–256 from the tile |

**Palette**: background `#060A14`, cyan `#3EE0FF`, amber `#FFB547` (wordmark gradient `#FFC56B→#FF9A2E`),
ink `#EEF3FF`, teal circuits `#22D3C5`/`#7CF7EA`, tear `#FFE45C→#FF8A1F`, rain green `#27E36B`,
wood `#9A4F2A→#6E3218`, cream bezel `#EFDDBF`.
**Type**: Space Grotesk Bold (wordmark), JetBrains Mono (taglines, code rain) — both SIL Open Font
License 1.1 (github.com/google/fonts, `ofl/spacegrotesk`, `ofl/jetbrainsmono`); embedded in the SVGs.

## Regenerating (src/)

Pure SVG built by Python, rendered with headless Chromium (Playwright) and Pillow:

    pip install playwright pillow && python -m playwright install chromium
    cd src && python wood.py && python small.py        # writes the SVGs (fonts/ must sit next to the scripts)
    python render2.py                                   # edit JOBS to pick which SVGs to render
    python make_ico.py                                  # seamhunter.ico: small art for <=32 px, tile for 48+

`wood.py` builds on `retro.py` → `rain.py` → `make.py` (each exec's the previous one's helpers).
