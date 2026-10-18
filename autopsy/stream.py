"""Captured HLS/DASH manifest analysis: where the ads are in the stream, and what the
client could key on (SCTE-35, DATERANGE, ad Periods, ad hosts, Twitch ad tags).

Static APK analysis can't see server-side stitching; a manifest captured from the device
(see the repo's capture runbooks) can. `autopsy stream playlist.m3u8`.
"""
from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from collections import Counter
from urllib.parse import urlparse

from .analyze import host_category

SEG_TYPES = {
    0x10: "Program Start", 0x11: "Program End", 0x20: "Chapter Start", 0x21: "Chapter End",
    0x22: "Break Start", 0x23: "Break End", 0x30: "Provider Ad Start", 0x31: "Provider Ad End",
    0x32: "Distributor Ad Start", 0x33: "Distributor Ad End", 0x34: "Provider Placement Opp Start",
    0x35: "Provider Placement Opp End", 0x36: "Distributor Placement Opp Start",
    0x37: "Distributor Placement Opp End", 0x38: "Provider Overlay PO Start", 0x39: "Provider Overlay PO End",
    0x40: "Unscheduled Event Start", 0x41: "Unscheduled Event End", 0x50: "Network Start", 0x51: "Network End",
}
AD_SEG = {0x22, 0x23, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}


class _Bits:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def read(self, n):
        v = 0
        for _ in range(n):
            byte = self.d[self.p >> 3]
            v = (v << 1) | ((byte >> (7 - (self.p & 7))) & 1)
            self.p += 1
        return v

    def skip(self, n):
        self.p += n

    def bytepos(self):
        return self.p >> 3


def _splice_time(b):
    if b.read(1):
        b.skip(6)
        return b.read(33) / 90000.0
    b.skip(7)
    return None


def decode_scte35(payload: str) -> dict:
    """Decode a base64 or 0x-hex splice_info_section (splice_insert, time_signal + segmentation)."""
    payload = payload.strip().strip('"')
    try:
        raw = bytes.fromhex(payload[2:]) if payload.lower().startswith("0x") else base64.b64decode(payload)
    except ValueError:
        return {"error": "not base64/hex"}
    if not raw or raw[0] != 0xFC:
        return {"error": "not a splice_info_section (table_id != 0xFC)"}
    try:
        b = _Bits(raw)
        b.skip(8 + 1 + 1 + 2)
        b.read(12)  # section_length
        b.skip(8)  # protocol
        enc = b.read(1)
        b.skip(6)
        pts_adj = b.read(33)
        b.skip(8 + 12)
        cmd_len = b.read(12)
        cmd = b.read(8)
        out = {"command": {5: "splice_insert", 6: "time_signal", 0: "splice_null", 7: "bandwidth_reservation",
                           4: "splice_schedule", 0xFF: "private"}.get(cmd, hex(cmd)),
               "pts_adjustment": pts_adj, "encrypted": bool(enc)}
        start = b.bytepos()
        if cmd == 5:
            out["event_id"] = b.read(32)
            cancel = b.read(1)
            b.skip(7)
            if not cancel:
                out["out_of_network"] = bool(b.read(1))
                program = b.read(1)
                dur_flag = b.read(1)
                immediate = b.read(1)
                b.skip(4)
                if program and not immediate:
                    out["pts"] = _splice_time(b)
                if not program:
                    return out  # component mode: rare, stop here
                if dur_flag:
                    out["auto_return"] = bool(b.read(1))
                    b.skip(6)
                    out["break_duration_s"] = round(b.read(33) / 90000.0, 3)
                b.skip(16 + 8 + 8)
        elif cmd == 6:
            out["pts"] = _splice_time(b)
        if cmd_len != 0xFFF:
            b.p = (start + cmd_len) * 8
        dl = b.read(16)
        end = b.bytepos() + dl
        segs = []
        while b.bytepos() + 2 <= end:
            tag = b.read(8)
            ln = b.read(8)
            nxt = b.bytepos() + ln
            if tag == 0x02 and ln >= 9:
                b.skip(32)  # identifier CUEI
                seg = {"event_id": b.read(32)}
                cancel = b.read(1)
                b.skip(7)
                if not cancel:
                    prog = b.read(1)
                    dflag = b.read(1)
                    b.skip(6)
                    if not prog:
                        cc = b.read(8)
                        b.skip(cc * 48)
                    if dflag:
                        seg["duration_s"] = round(b.read(40) / 90000.0, 3)
                    upid_type = b.read(8)
                    upid_len = b.read(8)
                    upid = bytes(b.read(8) for _ in range(upid_len))
                    t = b.read(8)
                    seg.update({"type_id": hex(t), "type": SEG_TYPES.get(t, "other"), "ad": t in AD_SEG,
                                "upid_type": upid_type, "upid": upid.decode("latin-1", "replace")[:60]})
                segs.append(seg)
            b.p = nxt * 8
        if segs:
            out["segmentation"] = segs
        return out
    except IndexError:
        return {"error": "truncated section"}


def analyze_hls(text: str) -> list[str]:
    L = []
    lines = text.splitlines()
    tags = Counter()
    hosts = Counter()
    ad_hosts = Counter()
    events = []
    t = 0.0
    seg = 0
    disc = 0
    for ln in lines:
        s = ln.strip()
        if s.startswith("#EXT-X-STREAM-INF"):
            tags["variant"] += 1
        if s.startswith("#EXTINF:"):
            try:
                dur = float(s[8:].split(",")[0])
            except ValueError:
                dur = 0
            t += dur
            seg += 1
            continue
        if s.startswith("#EXT-X-DISCONTINUITY") and not s.startswith("#EXT-X-DISCONTINUITY-SEQUENCE"):
            disc += 1
            events.append((t, "DISCONTINUITY", ""))
        for tag in ("#EXT-X-CUE-OUT", "#EXT-X-CUE-IN", "#EXT-X-CUE-OUT-CONT", "#EXT-OATCLS-SCTE35", "#EXT-X-DATERANGE",
                    "#EXT-X-SCTE35", "#EXT-X-ASSET", "#EXT-X-PLACEMENT-OPPORTUNITY", "#EXT-X-TWITCH", "#EXT-X-DATERANGE"):
            if s.startswith(tag):
                tags[tag] += 1
                detail = s[len(tag):][:200]
                m = re.search(r'SCTE35-(?:OUT|IN|CMD)=(0x[0-9A-Fa-f]+|"?[A-Za-z0-9+/=]{16,}"?)', s) or \
                    re.search(r"#EXT-OATCLS-SCTE35:([A-Za-z0-9+/=]{16,})", s) or \
                    re.search(r"#EXT-X-SCTE35:.*?CUE=\"?([A-Za-z0-9+/=]{16,})", s)
                dec = decode_scte35(m.group(1)) if m else None
                events.append((t, tag[1:], detail + (f"  => {dec}" if dec else "")))
                break
        if "stitched-ad" in s or "X-TV-TWITCH-AD" in s:
            tags["twitch-ad"] += 1
        if s and not s.startswith("#"):
            h = urlparse(s).hostname
            if h:
                hosts[h] += 1
                if host_category(h)[0]:
                    ad_hosts[h] += 1
    L.append(f"HLS: {seg} segments, {t:.1f} s, {disc} discontinuities, {tags['variant']} variants")
    if tags:
        L.append("Ad-signalling tags: " + ", ".join(f"{k} ×{v}" for k, v in tags.items() if k != "variant"))
    if hosts:
        L.append("Segment hosts: " + ", ".join(f"{h} ×{n}" for h, n in hosts.most_common(8)))
    if ad_hosts:
        L.append("AD hosts in segments: " + ", ".join(f"{h} ×{n}" for h, n in ad_hosts.items()))
    if events:
        L.append("")
        L.append("Timeline (t = playlist seconds):")
        for tt, kind, detail in events[:120]:
            L.append(f"  t={tt:8.1f}  {kind:<24} {detail}")
    L.append("")
    L.append(_hint(tags, disc, ad_hosts))
    return L


def analyze_dash(text: str) -> list[str]:
    L = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return [f"DASH parse error: {e}"]
    ns = {"d": root.tag.split("}")[0][1:]} if root.tag.startswith("{") else {"d": ""}
    q = (lambda p: p.replace("d:", "{%s}" % ns["d"])) if ns["d"] else (lambda p: p.replace("d:", ""))
    periods = root.findall(q("d:Period"))
    L.append(f"DASH: type={root.get('type')} {len(periods)} period(s) mediaPresentationDuration={root.get('mediaPresentationDuration')}")
    for p in periods:
        pid = p.get("id", "")
        start = p.get("start", "")
        dur = p.get("duration", "")
        bases = [b.text for b in p.iter(q("d:BaseURL")) if b.text]
        hosts = {urlparse(b).hostname for b in bases if b and urlparse(b).hostname}
        evs = []
        for es in p.findall(q("d:EventStream")):
            scheme = es.get("schemeIdUri", "")
            for ev in es:
                txt = "".join(ev.itertext()).strip()
                dec = decode_scte35(txt) if re.fullmatch(r"[A-Za-z0-9+/=\s]{16,}", txt or "") else None
                bin_ = ev.find(".//{*}Binary")
                if bin_ is not None and bin_.text:
                    dec = decode_scte35(bin_.text)
                evs.append(f"{scheme.rsplit(':', 2)[-2] if 'scte' in scheme else scheme} {dec or ''}"[:220])
        asset = p.find(q("d:AssetIdentifier"))
        ad_like = bool(re.search(r"(?i)\bad|pod|break|slate|preroll|midroll", pid)) or \
            any(host_category(h)[0] for h in hosts)
        L.append(f"  Period id={pid!r} start={start} dur={dur} hosts={sorted(hosts) or '-'}"
                 f"{' asset=' + asset.get('value', '') if asset is not None else ''}{'  <-- AD-LIKE' if ad_like else ''}")
        for e in evs[:6]:
            L.append(f"      event: {e}")
    L.append("")
    L.append("Seam hint: DashManifestParser.parse is where ad Periods are visible; period continuity and "
             "resume/seek matter. Live passthrough SSAI shows up via EventStream as a break signal.")
    return L


def _hint(tags, disc, ad_hosts):
    if tags.get("twitch-ad"):
        return "Seam hint: stitched ads signalled by custom HLS tags; the ad segments sit inline in the media playlist."
    if tags.get("#EXT-X-DATERANGE") or tags.get("#EXT-X-CUE-OUT") or tags.get("#EXT-OATCLS-SCTE35"):
        return ("Seam hint: breaks are signalled in-manifest (CUE-OUT/IN, DATERANGE). For passthrough SSAI the "
                "markers are a break detector; the ad media itself is stitched into the stream.")
    if ad_hosts:
        return "Seam hint: ad segments come from distinct ad hosts — identifiable by host in the player's data source."
    if disc:
        return ("Seam hint: only discontinuities mark splices — a cleaner variant may exist (CDN fallback / "
                "manifest path swap, e.g. a /dai/ vs non-/dai/ path).")
    return "No ad signalling found in this manifest (check the variant/media playlists, not just the master)."


def analyze_file(path: str) -> str:
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", "replace")
    head = text.lstrip()[:200]
    if head.startswith("#EXTM3U"):
        return "\n".join(analyze_hls(text))
    if "<MPD" in text[:2000]:
        return "\n".join(analyze_dash(text))
    m = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
    if m:
        return "\n".join(f"{x[:40]}… => {decode_scte35(x)}" for x in m[:20])
    return "Not an HLS/DASH manifest or SCTE-35 payload."
