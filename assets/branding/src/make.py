import base64, math, os

def _font(n):
    return open(n if os.path.exists(n) else os.path.join('fonts', n), 'rb').read()

sg = base64.b64encode(_font('SpaceGrotesk.ttf')).decode()
jb = base64.b64encode(_font('JetBrainsMono.ttf')).decode()
FONTS = f"""<style>
@font-face {{ font-family:'SG'; src:url(data:font/ttf;base64,{sg}) format('truetype'); font-weight:300 700; }}
@font-face {{ font-family:'JB'; src:url(data:font/ttf;base64,{jb}) format('truetype'); font-weight:100 800; }}
</style>"""

CYAN, AMBER, INK = "#3EE0FF", "#FFB547", "#EEF3FF"

def defs(uid):
    return f"""<defs>
  <radialGradient id="bg{uid}" cx="30%" cy="45%" r="85%">
    <stop offset="0" stop-color="#18264A"/><stop offset=".55" stop-color="#0C1328"/><stop offset="1" stop-color="#060912"/>
  </radialGradient>
  <linearGradient id="scr{uid}" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#0F1B36"/><stop offset="1" stop-color="#0A1226"/>
  </linearGradient>
  <linearGradient id="adside{uid}" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="{AMBER}" stop-opacity=".07"/><stop offset="1" stop-color="{AMBER}" stop-opacity="0"/>
  </linearGradient>
  <linearGradient id="word{uid}" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="#FFC56B"/><stop offset="1" stop-color="#FF9A2E"/>
  </linearGradient>
  <filter id="glowC{uid}" filterUnits="userSpaceOnUse" x="-400" y="-400" width="800" height="800">
    <feGaussianBlur stdDeviation="7" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
  <filter id="glowA{uid}" filterUnits="userSpaceOnUse" x="-400" y="-400" width="800" height="800">
    <feGaussianBlur stdDeviation="5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
  <pattern id="grid{uid}" width="40" height="40" patternUnits="userSpaceOnUse">
    <path d="M40 0H0V40" fill="none" stroke="#6F8BC7" stroke-opacity=".07" stroke-width="1"/>
  </pattern>
  <clipPath id="screen{uid}"><rect x="-190" y="-125" width="380" height="250" rx="26"/></clipPath>
</defs>"""

def mark(uid, scale=1.0):
    """TV + stitched seam + reticle, centered at (0,0), ~480 wide at scale 1."""
    # seam: gentle S-curve down through the screen
    pts = []
    for i in range(0, 41):
        t = i / 40
        y = -150 + 300 * t
        x = -18 + 34 * math.sin(t * math.pi * 1.15 - 0.4)
        pts.append((x, y))
    path = "M" + " L".join(f"{x:.1f} {y:.1f}" for x, y in pts)
    stitches = []
    for i in range(3, 40, 3):
        (x0, y0), (x1, y1) = pts[i - 1], pts[i + 1]
        dx, dy = x1 - x0, y1 - y0
        L = math.hypot(dx, dy); nx, ny = -dy / L, dx / L
        cx, cy = pts[i]
        stitches.append(f'<line x1="{cx - nx*16:.1f}" y1="{cy - ny*16:.1f}" x2="{cx + nx*16:.1f}" y2="{cy + ny*16:.1f}"/>')
    # reticle locked on the seam point
    rx, ry = pts[20]
    ticks = "".join(
        f'<line x1="{rx + math.cos(a)*82:.1f}" y1="{ry + math.sin(a)*82:.1f}" x2="{rx + math.cos(a)*104:.1f}" y2="{ry + math.sin(a)*104:.1f}"/>'
        for a in (0, math.pi/2, math.pi, 3*math.pi/2))
    return f"""<g transform="scale({scale})">
  <!-- TV body -->
  <rect x="-190" y="-125" width="380" height="250" rx="26" fill="url(#scr{uid})"/>
  <g clip-path="url(#screen{uid})">
    <rect x="-190" y="-125" width="190" height="250" fill="url(#adside{uid})"/>
    <g stroke="{CYAN}" stroke-opacity=".10" stroke-width="2">
      {''.join(f'<line x1="-190" y1="{y}" x2="190" y2="{y}"/>' for y in range(-110, 125, 22))}
    </g>
    <g filter="url(#glowA{uid})" fill="none" stroke="{AMBER}" stroke-linecap="round">
      <path d="{path}" stroke-width="7" stroke-dasharray="18 12"/>
      <g stroke-width="5">{''.join(stitches)}</g>
    </g>
  </g>
  <rect x="-190" y="-125" width="380" height="250" rx="26" fill="none" stroke="{CYAN}" stroke-width="9" filter="url(#glowC{uid})"/>
  <rect x="-64" y="146" width="128" height="10" rx="5" fill="{CYAN}" filter="url(#glowC{uid})"/>
  <path d="M-20 125 L-32 150 M20 125 L32 150" stroke="{CYAN}" stroke-width="7" stroke-linecap="round"/>
  <!-- reticle -->
  <g fill="none" stroke="{INK}" stroke-linecap="round" filter="url(#glowC{uid})">
    <circle cx="{rx:.1f}" cy="{ry:.1f}" r="70" stroke-width="7"/>
    <circle cx="{rx:.1f}" cy="{ry:.1f}" r="30" stroke-width="3" stroke-opacity=".55"/>
    <g stroke-width="7">{ticks}</g>
  </g>
  <circle cx="{rx:.1f}" cy="{ry:.1f}" r="8" fill="{AMBER}" filter="url(#glowA{uid})"/>
</g>"""

W, H = 1600, 900
banner = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">
{FONTS}{defs('b')}
<rect width="{W}" height="{H}" fill="url(#bgb)"/>
<rect width="{W}" height="{H}" fill="url(#gridb)"/>
<g transform="translate(390 430)">{mark('b', 1.12)}</g>
<g font-family="SG, 'Space Grotesk', system-ui, sans-serif" font-weight="700">
  <text x="700" y="440" font-size="132" letter-spacing="-4" fill="{INK}">Seam<tspan fill="url(#wordb)">Hunter</tspan></text>
</g>
<rect x="706" y="478" width="120" height="6" rx="3" fill="{CYAN}"/>
<text x="706" y="540" font-family="JB, 'JetBrains Mono', monospace" font-size="27" font-weight="600" letter-spacing="7" fill="#9FB2D8">FIND THE SEAM · CUT THE AD</text>
<text x="706" y="600" font-family="JB, 'JetBrains Mono', monospace" font-size="20" letter-spacing="1.5" fill="#5E7098">static ad-seam analyzer for Android TV  ·  local  ·  private</text>
</svg>"""
open('seamhunter-banner.svg', 'w').write(banner)

S = 1024
icon = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{S}" height="{S}" viewBox="0 0 {S} {S}">
{defs('i')}
<rect width="{S}" height="{S}" rx="220" fill="url(#bgi)"/>
<rect width="{S}" height="{S}" rx="220" fill="url(#gridi)"/>
<rect x="6" y="6" width="{S-12}" height="{S-12}" rx="214" fill="none" stroke="{CYAN}" stroke-opacity=".18" stroke-width="4"/>
<g transform="translate(512 494)">{mark('i', 1.74)}</g>
</svg>"""
open('seamhunter-icon.svg', 'w').write(icon)
print("ok", len(banner)//1024, "KB", len(icon)//1024, "KB")
