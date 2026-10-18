import math, random
src = open('rain.py').read()
exec(src.split("W, H = 1600, 900\n# keep-out")[0])      # FONTS, defs, rain(), rain_defs, CYAN/AMBER/INK

TEAL, TEAL2, YEL, ORG = "#22D3C5", "#7CF7EA", "#FFE45C", "#FF8A1F"

def retro_defs(u):
    return f"""<defs>
  <linearGradient id="cab{u}" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#1B2440"/><stop offset="1" stop-color="#0B1022"/></linearGradient>
  <radialGradient id="crt{u}" cx="50%" cy="48%" r="70%">
    <stop offset="0" stop-color="#062A2E"/><stop offset=".65" stop-color="#03171C"/><stop offset="1" stop-color="#010608"/></radialGradient>
  <radialGradient id="crtvig{u}" cx="50%" cy="50%" r="62%">
    <stop offset=".55" stop-color="#000" stop-opacity="0"/><stop offset="1" stop-color="#000" stop-opacity=".78"/></radialGradient>
  <linearGradient id="glare{u}" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#fff" stop-opacity=".16"/><stop offset=".35" stop-color="#fff" stop-opacity=".03"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient>
  <linearGradient id="tear{u}" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="{YEL}"/><stop offset=".5" stop-color="#FFB02E"/><stop offset="1" stop-color="{ORG}"/></linearGradient>
  <radialGradient id="burst{u}" cx="50%" cy="50%" r="50%">
    <stop offset="0" stop-color="{ORG}" stop-opacity=".55"/><stop offset=".45" stop-color="{ORG}" stop-opacity=".16"/><stop offset="1" stop-color="{ORG}" stop-opacity="0"/></radialGradient>
  <pattern id="scan{u}" width="4" height="4" patternUnits="userSpaceOnUse"><rect width="4" height="1.3" fill="#000" fill-opacity=".38"/></pattern>
  <filter id="gT{u}" filterUnits="userSpaceOnUse" x="-500" y="-500" width="1000" height="1000"><feGaussianBlur stdDeviation="2.6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  <filter id="gO{u}" filterUnits="userSpaceOnUse" x="-500" y="-500" width="1000" height="1000"><feGaussianBlur stdDeviation="6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  <filter id="gC{u}" filterUnits="userSpaceOnUse" x="-500" y="-500" width="1000" height="1000"><feGaussianBlur stdDeviation="6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  <clipPath id="scr{u}"><path d="{screen_path()}"/></clipPath>
</defs>"""

# CRT screen: rounded "TV-shaped" bulge (x -170..90, y -105..105)
SX0, SX1, SY0, SY1 = -172, 92, -106, 106
def screen_path():
    x0, x1, y0, y1, r, b = SX0, SX1, SY0, SY1, 34, 7   # b = bulge of each edge
    return (f"M{x0+r} {y0} Q{(x0+x1)/2} {y0-b} {x1-r} {y0} Q{x1} {y0} {x1} {y0+r} "
            f"Q{x1+b} {(y0+y1)/2} {x1} {y1-r} Q{x1} {y1} {x1-r} {y1} Q{(x0+x1)/2} {y1+b} {x0+r} {y1} "
            f"Q{x0} {y1} {x0} {y1-r} Q{x0-b} {(y0+y1)/2} {x0} {y0+r} Q{x0} {y0} {x0+r} {y0} Z")

def circuits(rnd, n=26):
    out = []
    for i in range(n):
        side = rnd.choice("LRTB")
        if side == "L": x, y, dx, dy = SX0 - 5, rnd.uniform(SY0, SY1), 1, 0
        elif side == "R": x, y, dx, dy = SX1 + 5, rnd.uniform(SY0, SY1), -1, 0
        elif side == "T": x, y, dx, dy = rnd.uniform(SX0, SX1), SY0 - 5, 0, 1
        else: x, y, dx, dy = rnd.uniform(SX0, SX1), SY1 + 5, 0, -1
        pts = [(x, y)]
        for seg in range(rnd.randint(2, 4)):
            L = rnd.uniform(18, 70)
            x += dx * L; y += dy * L
            pts.append((x, y))
            # 45-degree bend toward the centre line
            tx = -40 - x; ty = -y
            ndx = (1 if tx > 0 else -1) if dy else dx
            ndy = (1 if ty > 0 else -1) if dx else dy
            if rnd.random() < 0.7:
                d = rnd.uniform(10, 26); x += ndx * d; y += ndy * d; pts.append((x, y))
        d = "M" + " L".join(f"{a:.1f} {b:.1f}" for a, b in pts)
        bright = rnd.random() < 0.28
        w = rnd.choice([1.6, 2.2, 3])
        col = TEAL2 if bright else TEAL
        op = .85 if bright else .32
        out.append(f'<path d="{d}" fill="none" stroke="{col}" stroke-opacity="{op}" stroke-width="{w}" stroke-linejoin="round"'
                   + (f' filter="url(#gT{{u}})"' if bright else "") + "/>")
        ex, ey = pts[-1]
        out.append(f'<circle cx="{ex:.1f}" cy="{ey:.1f}" r="{w+1.6:.1f}" fill="#03171C" stroke="{col}" stroke-opacity="{op}" stroke-width="{w*0.9:.1f}"/>')
    return "".join(out)

def binary_field(rnd):
    out = []
    y = SY0 + 12
    while y < SY1 + 10:
        size = rnd.choice([9, 11, 13, 16, 22])
        x = SX0 + rnd.uniform(-10, 10)
        while x < SX1:
            n = rnd.randint(3, 9)
            txt = "".join(rnd.choice("01") for _ in range(n))
            op = rnd.choice([.10, .14, .2, .28, .45])
            col = TEAL2 if op > .3 else TEAL
            out.append(f'<text x="{x:.0f}" y="{y:.0f}" font-size="{size}" fill="{col}" fill-opacity="{op}">{txt}</text>')
            x += n * size * 0.62 + rnd.uniform(12, 40)
        y += size + rnd.uniform(3, 9)
    return f'<g font-family="JB, monospace" font-weight="700">{"".join(out)}</g>'

def tear_path(rnd, cx):
    pts = []
    y = SY0 - 12
    x = cx
    while y < SY1 + 12:
        pts.append((x, y))
        y += rnd.uniform(9, 17)
        x = cx + rnd.uniform(-11, 11) + 7 * math.sin(y / 30)
    return pts

def mark_retro(u, scale=1.0, seed=3):
    rnd = random.Random(seed)
    cx = -40                      # screen centre x
    tp = tear_path(rnd, cx)
    tear = "M" + " L".join(f"{a:.1f} {b:.1f}" for a, b in tp)
    # branches off the tear (lightning cracks)
    branches = []
    for i in range(2, len(tp) - 2, 2):
        if rnd.random() < 0.65:
            x, y = tp[i]; d = rnd.choice([-1, 1]); pts = [(x, y)]
            for _ in range(rnd.randint(2, 3)):
                x += d * rnd.uniform(8, 18); y += rnd.uniform(-9, 9); pts.append((x, y))
            branches.append("M" + " L".join(f"{a:.1f} {b:.1f}" for a, b in pts))
    # stitches across the tear
    stitches = []
    for i in range(1, len(tp) - 1):
        (x0, y0), (x1, y1) = tp[i - 1], tp[i + 1]
        dx, dy = x1 - x0, y1 - y0; L = math.hypot(dx, dy) or 1
        nx, ny = -dy / L, dx / L; x, y = tp[i]
        stitches.append(f'<line x1="{x-nx*12:.1f}" y1="{y-ny*12:.1f}" x2="{x+nx*12:.1f}" y2="{y+ny*12:.1f}"/>')
    # bursting binary particles
    parts = []
    for _ in range(70):
        i = rnd.randrange(len(tp)); x, y = tp[i]
        ang = rnd.uniform(0, 2 * math.pi); dist = abs(rnd.gauss(0, 30)) + 6
        px, py = x + math.cos(ang) * dist * 1.5, y + math.sin(ang) * dist * 0.8
        if not (SX0 + 6 < px < SX1 - 6 and SY0 + 6 < py < SY1 - 6):
            continue
        size = rnd.choice([7, 8, 9, 11, 13, 16])
        col = rnd.choice([YEL, "#FFC43D", ORG, ORG])
        op = max(.35, 1 - dist / 90)
        parts.append(f'<text x="{px:.1f}" y="{py:.1f}" font-size="{size}" fill="{col}" fill-opacity="{op:.2f}" '
                     f'transform="rotate({rnd.uniform(-60, 60):.0f} {px:.1f} {py:.1f})">{rnd.choice("01")}</text>')
    rx, ry = tp[len(tp) // 2]
    ticks = "".join(f'<line x1="{rx+math.cos(a)*56:.1f}" y1="{ry+math.sin(a)*56:.1f}" x2="{rx+math.cos(a)*74:.1f}" y2="{ry+math.sin(a)*74:.1f}"/>'
                    for a in (0, math.pi/2, math.pi, 3*math.pi/2))
    body = f"""
  <!-- antenna -->
  <g stroke="{CYAN}" stroke-width="5" stroke-linecap="round" filter="url(#gC{u})">
    <line x1="-40" y1="-150" x2="-118" y2="-238"/><line x1="-40" y1="-150" x2="30" y2="-246"/>
  </g>
  <circle cx="-118" cy="-238" r="7" fill="{CYAN}" filter="url(#gC{u})"/><circle cx="30" cy="-246" r="7" fill="{CYAN}" filter="url(#gC{u})"/>
  <path d="M-72 -150 Q-40 -176 -8 -150 Z" fill="url(#cab{u})" stroke="{CYAN}" stroke-width="5" filter="url(#gC{u})"/>
  <!-- legs -->
  <g stroke="{CYAN}" stroke-width="7" stroke-linecap="round" filter="url(#gC{u})">
    <line x1="-150" y1="150" x2="-168" y2="196"/><line x1="130" y1="150" x2="148" y2="196"/>
  </g>
  <!-- cabinet -->
  <rect x="-208" y="-150" width="416" height="300" rx="44" fill="url(#cab{u})"/>
  <rect x="-208" y="-150" width="416" height="300" rx="44" fill="none" stroke="{CYAN}" stroke-width="8" filter="url(#gC{u})"/>
  <rect x="-196" y="-138" width="392" height="276" rx="36" fill="none" stroke="{CYAN}" stroke-opacity=".25" stroke-width="2"/>
  <!-- bezel -->
  <path d="{screen_path()}" transform="translate(0 0) scale(1.075)" fill="#050A16" stroke="{CYAN}" stroke-opacity=".5" stroke-width="3"/>
  <!-- screen -->
  <path d="{screen_path()}" fill="url(#crt{u})"/>
  <g clip-path="url(#scr{u})">
    {binary_field(rnd)}
    {circuits(rnd).replace('{u}', u)}
    <ellipse cx="{rx:.1f}" cy="{ry:.1f}" rx="95" ry="120" fill="url(#burst{u})"/>
    <g filter="url(#gO{u})" fill="none" stroke-linecap="round" stroke-linejoin="round">
      <path d="{tear}" stroke="url(#tear{u})" stroke-width="7"/>
      <g stroke="#FFB02E" stroke-width="2.4" stroke-opacity=".9">{''.join(f'<path d="{b}"/>' for b in branches)}</g>
      <g stroke="{YEL}" stroke-width="3.6">{''.join(stitches)}</g>
    </g>
    <g font-family="JB, monospace" font-weight="800" filter="url(#gT{u})">{''.join(parts)}</g>
    <!-- reticle -->
    <g fill="none" stroke="{INK}" stroke-linecap="round" filter="url(#gC{u})">
      <circle cx="{rx:.1f}" cy="{ry:.1f}" r="46" stroke-width="5"/>
      <circle cx="{rx:.1f}" cy="{ry:.1f}" r="19" stroke-width="2.4" stroke-opacity=".6"/>
      <g stroke-width="5">{ticks}</g>
    </g>
    <rect x="-220" y="-130" width="340" height="260" fill="url(#scan{u})"/>
    <path d="{screen_path()}" fill="url(#crtvig{u})"/>
    <path d="M-150 -96 Q-60 -110 60 -96 Q-40 -60 -150 -20 Z" fill="url(#glare{u})"/>
  </g>
  <path d="{screen_path()}" fill="none" stroke="{TEAL2}" stroke-opacity=".35" stroke-width="2"/>
  <!-- control panel -->
  <line x1="112" y1="-122" x2="112" y2="122" stroke="{CYAN}" stroke-opacity=".3" stroke-width="2"/>
  <g filter="url(#gC{u})">
    <circle cx="156" cy="-78" r="26" fill="#0B1226" stroke="{CYAN}" stroke-width="5"/>
    <line x1="156" y1="-78" x2="171" y2="-96" stroke="{AMBER}" stroke-width="5" stroke-linecap="round"/>
    <circle cx="156" cy="-10" r="20" fill="#0B1226" stroke="{CYAN}" stroke-width="5"/>
    <line x1="156" y1="-10" x2="143" y2="-24" stroke="{AMBER}" stroke-width="4.5" stroke-linecap="round"/>
  </g>
  <g stroke="{CYAN}" stroke-opacity=".55" stroke-width="4" stroke-linecap="round">
    {''.join(f'<line x1="134" y1="{y}" x2="178" y2="{y}"/>' for y in range(38, 116, 13))}
  </g>
  <circle cx="178" cy="-124" r="4" fill="{AMBER}" filter="url(#gO{u})"/>
"""
    return f'<g transform="scale({scale})">{body}</g>'

W, H = 1600, 900
BZ = [("rect", 690, 330, 1470, 612, 110, 0.0), ("ellipse", 360, 430, 290, 290, 120, 0.10)]
for name, pal in (("green", ("#DDFFE6", "#27E36B")), ("cyan", ("#D9FBFF", "#35D6F5"))):
    u = "r" + name
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">
{FONTS}{defs(u)}{rain_defs(u, pal[0])}{retro_defs(u)}
<rect width="{W}" height="{H}" fill="#060A14"/>
{rain(u, W, H, pal, zones=BZ)}
<rect width="{W}" height="{H}" fill="url(#vig{u})"/>
<g transform="translate(360 470)">{mark_retro(u, 1.18)}</g>
<text x="700" y="440" font-family="SG, 'Space Grotesk', sans-serif" font-weight="700" font-size="132" letter-spacing="-4" fill="{INK}">Seam<tspan fill="url(#word{u})">Hunter</tspan></text>
<rect x="706" y="478" width="120" height="6" rx="3" fill="{CYAN}"/>
<text x="706" y="540" font-family="JB, 'JetBrains Mono', monospace" font-size="27" font-weight="600" letter-spacing="7" fill="#A9BCE0">FIND THE SEAM · CUT THE AD</text>
<text x="706" y="600" font-family="JB, 'JetBrains Mono', monospace" font-size="20" letter-spacing="1.5" fill="#6A7DA6">static ad-seam analyzer for Android TV  ·  local  ·  private</text>
</svg>"""
    open(f"seamhunter-retro-banner-{name}.svg", "w").write(svg)

S = 1024; u = "ri"
icon = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{S}" height="{S}" viewBox="0 0 {S} {S}">
{FONTS}{defs(u)}{rain_defs(u, '#DDFFE6')}{retro_defs(u)}
<clipPath id="tile{u}"><rect width="{S}" height="{S}" rx="220"/></clipPath>
<g clip-path="url(#tile{u})">
  <rect width="{S}" height="{S}" fill="#060A14"/>
  {rain(u, S, S, ("#DDFFE6", "#27E36B"), seed=7, zones=[("ellipse", 512, 530, 420, 380, 150, 0.0)], scale=1.15)}
  <rect width="{S}" height="{S}" fill="url(#vig{u})"/>
</g>
<rect x="6" y="6" width="{S-12}" height="{S-12}" rx="214" fill="none" stroke="{CYAN}" stroke-opacity=".22" stroke-width="4"/>
<g transform="translate(512 548)">{mark_retro(u, 1.72)}</g>
</svg>"""
open("seamhunter-retro-icon.svg", "w").write(icon)
print("ok")
