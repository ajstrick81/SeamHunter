import math, random
src = open('retro.py').read()
exec(src.split("W, H = 1600, 900\nBZ")[0])       # rain + screen content helpers + mark_retro

OUT = "#140A05"          # cartoon outline
WOOD1, WOOD2, WOODHI, WOODDK = "#9A4F2A", "#6E3218", "#C0703F", "#4A200E"
CREAM, CREAM2, GRAY, GRAYDK = "#EFDDBF", "#D9C29C", "#8D9091", "#5E6263"

def wood_defs(u):
    return f"""<defs>
  <linearGradient id="wd{u}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{WOOD1}"/><stop offset="1" stop-color="{WOOD2}"/></linearGradient>
  <linearGradient id="wds{u}" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{WOODDK}"/><stop offset="1" stop-color="#5E2A13"/></linearGradient>
  <linearGradient id="cr{u}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{CREAM}"/><stop offset="1" stop-color="{CREAM2}"/></linearGradient>
  <linearGradient id="gy{u}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#A3A6A7"/><stop offset="1" stop-color="{GRAYDK}"/></linearGradient>
  <radialGradient id="knob{u}" cx="40%" cy="35%" r="70%"><stop offset="0" stop-color="#5A5A60"/><stop offset=".5" stop-color="#1E1E22"/><stop offset="1" stop-color="#0A0A0C"/></radialGradient>
  <linearGradient id="brass{u}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#E9D38A"/><stop offset="1" stop-color="#8C6A2A"/></linearGradient>
  <radialGradient id="back{u}" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="#1FC8C0" stop-opacity=".22"/><stop offset=".6" stop-color="#1FC8C0" stop-opacity=".06"/><stop offset="1" stop-color="#1FC8C0" stop-opacity="0"/></radialGradient>
  <pattern id="grain{u}" width="60" height="12" patternUnits="userSpaceOnUse">
    <path d="M0 4 Q15 2 30 4 T60 4" fill="none" stroke="#3A1608" stroke-opacity=".22" stroke-width="1.2"/>
    <path d="M0 10 Q20 8 40 10 T60 9" fill="none" stroke="{WOODHI}" stroke-opacity=".18" stroke-width="1"/>
  </pattern>
</defs>"""

def mark_wood(u, scale=1.0, seed=3):
    rnd = random.Random(seed)
    cx = -40
    tp = tear_path(rnd, cx)
    tear = "M" + " L".join(f"{a:.1f} {b:.1f}" for a, b in tp)
    branches, stitches, parts = [], [], []
    for i in range(2, len(tp) - 2, 2):
        if rnd.random() < 0.65:
            x, y = tp[i]; d = rnd.choice([-1, 1]); pts = [(x, y)]
            for _ in range(rnd.randint(2, 3)):
                x += d * rnd.uniform(8, 18); y += rnd.uniform(-9, 9); pts.append((x, y))
            branches.append("M" + " L".join(f"{a:.1f} {b:.1f}" for a, b in pts))
    for i in range(1, len(tp) - 1):
        (x0, y0), (x1, y1) = tp[i - 1], tp[i + 1]
        dx, dy = x1 - x0, y1 - y0; L = math.hypot(dx, dy) or 1
        nx, ny = -dy / L, dx / L; x, y = tp[i]
        stitches.append(f'<line x1="{x-nx*12:.1f}" y1="{y-ny*12:.1f}" x2="{x+nx*12:.1f}" y2="{y+ny*12:.1f}"/>')
    for _ in range(70):
        i = rnd.randrange(len(tp)); x, y = tp[i]
        ang = rnd.uniform(0, 2 * math.pi); dist = abs(rnd.gauss(0, 30)) + 6
        px, py = x + math.cos(ang) * dist * 1.5, y + math.sin(ang) * dist * 0.8
        if not (SX0 + 6 < px < SX1 - 6 and SY0 + 6 < py < SY1 - 6):
            continue
        size = rnd.choice([7, 8, 9, 11, 13, 16]); col = rnd.choice([YEL, "#FFC43D", ORG, ORG])
        parts.append(f'<text x="{px:.1f}" y="{py:.1f}" font-size="{size}" fill="{col}" fill-opacity="{max(.35, 1 - dist/90):.2f}" '
                     f'transform="rotate({rnd.uniform(-60, 60):.0f} {px:.1f} {py:.1f})">{rnd.choice("01")}</text>')
    rx, ry = tp[len(tp) // 2]
    ticks = "".join(f'<line x1="{rx+math.cos(a)*56:.1f}" y1="{ry+math.sin(a)*56:.1f}" x2="{rx+math.cos(a)*74:.1f}" y2="{ry+math.sin(a)*74:.1f}"/>'
                    for a in (0, math.pi/2, math.pi, 3*math.pi/2))
    slats = "".join(f'<rect x="126" y="{y}" width="64" height="7" rx="2" fill="{WOOD1 if k % 2 else WOOD2}" stroke="{OUT}" stroke-width="1.5"/>'
                    for k, y in enumerate(range(22, 104, 11)))
    body = f"""
  <ellipse cx="-10" cy="0" rx="330" ry="300" fill="url(#back{u})"/>
  <!-- antennas + dome (light rim so they read on a dark background) -->
  <g stroke-linecap="round">
    <line x1="-58" y1="-166" x2="-150" y2="-300" stroke="#E6D6BA" stroke-width="9"/><line x1="-58" y1="-166" x2="-150" y2="-300" stroke="#1C1C20" stroke-width="5"/>
    <line x1="-8" y1="-166" x2="70" y2="-316" stroke="#E6D6BA" stroke-width="9"/><line x1="-8" y1="-166" x2="70" y2="-316" stroke="#1C1C20" stroke-width="5"/>
  </g>
  <circle cx="-150" cy="-300" r="9" fill="#2A2A30" stroke="#E6D6BA" stroke-width="2.5"/><circle cx="70" cy="-316" r="9" fill="#2A2A30" stroke="#E6D6BA" stroke-width="2.5"/>
  <path d="M-86 -150 Q-86 -186 -34 -186 Q18 -186 18 -150 Z" fill="#1C1C20" stroke="#E6D6BA" stroke-width="2.5"/>
  <path d="M-70 -160 Q-60 -176 -34 -178" fill="none" stroke="#fff" stroke-opacity=".25" stroke-width="4" stroke-linecap="round"/>
  <!-- legs + plinth -->
  <g fill="url(#wd{u})" stroke="{OUT}" stroke-width="5" stroke-linejoin="round">
    <path d="M-176 170 L-196 232 L-178 234 L-156 172 Z"/><path d="M150 170 L172 232 L190 230 L170 170 Z"/>
    <path d="M-120 170 L-128 222 L-114 222 L-104 170 Z" opacity=".75"/><path d="M96 170 L104 222 L118 222 L112 170 Z" opacity=".75"/>
    <path d="M-206 150 L200 150 L186 176 L-192 176 Z"/>
  </g>
  <!-- cabinet side (depth) + front -->
  <path d="M-222 -142 L-248 -120 L-248 142 L-222 158 Z" fill="url(#wds{u})" stroke="{OUT}" stroke-width="6" stroke-linejoin="round"/>
  <rect x="-222" y="-152" width="428" height="312" rx="30" fill="url(#wd{u})" stroke="{OUT}" stroke-width="7"/>
  <rect x="-222" y="-152" width="428" height="312" rx="30" fill="url(#grain{u})"/>
  <path d="M-200 -140 Q0 -150 190 -140" fill="none" stroke="{WOODHI}" stroke-opacity=".6" stroke-width="4" stroke-linecap="round"/>
  <!-- cream bezel + gray inner frame -->
  <rect x="-206" y="-136" width="318" height="274" rx="20" fill="url(#cr{u})" stroke="{OUT}" stroke-width="4"/>
  <path d="{screen_path()}" transform="scale(1.12)" fill="url(#gy{u})" stroke="{OUT}" stroke-width="3"/>
  <path d="{screen_path()}" transform="scale(1.05)" fill="#2A2D2E" stroke="{OUT}" stroke-width="2"/>
  <!-- screen (same neon content as the other version) -->
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
    <g fill="none" stroke="{INK}" stroke-linecap="round" filter="url(#gC{u})">
      <circle cx="{rx:.1f}" cy="{ry:.1f}" r="46" stroke-width="5"/>
      <circle cx="{rx:.1f}" cy="{ry:.1f}" r="19" stroke-width="2.4" stroke-opacity=".6"/>
      <g stroke-width="5">{ticks}</g>
    </g>
    <rect x="-220" y="-130" width="340" height="260" fill="url(#scan{u})"/>
    <path d="{screen_path()}" fill="url(#crtvig{u})"/>
    <path d="M-150 -96 Q-60 -110 60 -96 Q-40 -60 -150 -20 Z" fill="url(#glare{u})"/>
  </g>
  <path d="{screen_path()}" fill="none" stroke="{OUT}" stroke-width="3"/>
  <!-- control panel -->
  <rect x="118" y="-136" width="80" height="274" rx="10" fill="url(#cr{u})" stroke="{OUT}" stroke-width="4"/>
  <rect x="146" y="-126" width="24" height="18" rx="4" fill="{GRAY}" stroke="{OUT}" stroke-width="2.5"/>
  <circle cx="158" cy="-72" r="30" fill="url(#brass{u})" stroke="{OUT}" stroke-width="4"/>
  <circle cx="158" cy="-72" r="21" fill="url(#knob{u})" stroke="{OUT}" stroke-width="2.5"/>
  <path d="M150 -84 Q160 -90 168 -82" fill="none" stroke="#fff" stroke-opacity=".7" stroke-width="3" stroke-linecap="round"/>
  <rect x="122" y="14" width="72" height="96" rx="8" fill="{WOODDK}" stroke="{OUT}" stroke-width="3"/>
  {slats}
  <g stroke="{OUT}" stroke-width="2.5">
    <circle cx="136" cy="124" r="8.5" fill="url(#knob{u})"/><circle cx="158" cy="124" r="8.5" fill="url(#knob{u})"/><circle cx="180" cy="124" r="8.5" fill="url(#knob{u})"/>
  </g>
  <circle cx="186" cy="-120" r="4.5" fill="{AMBER}" filter="url(#gO{u})"/>
"""
    return f'<g transform="scale({scale})">{body}</g>'

W, H = 1600, 900
BZ = [("rect", 690, 330, 1470, 612, 110, 0.0), ("ellipse", 350, 440, 320, 330, 120, 0.08)]
pal = ("#DDFFE6", "#27E36B"); u = "w"
svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">
{FONTS}{defs(u)}{rain_defs(u, pal[0])}{retro_defs(u)}{wood_defs(u)}
<rect width="{W}" height="{H}" fill="#060A14"/>
{rain(u, W, H, pal, zones=BZ)}
<rect width="{W}" height="{H}" fill="url(#vig{u})"/>
<g transform="translate(350 500)">{mark_wood(u, 1.12)}</g>
<text x="700" y="440" font-family="SG, 'Space Grotesk', sans-serif" font-weight="700" font-size="132" letter-spacing="-4" fill="{INK}">Seam<tspan fill="url(#word{u})">Hunter</tspan></text>
<rect x="706" y="478" width="120" height="6" rx="3" fill="{CYAN}"/>
<text x="706" y="540" font-family="JB, 'JetBrains Mono', monospace" font-size="27" font-weight="600" letter-spacing="7" fill="#A9BCE0">FIND THE SEAM · CLIP THE AD</text>
<text x="706" y="600" font-family="JB, 'JetBrains Mono', monospace" font-size="20" letter-spacing="1.5" fill="#6A7DA6">static ad-seam analyzer for Android TV  ·  local  ·  private</text>
</svg>"""
open("seamhunter-wood-banner.svg", "w").write(svg)
S = 1024; u = "wi"
icon = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{S}" height="{S}" viewBox="0 0 {S} {S}">
{FONTS}{defs(u)}{rain_defs(u, pal[0])}{retro_defs(u)}{wood_defs(u)}
<clipPath id="tile{u}"><rect width="{S}" height="{S}" rx="220"/></clipPath>
<g clip-path="url(#tile{u})">
  <rect width="{S}" height="{S}" fill="#060A14"/>
  {rain(u, S, S, pal, seed=7, zones=[("ellipse", 512, 540, 430, 420, 150, 0.0)], scale=1.15)}
  <rect width="{S}" height="{S}" fill="url(#vig{u})"/>
</g>
<rect x="6" y="6" width="{S-12}" height="{S-12}" rx="214" fill="none" stroke="{CYAN}" stroke-opacity=".22" stroke-width="4"/>
<g transform="translate(520 590)">{mark_wood(u, 1.52)}</g>
</svg>"""
open("seamhunter-wood-icon.svg", "w").write(icon)
print("ok")
