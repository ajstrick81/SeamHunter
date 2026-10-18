import random, re
exec(open('make.py').read().split("W, H = 1600, 900")[0])   # reuse FONTS, defs(), mark()

GLYPHS = list("0123456789ABCDEF0123456789abcdef") + list("L;->()[]{}/$:=vpx") 
TOKENS = ["invoke", "const", "0x7f", "iget", "move", "Ljava", "->", "return", "if-eqz", "smali", "dex"]

def clamp(v): return max(0.0, min(1.0, v))

def keepout(x, y, zones):
    """1 = full strength, 0 = hidden. Smooth fade by distance from each keep-out zone."""
    f = 1.0
    for kind, a, b, c, d, feather, floor in zones:
        if kind == "rect":        # a,b = x0,y0  c,d = x1,y1
            dx = max(a - x, 0, x - c); dy = max(b - y, 0, y - d)
            dist = (dx * dx + dy * dy) ** 0.5
        else:                     # ellipse: a,b = cx,cy  c,d = rx,ry
            r = (((x - a) / c) ** 2 + ((y - b) / d) ** 2) ** 0.5
            dist = max(0.0, (r - 1) * min(c, d))
        f = min(f, floor + (1 - floor) * clamp(dist / feather))
    return f

def layer(rnd, W, H, palette, step, size, density, len_rng, base_op, heads, zones):
    head, trail = palette
    out = []
    for x in range(step // 2, W, step):
        if rnd.random() > density:
            continue
        for _ in range(rnd.choice([1, 1, 2])):
            length = rnd.randint(*len_rng)
            y0 = rnd.randint(-length * size, H)
            tok = list(rnd.choice(TOKENS)) if rnd.random() < 0.2 else []
            for k in range(length):
                y = y0 + k * size
                if y < -size or y > H + size:
                    continue
                ko = keepout(x, y, zones)
                if ko < 0.02:
                    continue
                ch = tok[k] if k < len(tok) else rnd.choice(GLYPHS)
                ch = {"<": "&lt;", ">": "&gt;", "&": "&amp;"}.get(ch, ch)
                fade = (k + 1) / length
                if heads and k == length - 1 and ko > 0.85:
                    out.append(f'<text x="{x}" y="{y}" fill="{head}" fill-opacity="{0.95*ko:.2f}" filter="url(#RG)">{ch}</text>')
                else:
                    op = (0.04 + base_op * fade ** 1.5) * ko
                    if op >= 0.02:
                        out.append(f'<text x="{x}" y="{y}" fill="{trail}" fill-opacity="{op:.2f}">{ch}</text>')
    return f'<g font-size="{size}">{"".join(out)}</g>'

def rain(uid, W, H, palette, seed=42, zones=(), scale=1.0):
    rnd = random.Random(seed)
    far = layer(rnd, W, H, palette, int(15 * scale), int(14 * scale), 0.85, (10, 34), 0.28, False, zones)
    near = layer(rnd, W, H, palette, int(27 * scale), int(21 * scale), 0.62, (8, 26), 0.62, True, zones)
    body = (far + near).replace('url(#RG)', f'url(#rg{uid})')
    return f"""<g font-family="JB, 'JetBrains Mono', monospace" font-weight="500" text-anchor="middle">{body}</g>"""

def rain_defs(uid, glowcol):
    return f"""<defs>
  <filter id="rg{uid}" x="-100%" y="-100%" width="300%" height="300%"><feGaussianBlur stdDeviation="2.4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  <radialGradient id="vig{uid}" cx="50%" cy="50%" r="75%"><stop offset=".45" stop-color="#050810" stop-opacity="0"/><stop offset="1" stop-color="#050810" stop-opacity=".85"/></radialGradient>
  <linearGradient id="calm{uid}" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="#070B16" stop-opacity=".0"/><stop offset=".40" stop-color="#070B16" stop-opacity=".82"/>
    <stop offset=".92" stop-color="#070B16" stop-opacity=".82"/><stop offset="1" stop-color="#070B16" stop-opacity=".0"/>
  </linearGradient>
  <radialGradient id="halo{uid}" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="#070B16" stop-opacity=".92"/><stop offset=".7" stop-color="#070B16" stop-opacity=".6"/><stop offset="1" stop-color="#070B16" stop-opacity="0"/></radialGradient>
</defs>"""

PALETTES = {"cyan": ("#D9FBFF", "#35D6F5"), "green": ("#DDFFE6", "#27E36B")}

W, H = 1600, 900
# keep-out: wordmark/tagline block (fully clear, soft 110px edge) and a dim zone around the TV mark
BZ = [("rect", 690, 330, 1470, 612, 110, 0.0), ("ellipse", 390, 440, 250, 190, 120, 0.12)]
for name, pal in PALETTES.items():
    uid = "b" + name
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">
{FONTS}{defs(uid)}{rain_defs(uid, pal[0])}
<rect width="{W}" height="{H}" fill="#060A14"/>
{rain(uid, W, H, pal, zones=BZ)}
<rect width="{W}" height="{H}" fill="url(#vig{uid})"/>
<g transform="translate(390 430)">{mark(uid, 1.12)}</g>
<text x="700" y="440" font-family="SG, 'Space Grotesk', sans-serif" font-weight="700" font-size="132" letter-spacing="-4" fill="{INK}">Seam<tspan fill="url(#word{uid})">Hunter</tspan></text>
<rect x="706" y="478" width="120" height="6" rx="3" fill="{CYAN}"/>
<text x="706" y="540" font-family="JB, 'JetBrains Mono', monospace" font-size="27" font-weight="600" letter-spacing="7" fill="#A9BCE0">FIND THE SEAM · CUT THE AD</text>
<text x="706" y="600" font-family="JB, 'JetBrains Mono', monospace" font-size="20" letter-spacing="1.5" fill="#6A7DA6">static ad-seam analyzer for Android TV  ·  local  ·  private</text>
</svg>"""
    open(f"seamhunter-banner-rain-{name}.svg", "w").write(svg)

# icon with subtle rain inside the tile
S = 1024
uid = "irain"
icon = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{S}" height="{S}" viewBox="0 0 {S} {S}">
{FONTS}{defs(uid)}{rain_defs(uid, PALETTES['cyan'][0])}
<clipPath id="tile{uid}"><rect width="{S}" height="{S}" rx="220"/></clipPath>
<g clip-path="url(#tile{uid})">
  <rect width="{S}" height="{S}" fill="#060A14"/>
  {rain(uid, S, S, PALETTES['cyan'], seed=7, zones=[("ellipse", 512, 494, 390, 300, 150, 0.0)], scale=1.15)}
  <rect width="{S}" height="{S}" fill="url(#vig{uid})"/>
</g>
<rect x="6" y="6" width="{S-12}" height="{S-12}" rx="214" fill="none" stroke="{CYAN}" stroke-opacity=".22" stroke-width="4"/>
<g transform="translate(512 494)">{mark(uid, 1.74)}</g>
</svg>"""
open("seamhunter-icon-rain.svg", "w").write(icon)
print("ok")
