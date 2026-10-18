src = open('wood.py').read()
exec(src.split("W, H = 1600, 900\nBZ")[0])
u = "ws"
# viewBox crops to the cabinet + a stub of the antennas; transparent background
svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="-262 -232 492 492">
{FONTS}{defs(u)}{retro_defs(u)}{wood_defs(u)}
<g transform="translate(0 0)">{mark_wood(u, 1.0).replace('<ellipse cx="-10" cy="0" rx="330" ry="300" fill="url(#backws)"/>', '')}</g>
</svg>"""
open("seamhunter-wood-icon-small.svg", "w").write(svg)
print("ok")
