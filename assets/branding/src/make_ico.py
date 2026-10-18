"""Build seamhunter.ico: 16/24/32 px from the TV-only small art (readable in the taskbar),
48-256 px from the full tile. Run after render2.py."""
from PIL import Image

big = Image.open("seamhunter-wood-icon.png").convert("RGBA")
small = Image.open("seamhunter-wood-icon-small.png").convert("RGBA")
frames = {s: small.resize((s, s), Image.LANCZOS) for s in (16, 24, 32)}
frames.update({s: big.resize((s, s), Image.LANCZOS) for s in (48, 64, 128, 256)})
frames[256].save("seamhunter.ico", format="ICO", sizes=[(s, s) for s in sorted(frames)],
                 append_images=[frames[s] for s in sorted(frames) if s != 256])
print("seamhunter.ico written")
