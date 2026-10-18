import asyncio
from playwright.async_api import async_playwright
JOBS = [("seamhunter-wood-banner",1600,900),("seamhunter-wood-icon",1024,1024),("seamhunter-wood-icon-small",256,256)]
async def main():
    async with async_playwright() as p:
        import os
        exe = os.environ.get("CHROMIUM_PATH")  # optional; default = Playwright's own Chromium
        b = await p.chromium.launch(**({"executable_path": exe} if exe else {}))
        for name, w, h in JOBS:
            pg = await b.new_page(viewport={"width": w, "height": h})
            await pg.set_content(f"<html><body style='margin:0;background:transparent'>{open(name + '.svg').read()}</body></html>")
            await pg.wait_for_timeout(500)
            await pg.screenshot(path=f"{name}.png", omit_background=True, clip={"x":0,"y":0,"width":w,"height":h})
        await b.close()
asyncio.run(main())
