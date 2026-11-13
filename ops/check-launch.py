"""Empty-page sandbox launch diagnostic. Never loads a site or a saved profile."""
import asyncio
import os
import tempfile
from pathlib import Path
from playwright.async_api import async_playwright

async def main():
    directory = Path(tempfile.mkdtemp(prefix='session_',dir='/run/daoos-browser'))
    (directory/'profile').mkdir()
    xv = await asyncio.create_subprocess_exec('Xvfb',':99','-screen','0','1280x800x24','-nolisten','tcp','-ac',stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
    await asyncio.sleep(.3)
    try:
        async with async_playwright() as pw:
            try:
                ctx = await pw.chromium.launch_persistent_context(str(directory/'profile'),headless=False,executable_path='/usr/local/bin/chromium-sandbox',env={**os.environ,'DISPLAY':':99'},chromium_sandbox=True,args=['--disable-dev-shm-usage'])
                print('Chromium started with both sandboxes')
                await ctx.close()
            except Exception as exc:
                print(str(exc).split('Call log:')[0])
                raise SystemExit(1)
    finally:
        xv.terminate()
        await xv.wait()
        __import__('shutil').rmtree(directory)

asyncio.run(main())
