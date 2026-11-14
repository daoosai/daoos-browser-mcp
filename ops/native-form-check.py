"""Check native browser form Origin; dummy credentials, no production login.

Run in a disposable sandboxed Browser-image container with its own tmpfs and
internal network/egress proxy and its own temporary browser profile.
The browser uses the same filesystem wrapper and native Chromium sandbox.
An optional protected key file tests login with a temporary operator identity;
revoke that identity after the test. Never pass a real website password.
"""
import asyncio
import json
import os
from pathlib import Path
from playwright.async_api import async_playwright


async def main():
    base = 'https://oknakomfort72.ru/browser'
    origin_expected = 'https://oknakomfort72.ru'
    profile = Path('/run/daoos-browser/session_native_form/profile')
    profile.mkdir(mode=0o700, parents=True)
    display = await asyncio.create_subprocess_exec('Xvfb', ':91', '-screen', '0', '1280x800x24', '-nolisten', 'tcp', '-ac',
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    for _ in range(50):
        if Path('/tmp/.X11-unix/X91').exists(): break
        await asyncio.sleep(.05)
    context = None
    playwright = await async_playwright().start()
    try:
        context = await playwright.chromium.launch_persistent_context(str(profile), headless=True,
            executable_path='/usr/local/bin/chromium-sandbox', chromium_sandbox=True, timeout=90000,
            env={**os.environ, 'DISPLAY': ':91'}, proxy={'server': 'http://egress:8888'},
            args=['--disable-gpu', '--disable-dev-shm-usage', '--proxy-bypass-list=<-loopback>'])
        context.set_default_timeout(30000)
        page = context.pages[0]
        print('Native Chromium started', flush=True)
        response = await page.goto(base+'/operator/login', wait_until='load')
        policies = response.headers.get('referrer-policy', '')
        # Deliberately invalid credential. This tests transport, not authentication.
        await page.locator('input[name=api_key]').fill('dbk_invalid_native_form_probe')
        async with page.expect_request(lambda req: req.method == 'POST' and req.url.endswith('/operator/login')) as posted:
            async with page.expect_response(lambda res: res.request.method == 'POST' and res.url.endswith('/operator/login')) as replied:
                await page.get_by_role('button', name='Войти', exact=True).click()
        request, reply = await posted.value, await replied.value
        origin = (await request.all_headers()).get('origin')
        body = await reply.text()
        assert origin == origin_expected, {'origin': origin, 'policy': policies}
        assert reply.status == 403 and 'role="alert"' in body and 'Ключ недействителен' in body
        valid_login = False
        key_file = os.getenv('NATIVE_FORM_OPERATOR_KEY_FILE')
        if key_file:
            await page.goto(base+'/operator/login', wait_until='load')
            await page.locator('input[name=api_key]').fill(' '+Path(key_file).read_text().strip()+' ')
            await page.get_by_role('button', name='Войти', exact=True).click()
            await page.wait_for_url(base+'/operator')
            assert await page.get_by_role('heading', name='Браузерные сессии', exact=True).count() == 1
            cookie = next(c for c in await context.cookies() if c['name'] == 'browser_operator')
            assert cookie['secure'] and cookie['httpOnly'] and cookie['path'] == '/browser'
            valid_login = True
        print(json.dumps({'passed': True, 'native_form_origin': origin, 'valid_operator_login': valid_login,
            'referrer_policy': policies, 'invalid_key_rejected': True}), flush=True)
    finally:
        if context:
            try: await asyncio.wait_for(context.close(), 10)
            except Exception: pass
        await playwright.stop()
        if display.returncode is None:
            display.terminate()
            await display.wait()


asyncio.run(main())
