"""Check native browser form Origin; dummy credentials, no production login.

Run in a disposable sandboxed Browser-image container with its own tmpfs and
internal network/egress proxy. It never uses the production database or keys.
"""
import asyncio
import json
from pathlib import Path
from cryptography.fernet import Fernet
from browser.config import Config
from browser.engine import Engine
from browser.store import Store, Principal
from browser.commands import validate


async def main():
    config = Config(database_url='sqlite:////tmp/native-form.db', data=Path('/tmp/native-form-data'),
        runtime=Path('/run/daoos-browser'), profile_key=Fernet.generate_key().decode(),
        public_url='https://oknakomfort72.ru/browser', operation_timeout=90)
    config.data.mkdir(mode=0o700, parents=True)
    store = Store(config.database_url)
    p = Principal('native-form-test', 'disposable', 'provisioner', frozenset({'read', 'write'}))
    raw = store.issue_key(p, p.scopes)
    p = store.authenticate(raw)
    engine = Engine(config, store)
    await engine.start()
    try:
        created = await engine.create(p, validate('create_session', {}, True), 'native-form-check')
        s = engine.session(created['session_id'], p)
        page = s.page
        response = await page.goto(config.public_url+'/operator/login', wait_until='load')
        policies = response.headers.get('referrer-policy', '')
        # Deliberately invalid credential. This tests transport, not authentication.
        await page.locator('input[name=api_key]').fill('dbk_invalid_native_form_probe')
        async with page.expect_request(lambda req: req.method == 'POST' and req.url.endswith('/operator/login')) as posted:
            async with page.expect_response(lambda res: res.request.method == 'POST' and res.url.endswith('/operator/login')) as replied:
                await page.get_by_role('button', name='Войти', exact=True).click()
        request, reply = await posted.value, await replied.value
        origin = (await request.all_headers()).get('origin')
        body = await reply.json()
        assert origin == config.origin, {'origin': origin, 'policy': policies}
        assert reply.status == 403 and body.get('error') == 'invalid_credentials', body
        print(json.dumps({'passed': True, 'native_form_origin': origin,
            'referrer_policy': policies, 'invalid_key_rejected': True}), flush=True)
        await engine.close(s, save=False)
    finally:
        await engine.stop()


asyncio.run(main())
