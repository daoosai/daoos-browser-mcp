"""Disposable fixture pixel/security checks and a real crash of ONLY Browser.
Operator/admin test: run before any real operator has an active browser session.
"""
import argparse
import asyncio
import base64
import io
import json
from pathlib import Path
import subprocess
import uuid
import httpx
import httpx2
from PIL import Image
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


async def main(args):
    key = args.key_file.read_text().strip()
    args.report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    report = {'checks': []}
    def passed(message):
        report['checks'].append(message)
        (args.report_dir/'recovery-report.json').write_text(json.dumps(report, indent=2))
        print('PASS: '+message, flush=True)
    async with httpx2.AsyncClient(headers={'Authorization': 'Bearer '+key}, timeout=150) as transport:
        async with Client(streamable_http_client(args.base+'/mcp', http_client=transport), read_timeout_seconds=150) as client:
            sid = None
            try:
                async def call(tool, action, sid=None, **params):
                    arguments = {'action': action, 'session_id': sid, 'params': params}
                    if tool == 'browser_write': arguments['request_id'] = uuid.uuid4().hex
                    return await client.call_tool(tool, arguments)
                async def write(action, sid=None, **params):
                    result = await call('browser_write', action, sid, **params)
                    assert not result.is_error, result.content
                    return result.structured_content
                created = await write('create_session')
                sid = created['session_id']
                report['session_id'] = sid
                await write('navigate', sid, url='http://fixture/tall', ready_selector='#top')
                await write('scroll', sid, y=300)
                await write('wait', sid, milliseconds=300)
                before = await call('browser_read', 'inspect', sid, selector='#top')
                shot = await call('browser_read', 'screenshot', sid, full_page=True)
                assert not shot.is_error, shot.content
                png = base64.b64decode(next(x.data for x in shot.content if x.type == 'image'))
                (args.report_dir/'tall.png').write_bytes(png)
                with Image.open(io.BytesIO(png)) as image:
                    assert 1250 <= image.width <= 1280 and image.height == 2400, image.size
                    assert [image.getpixel((600, y)) for y in (400, 1200, 2000)] == [(255,0,0),(0,255,0),(0,0,255)], [image.getpixel((600, y)) for y in (400,1200,2000)]
                after = await call('browser_read', 'inspect', sid, selector='#top')
                assert abs(before.structured_content['elements'][0]['box']['y']-after.structured_content['elements'][0]['box']['y']) < 2
                passed('real 2400px full-page image has all three pixel bands and restores scroll')
                await write('navigate', sid, url='http://fixture/', ready_selector='#count')
                denied = await call('browser_write', 'click', sid, selector='#count')
                assert denied.is_error and 'approval' in str(denied.content)
                snapshot = await call('browser_read', 'snapshot', sid)
                assert 'saved=null' in snapshot.structured_content['snapshot']
                passed('unapproved fixture mutation denied without changing localStorage')
                denied = await call('browser_write', 'navigate', sid, url='http://127.0.0.1/')
                assert denied.is_error
                denied = await call('browser_write', 'navigate', sid, url='http://fixture/redirect-private')
                assert denied.is_error
                passed('live private-address and metadata redirect navigation denied')
                await write('navigate', sid, url='http://fixture/', ready_selector='#spa')
                task = await write('execute_steps', sid, description='Disposable crash recovery verification', steps=[
                    {'action': 'wait', 'params': {'milliseconds': 5000}} for _ in range(10)])
                report['task_id'] = task['task_id']
                # No live task or browser context may be claimed restored after SIGKILL.
                subprocess.run(['docker', 'kill', '--signal', 'KILL', 'daoos-browser-browser-1'], check=True, stdout=subprocess.DEVNULL)
                subprocess.run(['docker', 'start', 'daoos-browser-browser-1'], check=True, stdout=subprocess.DEVNULL)
                async with httpx.AsyncClient(timeout=5) as rest:
                    for _ in range(60):
                        try:
                            response = await rest.get(args.base+'/ready', headers={'Authorization': 'Bearer '+key})
                            if response.status_code == 200: break
                        except httpx.HTTPError: pass
                        await asyncio.sleep(1)
                    else: raise AssertionError('Browser did not become ready after crash')
                result = await call('browser_read', 'task_result', task_id=task['task_id'])
                assert not result.is_error and result.structured_content['status'] == 'failed', result.content
                sessions = await call('browser_read', 'sessions')
                saved = next(x for x in sessions.structured_content['sessions'] if x['id'] == sid)
                assert saved['status'] == 'lost', saved
                denied = await call('browser_read', 'snapshot', sid)
                assert denied.is_error
                passed('SIGKILL preserves task/session records; task failed, session lost, no fake restoration')
                replacement = await write('create_session')
                result = await write('close_session', replacement['session_id'], save_profile=False)
                assert result['closed']
                passed('same MCP client reconnects after server crash and creates/closes a fresh browser')
            finally:
                if sid:
                    try:
                        await call('browser_write', 'close_session', sid, save_profile=False)
                    except Exception:
                        pass



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='https://oknakomfort72.ru/browser')
    parser.add_argument('--key-file', type=Path, required=True)
    parser.add_argument('--report-dir', type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
