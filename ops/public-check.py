"""Exercise the deployed HTTPS gateway without changing CRM business data.

Run outside the Browser memory cgroup; pass a protected operator key file.
OAuth secrets, cookies and codes stay in process memory and never enter reports.
"""
import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import struct
from urllib.parse import parse_qs, urlsplit
import uuid

import httpx
import httpx2
import websockets
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


async def check(base, key_file, directory):
    key = key_file.read_text().strip()
    assert key_file.stat().st_mode & 0o077 == 0, 'key file must be owner-only'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    report = {'base': base, 'checks': []}
    def passed(message):
        report['checks'].append(message)
        (directory/'public-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
        print('PASS: '+message, flush=True)
    origin = '{0.scheme}://{0.netloc}'.format(urlsplit(base))
    async with httpx.AsyncClient(timeout=120, follow_redirects=False) as rest:
        assert (await rest.get(base+'/health')).status_code == 200
        assert (await rest.get(base+'/mcp')).status_code == 401
        assert (await rest.get(base+'/novnc/core/rfb.js')).status_code == 401
        metadata = (await rest.get(origin+'/.well-known/oauth-authorization-server/browser')).json()
        assert metadata['issuer'] == base
        resource = (await rest.get(origin+'/.well-known/oauth-protected-resource/browser/mcp')).json()
        assert resource['resource'] == base+'/mcp'
        passed('HTTPS routing, discovery, unauthenticated MCP and noVNC denied')
        callback = 'https://chatgpt.com/connector_platform_oauth_redirect'
        registration = await rest.post(base+'/oauth/register', json={'redirect_uris': [callback], 'token_endpoint_auth_method': 'none'})
        assert registration.status_code == 201
        client_id = registration.json()['client_id']
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        state = secrets.token_urlsafe(24)
        response = await rest.get(base+'/oauth/authorize', params={'client_id': client_id, 'redirect_uri': callback,
            'response_type': 'code', 'code_challenge_method': 'S256', 'code_challenge': challenge,
            'resource': base+'/mcp', 'scope': 'read write', 'state': state})
        assert response.status_code == 200
        intent = re.search(r'name="intent" value="([^"]+)"', response.text).group(1)
        response = await rest.post(base+'/oauth/consent', data={'intent': intent, 'api_key': key}, headers={'Origin': origin})
        assert response.status_code == 303
        query = parse_qs(urlsplit(response.headers['location']).query)
        assert query['state'] == [state] and query['iss'] == [base]
        grant = {'grant_type': 'authorization_code', 'code': query['code'][0], 'code_verifier': verifier,
            'client_id': client_id, 'redirect_uri': callback, 'resource': base+'/mcp'}
        response = await rest.post(base+'/oauth/token', data=grant)
        assert response.status_code == 200
        access = response.json()['access_token']
        assert (await rest.post(base+'/oauth/token', data=grant)).status_code == 400
        passed('live HTTPS OAuth S256, consent, token exchange and code replay denial')
        response = await rest.post(base+'/operator/login', data={'api_key': key}, headers={'Origin': origin})
        assert response.status_code == 200
        cookie = rest.cookies.get('browser_operator')
        assert 'Secure' in response.headers['set-cookie'] and 'HttpOnly' in response.headers['set-cookie']
        assert 'Path=/browser' in response.headers['set-cookie']
        assert (await rest.get(base+'/mcp')).status_code == 401
        passed('HTTPS operator cookie path/flags and MCP cookie-credential denial')
        sid = None
        try:
            async with httpx2.AsyncClient(headers={'Authorization': 'Bearer '+access}, timeout=120) as transport:
                async with Client(streamable_http_client(base+'/mcp', http_client=transport), read_timeout_seconds=120) as client:
                    async def write(action, **params):
                        result = await client.call_tool('browser_write', {'action': action, 'session_id': sid, 'params': params, 'request_id': uuid.uuid4().hex})
                        assert not result.is_error, result.content
                        return result.structured_content
                    async def read(action, **params):
                        result = await client.call_tool('browser_read', {'action': action, 'session_id': sid, 'params': params})
                        assert not result.is_error, result.content
                        return result
                    tools = await client.list_tools()
                    assert {t.name for t in tools.tools} == {'browser_read', 'browser_write'}
                    (directory/'tools.json').write_text(json.dumps([t.model_dump(mode='json') for t in tools.tools], indent=2))
                    created = await write('create_session')
                    sid = created['session_id']
                    report['session_id'] = sid
                    await write('navigate', url='https://oknakomfort72.ru/crm/', ready_selector='body')
                    snapshot = (await read('snapshot')).structured_content
                    report['crm_title'] = snapshot['title']
                    report['crm_requires_login'] = 'Требуется вход' in snapshot['snapshot']
                    shot = await read('screenshot')
                    image = next(x for x in shot.content if x.type == 'image')
                    png = base64.b64decode(image.data)
                    assert png.startswith(b'\x89PNG') and struct.unpack('!II', png[16:24]) == (1280, 800)
                    (directory/'public-crm.png').write_bytes(png)
                    passed('OAuth bearer discovers both tools, opens real CRM and receives MCP PNG')
                    assert (await rest.get(base+'/operator/'+sid)).status_code == 200
                    assert (await rest.get(base+'/novnc/core/rfb.js')).status_code == 200
                    assert (await rest.post(base+'/api/sessions/'+sid+'/control', json={'mode': 'manual'}, headers={'Origin': origin})).status_code == 200
                    blocked = await client.call_tool('browser_write', {'action': 'scroll', 'session_id': sid, 'params': {}, 'request_id': uuid.uuid4().hex})
                    assert blocked.is_error
                    async with websockets.connect(base.replace('https:', 'wss:')+'/api/vnc/'+sid,
                            origin=origin, additional_headers={'Cookie': 'browser_operator='+cookie}) as ws:
                        buffer = bytearray()
                        async def exact(n):
                            while len(buffer) < n: buffer.extend(await asyncio.wait_for(ws.recv(), 15))
                            result = bytes(buffer[:n]); del buffer[:n]; return result
                        assert (await exact(12)).startswith(b'RFB ')
                        await ws.send(b'RFB 003.008\n')
                        n = (await exact(1))[0]; assert 1 in await exact(n)
                        await ws.send(b'\x01'); assert await exact(4) == b'\x00'*4
                        await ws.send(b'\x01')
                        init = await exact(24); await exact(struct.unpack('!I', init[20:24])[0])
                        assert struct.unpack('!HH', init[:4]) == (1280, 800)
                        # Safe manual focus traversal only; never submit CRM forms.
                        await ws.send(struct.pack('!BBHI', 4, 1, 0, 0xff09)+struct.pack('!BBHI', 4, 0, 0, 0xff09))
                        await asyncio.sleep(.3)
                    assert (await rest.post(base+'/api/sessions/'+sid+'/control', json={'mode': 'agent'}, headers={'Origin': origin})).status_code == 200
                    await write('scroll', y=0)
                    passed('public protected noVNC assets, WSS RFB, manual Tab, agent lock and resume')
                    await write('close_session', save_profile=False)
                    sid = None
                    passed('final browser closed without saving unauthenticated CRM profile')
        finally:
            if sid:
                await rest.post(base+'/api/sessions/'+sid+'/control', json={'mode': 'agent'}, headers={'Origin': origin})
                # Cleanup uses the server receipt; no CRM mutations are retried.
                async with httpx2.AsyncClient(headers={'Authorization': 'Bearer '+key}, timeout=120) as transport:
                    async with Client(streamable_http_client(base+'/mcp', http_client=transport), read_timeout_seconds=120) as client:
                        await client.call_tool('browser_write', {'action': 'close_session', 'session_id': sid, 'params': {'save_profile': False}, 'request_id': uuid.uuid4().hex})
            await rest.post(base+'/oauth/revoke', data={'token': access})
            await rest.post(base+'/oauth/revoke', data={'token': cookie})
        assert (await rest.get(base+'/ready', headers={'Authorization': 'Bearer '+access})).status_code == 401
        passed('OAuth token revoked and rejected after verification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='https://oknakomfort72.ru/browser')
    parser.add_argument('--operator-key-file', type=Path, required=True)
    parser.add_argument('--report-dir', type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(check(args.base.rstrip('/'), args.operator_key_file, args.report_dir))
