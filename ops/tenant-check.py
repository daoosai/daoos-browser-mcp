"""Live isolation check from outside the Browser's constrained memory cgroup.

Requires a protected JSON fixture containing a temporary tenant key and the
original owner's profile_id/session_id/task_id/screenshot_id. Never prints keys.
Use only with the disposable fixture and its temporary /32 egress exception.
"""
import argparse
import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import uuid
import httpx
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


@asynccontextmanager
async def connection(base, key):
    async with httpx2.AsyncClient(headers={'Authorization': 'Bearer '+key}, timeout=150) as transport:
        async with Client(streamable_http_client(base+'/mcp', http_client=transport), read_timeout_seconds=150) as client:
            yield client


async def main(args):
    assert args.tenant_file.stat().st_mode & 0o077 == 0
    config = json.loads(args.tenant_file.read_text())
    owner = args.operator_key_file.read_text().strip()
    checks = []
    def passed(value):
        checks.append(value)
        args.report_file.write_text(json.dumps({'passed': checks}, indent=2))
        print('PASS: '+value, flush=True)
    async def write(client, action, sid=None, **params):
        return await client.call_tool('browser_write', {'action': action, 'session_id': sid, 'params': params, 'request_id': uuid.uuid4().hex})
    async def snapshot(client, sid):
        result = await client.call_tool('browser_read', {'action': 'snapshot', 'session_id': sid, 'params': {}})
        assert not result.is_error, result.content
        return result.structured_content['snapshot']
    async def use_browser(client, profile=None):
        result = await write(client, 'create_session', **({'profile_id': profile} if profile else {}))
        assert not result.is_error, result.content
        sid = result.structured_content['session_id']
        try:
            result = await write(client, 'navigate', sid, url='http://fixture/', ready_selector='#spa')
            assert not result.is_error, result.content
            return await snapshot(client, sid)
        finally:
            result = await write(client, 'close_session', sid, save_profile=False)
            assert not result.is_error, result.content
    try:
        async with connection(args.base, owner) as client:
            state = await use_browser(client, config['profile_id'])
            assert 'saved=1' in state and 'fixture=authorized' in state, 'owner test profile missing saved state'
            passed('original owner encrypted profile restores its fixture cookie and localStorage')
        async with connection(args.base, config['key']) as client:
            sessions = await client.call_tool('browser_read', {'action': 'sessions', 'params': {}})
            assert sessions.structured_content['sessions'] == []
            denied = await client.call_tool('browser_read', {'action': 'snapshot', 'session_id': config['session_id'], 'params': {}})
            assert denied.is_error
            assert (await write(client, 'create_session', profile_id=config['profile_id'])).is_error
            denied = await client.call_tool('browser_read', {'action': 'task_result', 'params': {'task_id': config['task_id']}})
            assert denied.is_error
            async with httpx.AsyncClient(headers={'Authorization': 'Bearer '+config['key']}) as http:
                assert (await http.get(args.base+'/api/files/'+config['screenshot_id'])).status_code == 403
            passed('second tenant cannot read owner session/task/image or reopen owner profile')
            state = await use_browser(client)
            assert 'saved=null cookie=' in state and 'fixture=authorized' not in state, 'cross-tenant browser state leak'
            passed('second tenant browser has no original cookie or localStorage')
    finally:
        async with httpx.AsyncClient() as http:
            await http.post(args.base+'/oauth/revoke', data={'token': config['key']})
    async with httpx.AsyncClient(headers={'Authorization': 'Bearer '+config['key']}) as http:
        assert (await http.get(args.base+'/ready')).status_code == 401
    passed('temporary tenant key revoked and denied')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='https://oknakomfort72.ru/browser')
    parser.add_argument('--operator-key-file', type=Path, required=True)
    parser.add_argument('--tenant-file', type=Path, required=True)
    parser.add_argument('--report-file', type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
