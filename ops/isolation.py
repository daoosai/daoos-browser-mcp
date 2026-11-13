"""Real HTTP/MCP tenant isolation checks. Run inside the Browser container."""
import asyncio,json,os,uuid
from pathlib import Path
from urllib.parse import urlsplit
import httpx,httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from browser.store import Store,Principal

async def main():
    store=Store(os.environ['DATABASE_URL'])
    owner=store.authenticate(Path('/data/operator-key').read_text().strip())
    report=json.loads(Path('/data/integration-report.json').read_text())
    saved_profile=report['profile_id']
    suffix=uuid.uuid4().hex[:8]
    other=Principal('isolation_'+suffix,'test_org_'+suffix,'provisioner',frozenset({'read','write'}))
    store.put('organizations',other.org,other,{'test_only':True})
    store.put('users',other.user,other,{'test_only':True})
    raw=store.issue_key(other,other.scopes)
    headers={'Host':urlsplit(os.environ['PUBLIC_URL']).netloc,'Authorization':'Bearer '+raw}
    checks=[]
    try:
        async with httpx2.AsyncClient(headers=headers,timeout=120) as http:
            async with Client(streamable_http_client('http://127.0.0.1:8000/mcp',http_client=http),read_timeout_seconds=120) as client:
                async def read(action,sid=None,**params):
                    return await client.call_tool('browser_read',{'action':action,'session_id':sid,'params':params})
                async def write(action,sid=None,**params):
                    return await client.call_tool('browser_write',{'action':action,'session_id':sid,'params':params,'request_id':uuid.uuid4().hex})
                assert (await read('sessions')).structured_content['sessions']==[]
                assert (await read('snapshot',report['session_id'])).is_error
                assert (await write('create_session',profile_id=saved_profile)).is_error
                tasks=store.list('tasks',owner)
                if tasks: assert (await read('task_result',task_id=tasks[0]['id'])).is_error
                shots=[a for a in store.list('actions',owner) if a.get('kind')=='screenshot']
                assert shots
                async with httpx.AsyncClient(headers=headers,timeout=30) as rest:
                    denied=await rest.get('http://127.0.0.1:8000/api/files/'+shots[0]['id'])
                    assert denied.status_code==403 and not denied.content.startswith(b'\x89PNG')
                checks.append('foreign session, profile, task and screenshot denied over real API')
                result=await write('create_session')
                assert not result.is_error,result.content
                sid=result.structured_content['session_id']
                try:
                    result=await write('navigate',sid,url='http://fixture/')
                    assert not result.is_error,result.content
                    state=(await read('snapshot',sid)).structured_content['snapshot']
                    assert 'saved=null cookie=' in state and 'fixture=authorized' not in state,state
                    checks.append('new tenant has neither original cookies nor localStorage')
                finally:
                    result=await write('close_session',sid,save_profile=False)
                    assert not result.is_error,result.content
    finally:
        # Revoke even if a browser launch or assertion fails.
        p=store.authenticate(raw)
        store.patch('api_keys',p.key,p,{'revoked':True})
    Path('/data/isolation-report.json').write_text(json.dumps({'passed':checks},indent=2))
    print(json.dumps({'passed':checks}))

asyncio.run(main())
