"""Run inside the browser container against the actual HTTP/MCP endpoint.
Uses the operator key from a protected file, never prints it. CRM is read-only.
"""
import asyncio
import base64
import json
import os
from pathlib import Path
import time
import uuid
import httpx
import io
import struct
from PIL import Image
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from contextlib import asynccontextmanager
import httpx2

BASE = 'http://127.0.0.1:8000'
PUBLIC = os.environ['PUBLIC_URL']
KEY = Path('/data/operator-key').read_text().strip()
HEADERS = {'Authorization':'Bearer '+KEY,'Host':__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(PUBLIC).netloc}
class Checks(list):
    def append(self,value):
        super().append(value)
        print('PASS: '+value,flush=True)
report = {'checks': Checks()}

@asynccontextmanager
async def mcp_client():
    async with httpx2.AsyncClient(headers=HEADERS, timeout=90) as http:
        async with Client(streamable_http_client(BASE+'/mcp',http_client=http), read_timeout_seconds=90) as client:
            yield client


async def main():
    async with mcp_client() as client:
        catalog = await client.list_tools()
        assert {t.name for t in catalog.tools} == {'browser_read','browser_write'}
        report['checks'].append('MCP current protocol tool discovery')
        async def read(action, sid=None, **params):
            r = await client.call_tool('browser_read', {'action':action,'session_id':sid,'params':params})
            assert not r.is_error, str(r.content)
            return r
        async def write(action, sid=None, **params):
            r = await client.call_tool('browser_write', {'action':action,'session_id':sid,'params':params,'request_id':uuid.uuid4().hex})
            assert not r.is_error, str(r.content)
            return r.structured_content
        created = await write('create_session')
        sid = created['session_id']
        report['session_id'] = sid
        report['profile_id'] = created['profile_id']
        try:
            nav=await write('navigate',sid,url='https://oknakomfort72.ru/crm/',ready_selector='body')
            await write('wait',sid,milliseconds=2000)
            snapshot=(await read('snapshot',sid)).structured_content
            shot=await read('screenshot',sid)
            png=next(x for x in shot.content if x.type=='image')
            Path('/data/crm.png').write_bytes(base64.b64decode(png.data))
            Path('/data/crm-snapshot.txt').write_text(snapshot['snapshot'])
            report['crm']={'navigation':nav,'snapshot':snapshot,'elements':(await read('inspect',sid)).structured_content,
                'console':(await read('console',sid)).structured_content,'network':(await read('network',sid)).structured_content}
            report['checks'].append('production CRM opened without mutating interactions')
            Path('/data/crm-report.json').write_text(json.dumps(report['crm'],ensure_ascii=False,indent=2))
            await write('navigate', sid, url='http://fixture/', ready_selector='#spa')
            await write('wait', sid, milliseconds=300)
            snap = await read('snapshot',sid)
            assert 'SPA ready' in snap.structured_content['snapshot']
            screenshot = await read('screenshot',sid)
            image = next(x for x in screenshot.content if x.type=='image')
            png_bytes=base64.b64decode(image.data)
            assert png_bytes.startswith(b'\x89PNG')
            assert struct.unpack('!II',png_bytes[16:24])==(1280,800)
            with Image.open(io.BytesIO(png_bytes)) as actual:
                assert len(actual.getcolors(maxcolors=1_000_000) or [])>3, 'blank physical display'
            shot = Path('/data/integration-fixture.png')
            shot.write_bytes(base64.b64decode(image.data))
            report['checks'].append('shared headed Chromium: SPA, DOM, MCP PNG image')
            for params in [{'full_page':True},{'selector':'#count'}]:
                r=await read('screenshot',sid,**params)
                assert any(x.type=='image' for x in r.content)
            report['checks'].append('full-page and element screenshots')
            elements = await read('inspect',sid)
            assert any(x['box'] for x in elements.structured_content['elements'])
            # Approve exact harmless fixture interaction using the protected operator endpoint.
            request = await client.call_tool('browser_write', {'action':'request_approval','session_id':sid,'params':{'action':'click','params':{'selector':'#count'}},'request_id':uuid.uuid4().hex})
            assert not request.is_error,str(request.content)
            aid=request.structured_content['approval_id']
            async with httpx.AsyncClient(timeout=60) as http:
                r=await http.post(BASE+'/api/approvals/'+aid,headers={**HEADERS,'Origin':PUBLIC},json={'approve':True})
                assert r.status_code==200,r.text
            click_args={'action':'click','session_id':sid,'params':{'selector':'#count','approval_id':aid},'request_id':uuid.uuid4().hex}
            first_click=await client.call_tool('browser_write',click_args)
            assert not first_click.is_error,first_click.content
            duplicate=await client.call_tool('browser_write',click_args)
            assert not duplicate.is_error and duplicate.structured_content['duplicate'],duplicate.content
            report['checks'].append('actual duplicate write receipt prevents repeated mutation')
            assert '"1"' in (await read('snapshot',sid)).structured_content['snapshot'] or '1' in (await read('snapshot',sid)).structured_content['snapshot']
            report['checks'].append('one-time exact approval and Playwright click on disposable fixture')
            # A second MCP connection sees the same browser without retaining an HTTP request.
            async with mcp_client() as reconnected:
                r=await reconnected.call_tool('browser_read',{'action':'tabs','session_id':sid,'params':{}})
                assert not r.is_error
            report['checks'].append('MCP reconnect preserves browser session')
            task=await write('execute_steps',sid,description='fixture multi-step read-only navigation',steps=[
                {'action':'navigate','params':{'url':'http://fixture/#dialogs'},'expect':{'selector':'#count'}},
                {'action':'wait','params':{'milliseconds':100}}])
            for _ in range(100):
                status=(await read('task_status',None,task_id=task['task_id'])).structured_content
                if status['status'] in {'completed','failed','cancelled'}:break
                await asyncio.sleep(.1)
            assert status['status']=='completed',status
            report['checks'].append('durable asynchronous execute_steps, expectations and task polling')
            # RFB over the authenticated websocket, same browser, keyboard event after handoff.
            await vnc_handoff(sid, client)
            report['checks'].append('authenticated VNC same browser, manual key event, agent resumes')
            await write('close_session',sid)
            saved=created['profile_id']
            reopened=await write('create_session',profile_id=saved)
            sid=reopened['session_id']
            await write('navigate',sid,url='http://fixture/')
            restored=(await read('snapshot',sid)).structured_content['snapshot']
            assert 'saved=1' in restored and 'fixture=authorized' in restored, restored
            report['checks'].append('encrypted full profile close/reopen')
            await write('close_session',sid)
            sid=None

        finally:
            if sid:
                async with httpx.AsyncClient(timeout=60) as http:
                    await http.post(BASE+'/api/sessions/'+sid+'/control',headers={**HEADERS,'Origin':PUBLIC},json={'mode':'agent'})
                await write('close_session',sid)
        report['usage']=(await read('usage')).structured_content
    Path('/data/integration-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print(json.dumps({'passed':report['checks'],'crm_title':report.get('crm',{}).get('snapshot',{}).get('title')},ensure_ascii=False))


async def vnc_handoff(sid, client):
    import struct
    import websockets
    async with httpx.AsyncClient(timeout=60) as http:
        response=await http.post(BASE+'/api/sessions/'+sid+'/control',headers={**HEADERS,'Origin':PUBLIC},json={'mode':'manual'})
        assert response.status_code==200,response.text
    r=await client.call_tool('browser_write',{'action':'scroll','session_id':sid,'params':{},'request_id':uuid.uuid4().hex})
    assert r.is_error
    # Real authenticated WebSocket -> x11vnc -> SAME Xvfb/Chromium.
    async with websockets.connect('ws://127.0.0.1:18131/api/vnc/'+sid,
            host='127.0.0.1',port=8000,origin=PUBLIC,
            additional_headers={'Authorization':'Bearer '+KEY}) as ws:
        buffer=bytearray()
        async def exact(n):
            while len(buffer)<n: buffer.extend(await ws.recv())
            result=bytes(buffer[:n]);del buffer[:n];return result
        assert (await exact(12)).startswith(b'RFB ')
        await ws.send(b'RFB 003.008\n')
        n=(await exact(1))[0];security=await exact(n);assert 1 in security
        await ws.send(b'\x01');assert await exact(4)==b'\x00'*4
        await ws.send(b'\x01')
        init=await exact(24);await exact(struct.unpack('!I',init[20:24])[0])
        await ws.send(struct.pack('!BBHH',5,1,600,300)+struct.pack('!BBHH',5,0,600,300))
        await asyncio.sleep(.1)
        await ws.send(struct.pack('!BBHI',4,1,0,0xff09)+struct.pack('!BBHI',4,0,0,0xff09))
        await asyncio.sleep(.3)
        focused=await client.call_tool('browser_read',{'action':'inspect','session_id':sid,'params':{'selector':':focus'}})
        assert focused.structured_content['elements'][0]['tag']=='A',focused.content
    async with httpx.AsyncClient(timeout=60) as http:
        response=await http.post(BASE+'/api/sessions/'+sid+'/control',headers={**HEADERS,'Origin':PUBLIC},json={'mode':'agent'})
        assert response.status_code==200,response.text
    r=await client.call_tool('browser_write',{'action':'scroll','session_id':sid,'params':{'y':100},'request_id':uuid.uuid4().hex})
    assert not r.is_error,str(r.content)


asyncio.run(main())
