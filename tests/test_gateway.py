import asyncio
from contextlib import asynccontextmanager
import json
import time
from types import SimpleNamespace
from fastapi.testclient import TestClient
import pytest
from browser.app import create_app
from browser.engine import Engine
from browser.oauth import pkce
from browser.store import Denied


class FakeEngine:
    def __init__(self): self.pw = True
    async def start(self): pass
    async def stop(self): pass
    async def read(self, p, action, sid=None, params=None):
        p.require("read")
        if action == "screenshot":
            return {"image": "aGVsbG8=", "artifact_id": "fake", "viewport": {"width": 1280, "height": 800}}
        return {"ready": True}
    async def write(self, p, *args):
        p.require("write")
        return {"success": True}


@pytest.fixture
def client(setup):
    c, store, p, raw = setup
    app = create_app(c, store, FakeEngine())
    with TestClient(app, base_url=c.public_url) as client:
        yield client


def test_api_auth_and_origin(client, setup):
    c, store, p, raw = setup
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 401
    auth = {"Authorization": "Bearer "+raw}
    assert client.get("/ready", headers=auth).status_code == 200
    assert client.get("/ready", headers={**auth, "Origin": "https://evil.test"}).status_code == 403
    assert client.get("/ready", headers={**auth, "Host": "evil.test"}).status_code == 400
    assert client.get("/api/files/../../etc/passwd", headers=auth).status_code != 200


def test_operator_login_origin(client, setup):
    c, store, p, raw = setup
    page = client.get("/operator/login")
    assert page.headers["referrer-policy"] == "same-origin"
    for origin in ("null", "https://evil.test", "https://chatgpt.com"):
        denied = client.post("/operator/login", data={"api_key": raw}, headers={"Origin": origin})
        assert denied.status_code == 403
        assert "browser_operator" not in denied.cookies
    assert client.post("/operator/login", data={"api_key": raw}).status_code == 403
    response = client.post("/operator/login", data={"api_key": raw}, headers={"Origin": c.origin})
    assert response.status_code == 200
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=strict" in response.headers["set-cookie"]
    assert client.post("/mcp", json={}).status_code == 401


def test_operator_html_login_and_scopes(client, setup):
    c, store, p, raw = setup
    headers = {"Origin": c.origin, "Accept": "text/html"}
    for wrong in ("crmPasswordShouldNotBeReflected", "dbk_invalid_test_key"):
        response = client.post('/operator/login', data={'api_key': wrong}, headers=headers)
        assert response.status_code == 403 and 'role="alert"' in response.text
        assert wrong not in response.text
    limited = store.issue_key(p, {'read', 'write'})
    assert client.post('/operator/login', data={'api_key': limited}, headers=headers).status_code == 403
    store.put('sessions', 'session_owned', p, {'status': 'active'})
    response = client.post('/operator/login', data={'api_key': '\n '+raw+' \n'}, headers=headers, follow_redirects=False)
    assert response.status_code == 303 and response.headers['location'] == c.public_url+'/operator'
    assert 'HttpOnly' in response.headers['set-cookie']
    page = client.get('/operator', headers={'Accept': 'text/html'})
    assert page.status_code == 200 and '/operator/session_owned' in page.text


def test_operator_browser_requires_login_but_mcp_stays_401(client):
    response = client.get('/operator/old_session', headers={'Accept': 'text/html'}, follow_redirects=False)
    assert response.status_code == 303 and response.headers['location'].endswith('/operator/login')
    assert client.get('/operator/old_session').status_code == 401
    assert client.get('/mcp', headers={'Accept': 'text/html'}).status_code == 401


def test_oauth_pkce_resource_and_single_use(client, setup):
    c, store, p, raw = setup
    uri = c.redirect_uris[0]
    registration = client.post("/oauth/register", json={"redirect_uris": [uri]}).json()
    cid = registration["client_id"]
    verifier = "x"*43
    query = dict(client_id=cid, redirect_uri=uri, response_type="code", code_challenge_method="S256",
        code_challenge=pkce(verifier), state="state", resource=c.public_url+"/mcp", scope="read write")
    assert client.get("/oauth/authorize", params={**query, "resource": "https://evil.test"}).status_code == 400
    response = client.get("/oauth/authorize", params=query)
    assert response.status_code == 200
    intent = client.cookies["oauth_intent"]
    assert client.post("/oauth/consent", data={"intent": "wrong", "api_key": raw}).status_code == 403
    response = client.post("/oauth/consent", data={"intent": intent, "api_key": raw}, follow_redirects=False)
    assert response.status_code == 303
    from urllib.parse import parse_qs, urlsplit
    code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
    token_data = dict(grant_type="authorization_code", code=code, code_verifier=verifier, client_id=cid, redirect_uri=uri, resource=c.public_url+"/mcp")
    assert client.post("/oauth/token", data={**token_data, "code_verifier": "wrong"*10}).status_code == 400
    token = client.post("/oauth/token", data=token_data).json()["access_token"]
    assert store.authenticate(token).scopes == {"read", "write"}
    assert client.post("/oauth/token", data=token_data).status_code == 400
    assert client.post("/oauth/revoke", data={"token": token}).status_code == 200
    with pytest.raises(Denied): store.authenticate(token)
    assert client.post("/oauth/register", json={"redirect_uris": ["https://evil.test"]}).status_code == 400


def test_rate_limit(client):
    statuses = [client.get("/health").status_code for _ in range(241)]
    assert statuses[-1] == 429


async def test_dangerous_actions_idempotency_and_timeout(setup):
    c, store, p, raw = setup
    engine = Engine(c, store)
    page = SimpleNamespace(url="https://crm.example/", is_closed=lambda: False)
    from browser.engine import LiveSession
    s = LiveSession("s", p, "p", c.runtime)
    s.tabs["tab"] = page
    s.current = "tab"
    engine.live["s"] = s
    store.put("sessions", "s", p, {"status": "active"})
    result = await engine.write(p, "click", "s", {"selector": "#delete"}, "one")
    assert result["error"] == "approval_required_use_request_approval"
    duplicate = await engine.write(p, "click", "s", {"selector": "#delete"}, "one")
    assert duplicate["duplicate"]
    with pytest.raises(Denied): await engine.write(p, "click", "s", {"selector": "#pay"}, "one")
    s.control = "manual"
    result = await engine.write(p, "scroll", "s", {}, "two")
    assert result["error"] == "operator_has_control"
    s.control = "agent"
    c.operation_timeout = .01
    async def slow(*args): await asyncio.sleep(1)
    engine.perform = slow
    result = await engine.write(p, "scroll", "s", {}, "three")
    assert result["error"] == "operation_timeout"


async def test_exact_one_time_approval(setup):
    c, store, p, raw = setup
    from browser.engine import LiveSession
    engine = Engine(c, store)
    s = LiveSession("s", p, "p", c.runtime)
    s.tabs["tab"] = SimpleNamespace(url="https://crm.example/", is_closed=lambda: False)
    s.current = "tab"
    engine.live["s"] = s
    store.put("sessions", "s", p, {"status": "active"})
    params = {"selector": "#safe"}
    result = await engine.write(p, "request_approval", "s", {"action": "click", "params": params}, "request")
    aid = result["approval_id"]
    store.patch("approvals", aid, p, {"status": "approved"})
    engine.approved(s, p, "click", {**params, "approval_id": aid})
    with pytest.raises(Denied): engine.approved(s, p, "click", {**params, "approval_id": aid})

async def test_real_streamable_http_and_reconnect(setup):
    import socket
    import threading
    import uvicorn
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    c, store, p, raw = setup
    sock = socket.socket()
    sock.bind(('127.0.0.1',0))
    port = sock.getsockname()[1]
    c.public_url = f'http://127.0.0.1:{port}'
    app = create_app(c,store,FakeEngine())
    server = uvicorn.Server(uvicorn.Config(app,log_level='error',access_log=False))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]),daemon=True)
    thread.start()
    for _ in range(100):
        if server.started: break
        await asyncio.sleep(.05)
    assert server.started
    try:
        for _ in range(2):
            async with httpx2.AsyncClient(headers={'Authorization':'Bearer '+raw}) as http:
                async with Client(streamable_http_client(c.public_url+'/mcp',http_client=http)) as client:
                    catalog = await client.list_tools()
                    assert {t.name for t in catalog.tools} == {'browser_read','browser_write'}
                    r = await client.call_tool('browser_read',{'action':'screenshot','params':{},'session_id':'s'})
                    assert not r.is_error, r.content
                    assert any(x.type=='image' for x in r.content)
                    assert r.structured_content['viewport']['width'] == 1280
                    r = await client.call_tool('browser_read',{'action':'bad','params':{}})
                    assert r.is_error
    finally:
        server.should_exit = True
        await asyncio.to_thread(thread.join,5)


def test_websocket_authentication_and_handler(client,setup):
    from starlette.websockets import WebSocketDisconnect
    c,store,p,raw=setup
    with pytest.raises(WebSocketDisconnect) as closed:
        with client.websocket_connect('/api/vnc/s',headers={'Host':'127.0.0.1:18131','Origin':c.origin}): pass
    assert closed.value.code==4403
    client.app.state.engine.session=lambda sid,p: SimpleNamespace(vnc_port=65534,stopped=False)
    with pytest.raises(WebSocketDisconnect) as closed:
        with client.websocket_connect('/api/vnc/s',headers={'Host':'127.0.0.1:18131','Origin':c.origin,'Authorization':'Bearer '+raw}) as ws:
            ws.receive_bytes()
    assert closed.value.code==1013


def test_chunked_body_limit(client,setup):
    c,store,p,raw=setup
    def chunks():
        yield b'a'*(600*1024)
        yield b'a'*(600*1024)
    r=client.post('/oauth/register',content=chunks(),headers={'Content-Type':'application/json'})
    assert r.status_code==413


def test_authenticated_websocket_forwards_raw_key_input(client,setup):
    c,store,p,raw=setup
    async def start_tcp():
        async def handle(reader,writer):
            writer.write(b'hello');await writer.drain()
            message=await reader.readexactly(4)
            writer.write(b'ack:'+message);await writer.drain()
            writer.close()
        server=await asyncio.start_server(handle,'127.0.0.1',0)
        return server,server.sockets[0].getsockname()[1]
    server,port=client.portal.call(start_tcp)
    client.app.state.engine.session=lambda sid,p: SimpleNamespace(vnc_port=port,stopped=False,last_used=0)
    try:
        with client.websocket_connect('/api/vnc/s',headers={'Host':'127.0.0.1:18131','Origin':c.origin,'Authorization':'Bearer '+raw}) as ws:
            assert ws.receive_bytes()==b'hello'
            ws.send_bytes(b'ping')
            assert ws.receive_bytes()==b'ack:ping'
    finally:
        async def close():server.close();await server.wait_closed()
        client.portal.call(close)
