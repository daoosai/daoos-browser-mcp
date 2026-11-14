"""Small OAuth 2.1 authorization-code bridge to individually provisioned API keys.
Exact configured redirect URIs, S256, issuer and resource binding, hashed opaque
credentials, single-use codes, short-lived tokens; no remote metadata fetches.
"""
import base64
import hashlib
from html import escape
import secrets
import time
from urllib.parse import urlencode
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from .store import Principal, Denied, uid, digest


def pkce(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip("=")


def install_oauth(app, config, store):
    issuer = config.public_url.rstrip("/")
    system = Principal("oauth", "system", "", frozenset())

    def lookup(kind, id):
        t = store.tables[kind]
        with store.engine.connect() as c:
            row = c.execute(select(t).where(t.c.id == id)).mappings().first()
        if not row: raise HTTPException(400, "invalid_oauth_request")
        return row

    @app.get("/.well-known/oauth-protected-resource")
    @app.get("/.well-known/oauth-protected-resource/mcp")
    async def resource():
        return {"resource": issuer+"/mcp", "authorization_servers": [issuer], "scopes_supported": ["read", "write"], "bearer_methods_supported": ["header"]}

    @app.get("/.well-known/oauth-authorization-server")
    async def metadata():
        return {"issuer": issuer, "authorization_endpoint": issuer+"/oauth/authorize", "token_endpoint": issuer+"/oauth/token",
            "registration_endpoint": issuer+"/oauth/register", "revocation_endpoint": issuer+"/oauth/revoke",
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": ["none"], "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True, "scopes_supported": ["read", "write"]}

    @app.post("/oauth/register")
    async def register(request: Request):
        data = await request.json()
        uris = data.get("redirect_uris", [])
        if not uris or len(uris) > 5 or any(u not in config.redirect_uris for u in uris):
            raise HTTPException(400, "redirect_uri_not_preconfigured")
        if data.get("token_endpoint_auth_method", "none") != "none":
            raise HTTPException(400, "only_public_clients_with_pkce")
        client_id = uid("client")
        store.put("oauth", client_id, system, {"redirect_uris": uris})
        return JSONResponse({"client_id": client_id, "redirect_uris": uris, "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"], "response_types": ["code"]}, status_code=201)

    @app.get("/oauth/authorize")
    async def authorize(request: Request):
        q = dict(request.query_params)
        client = store.get("oauth", q.get("client_id", ""), system)
        if (q.get("redirect_uri") not in client["redirect_uris"] or q.get("response_type") != "code"
            or q.get("code_challenge_method") != "S256" or len(q.get("code_challenge", "")) != 43
            or q.get("resource") != issuer+"/mcp" or not q.get("state") or len(q["state"]) > 2000):
            raise HTTPException(400, "invalid_authorization_request")
        scopes = set(q.get("scope", "read").split())
        if not scopes or not scopes <= {"read", "write"}: raise HTTPException(400, "invalid_scope")
        intent = secrets.token_urlsafe(32)
        store.put("oauth", digest(intent), system, {**q, "scope": sorted(scopes), "expires": time.time()+300, "status": "pending"})
        body = f'''<!doctype html><html lang="ru"><meta charset="utf-8"><title>DAOOS Browser — разрешение</title>
        <h1>Подключение DAOOS Browser</h1><p>Клиент: {escape(q['client_id'])}</p>
        <p>Права: {escape(' '.join(sorted(scopes)))}</p><p>Возврат: {escape(q['redirect_uri'])}</p>
        <p>Введите отдельный ключ DAOOS Browser. Пароли сайтов вводятся только через VNC.</p>
        <form method="post" action="{issuer}/oauth/consent"><input type="hidden" name="intent" value="{intent}">
        <input name="api_key" type="password" required autocomplete="off"><button>Разрешить подключение</button></form></html>'''
        response = HTMLResponse(body)
        response.set_cookie("oauth_intent", intent, httponly=True, secure=config.secure_cookies, samesite="lax", max_age=300)
        return response

    @app.post("/oauth/consent")
    async def consent(request: Request):
        form = await request.form()
        intent = form.get("intent", "")
        if not secrets.compare_digest(request.cookies.get("oauth_intent", ""), intent): raise HTTPException(403, "csrf_denied")
        p = store.authenticate(form.get("api_key", ""))
        with store.engine.begin() as c:
            saved = store.get("oauth", digest(intent), system, conn=c, lock=True)
            if saved["status"] != "pending" or saved["expires"] < time.time(): raise HTTPException(400, "authorization_expired")
            if not set(saved["scope"]) <= p.scopes: raise HTTPException(403, "scope_denied")
            store.patch("oauth", saved["id"], system, {"status": "consumed"}, conn=c)
            code = secrets.token_urlsafe(32)
            store.put("oauth", digest(code), p, {**saved, "status": "code", "parent_key": p.key, "expires": time.time()+60}, conn=c)
        uri = saved["redirect_uri"] + ("&" if "?" in saved["redirect_uri"] else "?") + urlencode({"code": code, "state": saved["state"], "iss": issuer})
        response = RedirectResponse(uri, status_code=303)
        response.delete_cookie("oauth_intent")
        return response

    @app.post("/oauth/token")
    async def token(request: Request):
        form = await request.form()
        if form.get("grant_type") != "authorization_code": raise HTTPException(400, "unsupported_grant_type")
        row = lookup("oauth", digest(form.get("code", "")))
        p = Principal(row["user"], row["org"], "", frozenset())
        with store.engine.begin() as c:
            saved = store.get("oauth", row["id"], p, conn=c, lock=True)
            if (saved.get("status") != "code" or saved["expires"] < time.time()
                or form.get("client_id") != saved["client_id"] or form.get("redirect_uri") != saved["redirect_uri"]
                or form.get("resource") != issuer+"/mcp" or not 43 <= len(form.get("code_verifier", "")) <= 128
                or not secrets.compare_digest(pkce(form.get("code_verifier", "")), saved["code_challenge"])):
                raise HTTPException(400, "invalid_grant")
            parent = store.get("api_keys", saved["parent_key"], p, conn=c)
            if parent["revoked"] or parent.get("expires", time.time()+1) <= time.time(): raise HTTPException(400, "invalid_grant")
            store.patch("oauth", row["id"], p, {"status": "consumed"}, conn=c)
            raw = "dbo_" + secrets.token_urlsafe(32)
            store.put("api_keys", digest(raw), p, {"scopes": saved["scope"], "revoked": False,
                "expires": time.time()+3600, "parent_key": saved["parent_key"], "client_id": saved["client_id"]}, conn=c)
        return {"access_token": raw, "token_type": "Bearer", "expires_in": 3600, "scope": " ".join(saved["scope"])}

    @app.post("/oauth/revoke")
    async def revoke(request: Request):
        form = await request.form()
        try:
            p = store.authenticate(form.get("token", ""))
            store.patch("api_keys", p.key, p, {"revoked": True})
        except Denied: pass
        return {}
