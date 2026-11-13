import asyncio
import json
import socket
import time
from unittest.mock import AsyncMock
import pytest
from browser.security import safe_url, public_ip, resolve_public, command_hash
from browser.store import Denied, Principal
from browser.commands import validate, methods
from browser.profiles import Vault


@pytest.mark.parametrize("url", ["file:///etc/passwd", "javascript:alert(1)", "ftp://example.org", "https://user:password@example.org", "http://example.org:5432", "http://example.org\\@127.0.0.1", "https://example.org/\r\nfoo"])
def test_url_denied(url):
    with pytest.raises(Denied): safe_url(url)


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.2", "172.16.1.1", "::1", "::ffff:127.0.0.1", "fe80::1", "224.0.0.1", "0.0.0.0"])
def test_private_network_denied(ip): assert not public_ip(ip)


async def test_rebinding_and_mixed_dns_denied(monkeypatch):
    loop = asyncio.get_running_loop()
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ["93.184.216.34", "127.0.0.1"]]
    monkeypatch.setattr(loop, "getaddrinfo", AsyncMock(return_value=addresses))
    with pytest.raises(Denied): await resolve_public("rebind.test", 443)
    monkeypatch.setattr(loop, "getaddrinfo", AsyncMock(return_value=addresses[:1]))
    assert await resolve_public("public.test", 443) == ["93.184.216.34"]


def test_explicit_internal_allowlist(monkeypatch):
    async def run():
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 443))]))
        assert await resolve_public("internal.test", 443, ["10.1.2.3/32"]) == ["10.1.2.3"]
    asyncio.run(run())


def test_commands_are_closed_schemas():
    assert "execute_js" not in methods()["browser_write"]
    with pytest.raises(ValueError): validate("evaluate", {}, True)
    with pytest.raises(ValueError): validate("navigate", {"url": "https://example.org", "shell": "ls"}, True)
    with pytest.raises(ValueError): validate("wait", {"milliseconds": 999999}, True)
    with pytest.raises(ValueError): validate("press_key", {"key": "Control+L"}, True)
    assert command_hash("fill", "s", {"selector": "input", "text": "a"}) != command_hash("fill", "s", {"selector": "input", "text": "b"})


def test_owner_isolation(setup):
    c, store, p, raw = setup
    store.put("sessions", "session_test", p, {"status": "active"})
    for other in [Principal("other", p.org, "x", p.scopes), Principal(p.user, "other", "x", p.scopes)]:
        assert store.list("sessions", other) == []
        with pytest.raises(Denied): store.get("sessions", "session_test", other)
        with pytest.raises(Denied): store.patch("sessions", "session_test", other, {})
        with pytest.raises(Denied): store.remove("sessions", "session_test", other)


def test_revocation_and_child_expiry(setup):
    c, store, p, raw = setup
    child = store.issue_key(p, {"read"})
    cp = store.authenticate(child)
    store.patch("api_keys", cp.key, p, {"parent_key": p.key, "expires": time.time()+60})
    assert store.authenticate(child).scopes == {"read"}
    store.patch("api_keys", p.key, p, {"revoked": True})
    with pytest.raises(Denied): store.authenticate(raw)
    with pytest.raises(Denied): store.authenticate(child)


def test_usage_dedup_and_quota_atomicity(setup):
    c, store, p, raw = setup
    store.patch("quotas", p.org+":"+p.user, p, {"limits": {"actions_count": 2}})
    store.charge("event", p, "actions_count")
    store.charge("event", p, "actions_count")
    store.charge("event2", p, "actions_count")
    with pytest.raises(Denied): store.charge("event3", p, "actions_count")
    assert store.get("quotas", p.org+":"+p.user, p)["totals"]["actions_count"] == 2
    assert len(store.list("usage", p)) == 2


def test_crash_recovery_is_honest(setup):
    c, store, p, raw = setup
    store.put("sessions", "s", p, {"status": "active"})
    store.put("tasks", "t", p, {"status": "running"})
    store.put("actions", "a", p, {"status": "running"})
    store.recover()
    assert store.get("sessions", "s", p)["status"] == "lost"
    assert store.get("tasks", "t", p)["status"] == "failed"
    assert store.get("actions", "a", p)["status"] == "uncertain"


async def test_startup_failure_survives_cleanup_failure(setup, monkeypatch):
    from browser.engine import Engine
    config, store, owner, raw = setup
    engine = Engine(config, store)
    def failed_restore(*args):
        raise TimeoutError("original startup failure")
    monkeypatch.setattr(engine.vault, "restore", failed_restore)
    monkeypatch.setattr(engine, "close", AsyncMock(side_effect=Denied("cleanup failure")))
    with pytest.raises(TimeoutError, match="original startup failure"):
        await engine.create(owner, {"profile_id": None, "width": 1280, "height": 800}, "startup-test")
    assert store.list("sessions", owner)[0]["status"] == "failed"


def test_profile_encryption_and_restore(setup, tmp_path):
    c, store, p, raw = setup
    v = Vault(c.data / "vault", c.profile_key)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "Cookies").write_text("secret-cookie")
    (runtime / "link").symlink_to("/etc/passwd")
    pid = "profile_" + "a"*32
    v.save(pid, runtime)
    assert b"secret-cookie" not in v.path(pid).read_bytes()
    restored = tmp_path / "restored"
    restored.mkdir()
    v.restore(pid, restored)
    assert (restored / "Cookies").read_text() == "secret-cookie"
    assert not (restored / "link").exists()
    with pytest.raises(Denied): v.path("../../etc/passwd")
    v.delete(pid)
    assert not v.path(pid).exists()


def test_oauth_child_cannot_bypass_key_quota_or_scope(setup):
    c, store, p, raw = setup
    store.patch('api_keys',p.key,p,{'limits':{'actions_count':1}})
    raw_child = store.issue_key(p,{'read'})
    child = store.authenticate(raw_child)
    store.patch('api_keys',child.key,p,{'parent_key':p.key})
    store.charge('child1',child,'actions_count')
    with pytest.raises(Denied): store.charge('child2',child,'actions_count')
    assert store.get('api_keys',p.key,p)['totals']['actions_count']==1
    store.patch('api_keys',p.key,p,{'scopes':[]})
    with pytest.raises(Denied): store.authenticate(raw_child)
    with pytest.raises(Denied): store.validate_principal(child)


def test_default_provisioning_does_not_grant_operator(setup,tmp_path):
    import os,subprocess,sys
    c,store,p,raw=setup
    output=tmp_path/'key'
    r=subprocess.run([sys.executable,'-m','browser.cli','provision','--user','newowner','--org','neworg','--key-output',str(output)],
        env={**os.environ,'DATABASE_URL':c.database_url},capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    principal=store.authenticate(output.read_text().strip())
    assert principal.scopes=={'read','write'}


def test_window_manager_cannot_launch_host_programs():
    from pathlib import Path
    import xml.etree.ElementTree as ET
    root=ET.parse(Path(__file__).parents[1]/'browser/openbox.xml').getroot()
    ns={'o':'http://openbox.org/3.4/rc'}
    assert all(a.attrib.get('name') in {'Focus','Raise'} for a in root.findall('.//o:action',ns))
    assert not root.findall('.//o:command',ns)
    assert not root.findall('.//o:keybind',ns)


def test_exhausted_browser_time_denies_zero_cost_admission(setup):
    c,store,p,raw=setup
    store.patch('api_keys',p.key,p,{'limits':{'browser_seconds':0}})
    with pytest.raises(Denied): store.charge('admission',p,'browser_seconds',0)


def test_persistent_file_budget_rejects_excess(setup,tmp_path,monkeypatch):
    from browser.storage_limits import ensure_budget
    budget=tmp_path/'budget'
    budget.mkdir()
    (budget/'file').write_bytes(b'12345')
    monkeypatch.setenv('MAX_ARTIFACT_BYTES','8')
    ensure_budget(budget,3)
    with pytest.raises(Denied):ensure_budget(budget,4)
