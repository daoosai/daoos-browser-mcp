import asyncio
import base64
from collections import deque
from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
import shutil
import time
from urllib.parse import urlsplit

import psutil
from playwright.async_api import async_playwright
from .commands import validate, methods, SENSITIVE, WRITE
from .profiles import Vault
from .capture import capture
from .storage_limits import ensure_budget
from .security import safe_url, log_url, observed_url, command_hash
from .store import Denied, uid


@dataclass
class LiveSession:
    id: str
    owner: object
    profile_id: str
    directory: Path
    context: object = None
    tabs: dict = field(default_factory=dict)
    current: str = ""
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    control: str = "agent"
    console: deque = field(default_factory=lambda: deque(maxlen=100))
    network: deque = field(default_factory=lambda: deque(maxlen=100))
    processes: list = field(default_factory=list)
    started: float = field(default_factory=time.monotonic)
    metered: float = field(default_factory=time.monotonic)
    last_used: float = field(default_factory=time.monotonic)
    vnc_port: int = 0
    stopped: bool = False
    task_id: str | None = None
    meter_tick: int = 0
    cpu_seen: dict = field(default_factory=dict)
    browser_roots: list = field(default_factory=list)

    @property
    def page(self):
        page = self.tabs.get(self.current)
        if page and not page.is_closed():
            return page
        available = [(k, p) for k, p in self.tabs.items() if not p.is_closed()]
        if not available:
            raise Denied("no_open_tabs")
        self.current = available[0][0]
        return available[0][1]


class Engine:
    def __init__(self, config, store):
        self.config, self.store = config, store
        self.vault = Vault(config.data / "profiles", config.profile_key)
        self.live = {}
        self.tasks = {}
        self.capacity = asyncio.Lock()
        self.pw = None
        self.reaper = None
        self.artifacts = config.data / "artifacts"
        self.artifacts.mkdir(parents=True, mode=0o700, exist_ok=True)
        config.runtime.mkdir(parents=True, mode=0o700, exist_ok=True)

    async def start(self):
        self.store.recover()
        # Plaintext runtime never counts as a restored authorization profile.
        for d in self.config.runtime.glob("session_*"):
            if d.is_dir():
                shutil.rmtree(d)
        self.pw = await async_playwright().start()
        self.reaper = asyncio.create_task(self.sweep())

    async def stop(self):
        if self.reaper:
            self.reaper.cancel()
            await asyncio.gather(self.reaper, return_exceptions=True)
        for task in list(self.tasks.values()):
            task.cancel()
        await asyncio.gather(*list(self.tasks.values()), return_exceptions=True)
        for s in list(self.live.values()):
            async with s.lock:
                await self.close(s, save=True)
        if self.pw:
            await self.pw.stop()

    async def sweep(self):
        while True:
            await asyncio.sleep(10)
            for s in list(self.live.values()):
                if not s.lock.locked():
                    async with s.lock:
                        self.meter(s)
                        quota = self.store.get("quotas", s.owner.org+":"+s.owner.user, s.owner)
                        exhausted = quota["totals"].get("browser_seconds", 0) >= quota["limits"].get("browser_seconds", float("inf"))
                        key = self.store.get("api_keys", s.owner.key, s.owner)
                        keys = [key]
                        if key.get("parent_key"):
                            keys.append(self.store.get("api_keys", key["parent_key"], s.owner))
                        exhausted = exhausted or any(k.get("totals", {}).get("browser_seconds", 0) >= k.get("limits", {}).get("browser_seconds", float("inf")) for k in keys)
                        try: self.store.validate_principal(s.owner)
                        except Denied: exhausted = True
                        if exhausted or time.monotonic() - s.last_used > self.config.idle_seconds:
                            await self.close(s, save=True)
            cutoff = time.time() - 86400
            for path in self.artifacts.iterdir():
                if path.is_file() and path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)

    def meter(self, s):
        now = time.monotonic()
        s.meter_tick += 1
        self.store.charge(f"{s.id}:time:{s.meter_tick}", s.owner, "browser_seconds", now-s.metered, s.id, s.task_id, enforce=False)
        s.metered = now
        memory, cpu, seen = 0, 0.0, set()
        # Avoid reading /proc/*/cmdline: it can fault swapped process memory and
        # block the event loop on a memory-constrained host. Kernel stat counters
        # and the launch-time process ancestry are sufficient for attribution.
        for root in s.browser_roots:
            try:
                if not root.is_running(): continue
                for child in [root, *root.children(recursive=True)]:
                    if child.pid in seen: continue
                    seen.add(child.pid)
                    sample = child.cpu_times()
                    total = sample.user + sample.system
                    cpu += max(0, total-s.cpu_seen.get(child.pid, 0))
                    s.cpu_seen[child.pid] = total
                    memory += child.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        if seen:
            self.store.charge(f"{s.id}:cpu:{s.meter_tick}", s.owner, "cpu_seconds", cpu, s.id, s.task_id, enforce=False)
            self.store.charge(f"{s.id}:memory:{s.meter_tick}", s.owner, "memory_usage", memory, s.id, s.task_id, enforce=False)

    def session(self, id, p):
        self.store.get("sessions", id, p)
        s = self.live.get(id)
        if not s or s.stopped:
            raise Denied("session_not_live")
        return s

    def watch_page(self, s, page):
        tab_id = uid("tab")
        s.tabs[tab_id] = page
        if not s.current:
            s.current = tab_id
        # Deliberately omit console strings and bodies: they routinely contain tokens.
        page.on("console", lambda msg: s.console.append({"type": msg.type, "message": "[content omitted]"}))
        page.on("pageerror", lambda err: s.console.append({"type": "pageerror", "message": "[content omitted]"}))
        page.on("requestfailed", lambda req: s.network.append({"origin": log_url(req.url), "event": "requestfailed"}))
        page.on("response", lambda res: s.network.append({"origin": log_url(res.url), "status": res.status}) if res.status >= 400 else None)

    async def spawn(self, *args, **kwargs):
        return await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL, **kwargs)

    async def wait_vnc(self, s):
        # Do not probe RFB with a half-completed handshake: some x11vnc builds
        # can hold an X server grab during it, blocking compositor screenshots.
        for _ in range(50):
            if s.processes[-1].returncode is not None:
                raise Denied("vnc_start_failed")
            lines = Path("/proc/net/tcp").read_text().splitlines()[1:]
            if any(int(line.split()[1].split(":")[1], 16) == s.vnc_port and line.split()[3] == "0A" for line in lines):
                return
            await asyncio.sleep(.05)
        raise Denied("vnc_start_timeout")

    async def create(self, p, params, event):
        async with self.capacity:
            if len(self.live) >= self.config.max_sessions:
                raise Denied("session_capacity_reached")
            pid = params["profile_id"]
            if pid:
                self.store.get("profiles", pid, p)
                if any(s.profile_id == pid for s in self.live.values()):
                    raise Denied("profile_in_use")
            else:
                pid = uid("profile")
                self.store.put("profiles", pid, p, {"status": "empty"})
            self.store.charge(event+":session", p, "sessions_count")
            self.store.charge(event+":admission", p, "browser_seconds", 0)
            sid = uid("session")
            directory = self.config.runtime / sid
            directory.mkdir(mode=0o700)
            profile_dir = directory / "profile"
            profile_dir.mkdir(mode=0o700)
            s = LiveSession(sid, p, pid, directory)
            self.store.put("sessions", sid, p, {"status": "starting", "profile_id": pid, "control": "agent"})
            try:
                self.vault.restore(pid, profile_dir)
                preferences = profile_dir / "Default" / "Preferences"
                preferences.parent.mkdir(mode=0o700, exist_ok=True)
                prefs = json.loads(preferences.read_text()) if preferences.is_file() else {}
                prefs.setdefault("translate", {})["enabled"] = False
                prefs["credentials_enable_service"] = False
                prefs.setdefault("profile", {})["password_manager_enabled"] = False
                preferences.write_text(json.dumps(prefs))
                preferences.chmod(0o600)
                used = {x.vnc_port for x in self.live.values()}
                index = next(i for i in range(self.config.max_sessions) if 5901+i not in used)
                display = ":" + str(91 + index)
                s.vnc_port = 5901 + index
                width, height = params["width"], params["height"]
                s.processes.append(await self.spawn("Xvfb", display, "-screen", "0", f"{width}x{height}x24", "-nolisten", "tcp", "-ac"))
                for _ in range(50):
                    if Path(f"/tmp/.X11-unix/X{91+index}").exists():
                        break
                    await asyncio.sleep(.05)
                s.processes.append(await self.spawn("openbox", "--sm-disable", "--config-file", str(Path(__file__).with_name("openbox.xml")),
                    env={**os.environ, "DISPLAY": display, "HOME": str(directory)}))
                await asyncio.sleep(.2)
                args = ["--proxy-bypass-list=<-loopback>", "--disable-quic", "--disable-dev-shm-usage",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-extensions", "--kiosk", "--app=about:blank", "--window-position=0,0", "--force-device-scale-factor=1", "--disable-gpu"]
                try:
                    driver = psutil.Process(self.pw._impl_obj._connection._transport._proc.pid)
                    before = {c.pid for c in driver.children()}
                except (AttributeError, psutil.Error):
                    driver, before = None, set()
                s.context = await self.pw.chromium.launch_persistent_context(
                    str(profile_dir), headless=False, ignore_default_args=["about:blank"], timeout=self.config.operation_timeout*1000,
                    executable_path="/usr/local/bin/chromium-sandbox",
                    downloads_path=str(s.directory / "downloads"), viewport={"width": width, "height": height},
                    env={**os.environ, "DISPLAY": display}, proxy={"server": self.config.proxy},
                    accept_downloads=True, service_workers="block", args=args,
                    chromium_sandbox=os.getenv("CHROMIUM_SANDBOX", "true") == "true")
                if driver:
                    try: s.browser_roots = [c for c in driver.children() if c.pid not in before]
                    except psutil.Error: pass
                s.context.on("close", lambda: self.store.patch("sessions", sid, p, {"status": "lost", "control": "none"}) if not s.stopped else None)
                saved_state = profile_dir / ".daoos-storage-state.json"
                if saved_state.is_file():
                    restored_state = json.loads(saved_state.read_text())
                    await s.context.add_cookies(restored_state.get("cookies", []))
                s.context.set_default_timeout(self.config.operation_timeout*1000)
                s.context.set_default_navigation_timeout(self.config.operation_timeout*1000)
                async def guard(route):
                    try:
                        req = route.request
                        safe_url(req.url)
                        # Network enforcement also covers redirects/subresources in the pinned egress proxy.
                        # Disallow protocols that can read local files, including manual VNC navigation.
                        await route.continue_()
                    except Exception:
                        await route.abort("blockedbyclient")
                await s.context.route("**/*", guard)
                for page in s.context.pages:
                    self.watch_page(s, page)
                s.context.on("page", lambda page: self.watch_page(s, page))
                cdp = await s.context.new_cdp_session(s.page)
                try:
                    window = await cdp.send("Browser.getWindowForTarget")
                    await cdp.send("Browser.setWindowBounds", {"windowId": window["windowId"], "bounds": {"windowState": "normal"}})
                    await cdp.send("Browser.setWindowBounds", {"windowId": window["windowId"], "bounds": {"left": 0, "top": 0, "width": width, "height": height}})
                    await cdp.send("Browser.setWindowBounds", {"windowId": window["windowId"], "bounds": {"windowState": "fullscreen"}})
                finally:
                    try:
                        async with asyncio.timeout(2): await cdp.detach()
                    except Exception: pass
                await asyncio.sleep(.15)
                s.processes.append(await self.spawn("x11vnc", "-display", display, "-localhost", "-rfbport", str(s.vnc_port),
                    "-forever", "-shared", "-viewonly", "-nopw", "-noxdamage", "-quiet"))
                await self.wait_vnc(s)
                self.live[sid] = s
                self.store.patch("sessions", sid, p, {"status": "active", "control": "agent"})
                return {"session_id": sid, "profile_id": pid, "vnc_url": self.config.public_url+"/operator/"+sid,
                        "viewport": {"width": width, "height": height}}
            except BaseException:
                # Cleanup failures must not hide the original startup/timeout error.
                try:
                    await self.close(s, save=False)
                except Exception:
                    pass
                self.store.patch("sessions", sid, p, {"status": "failed"})
                raise

    async def close(self, s, save=True):
        if s.stopped:
            return
        s.stopped = True
        self.store.patch("sessions", s.id, s.owner, {"status": "closing", "control": "none"})
        save_error = False
        try:
            if s.context:
                if save:
                    state = {"cookies": await asyncio.wait_for(s.context.cookies(), 15)}
                    state_path = s.directory / "profile" / ".daoos-storage-state.json"
                    state_path.write_text(json.dumps(state))
                    state_path.chmod(0o600)
                await asyncio.wait_for(s.context.close(), 15)
            if save and s.context:
                self.vault.save(s.profile_id, s.directory / "profile")
                self.store.patch("profiles", s.profile_id, s.owner, {"status": "saved", "saved_at": time.time()})
        except Exception:
            save_error = True
        finally:
            for proc in reversed(s.processes):
                if proc.returncode is None:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), 3)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
            self.meter(s)
            shutil.rmtree(s.directory, ignore_errors=True)
            self.live.pop(s.id, None)
            self.store.patch("sessions", s.id, s.owner, {"status": "closed", "profile_saved": save and not save_error})
        if save_error:
            raise Denied("session_closed_profile_save_failed" if save else "browser_close_failed")

    async def handoff(self, sid, p, mode):
        p.require("operator")
        s = self.session(sid, p)
        async with s.lock:
            if s.task_id and mode == "manual":
                # A task reaches waiting_for_user only after its current command finishes.
                self.store.patch("tasks", s.task_id, p, {"status": "waiting_for_user"})
            # Kill old VNC server to invalidate every existing connection on a handoff.
            old = s.processes.pop()
            if old.returncode is None:
                old.terminate()
                try: await asyncio.wait_for(old.wait(), 3)
                except TimeoutError:
                    old.kill()
                    await old.wait()
            display = ":" + str(91 + s.vnc_port - 5901)
            args = ["x11vnc", "-display", display, "-localhost", "-rfbport", str(s.vnc_port),
                    "-forever", "-shared", "-nopw", "-noxdamage", "-quiet"]
            if mode == "agent":
                args.append("-viewonly")
            s.processes.append(await self.spawn(*args))
            await self.wait_vnc(s)
            s.control = mode
            s.last_used = time.monotonic()
            self.store.patch("sessions", sid, p, {"control": mode})
            self.store.put("actions", uid("handoff"), p, {"session_id": sid, "action": "handoff", "mode": mode, "status": "completed"})
        return {"control": mode}

    async def screenshot(self, s, p, params, event, task_id=None):
        self.store.charge(event+":screenshot", p, "screenshots_count", session_id=s.id, task_id=task_id)
        page = s.page
        data, dimensions = await capture(s, params)
        if len(data) > 6*1024*1024:
            raise Denied("screenshot_too_large")
        artifact = uid("file")
        path = self.artifacts / artifact
        ensure_budget(self.artifacts, len(data))
        path.write_bytes(data)
        path.chmod(0o600)
        self.store.put("actions", artifact, p, {"kind": "screenshot", "session_id": s.id, "task_id": task_id})
        return {"artifact_id": artifact, "mime_type": "image/png", "viewport": page.viewport_size, "image_size": dimensions,
                "source": "shared_x11_display", "scroll_capture": bool(params.get("full_page")),
                "image": base64.b64encode(data).decode()}

    def approved(self, s, p, action, params):
        # ALL potentially mutating interactions require exact owner approval.
        # Only explicitly configured disposable test origins bypass this gate.
        u = urlsplit(s.page.url)
        origin = f"{u.scheme}://{u.netloc}"
        if origin in self.config.test_origins:
            return
        id = params.get("approval_id")
        if not id:
            raise Denied("approval_required_use_request_approval")
        with self.store.engine.begin() as c:
            saved = self.store.get("approvals", id, p, conn=c, lock=True)
            if (saved.get("status") != "approved" or saved["expires"] < time.time() or saved["hash"] != command_hash(action, s.id, params)
                or saved.get("tab_id") != s.current or saved.get("page_url_hash") != __import__("hashlib").sha256(s.page.url.encode()).hexdigest()):
                raise Denied("approval_invalid_or_consumed")
            self.store.patch("approvals", id, p, {"status": "consumed"}, conn=c)

    async def read(self, p, action, sid=None, params=None):
        self.store.validate_principal(p)
        p.require("read")
        params = validate(action, params or {})
        if action == "methods": return methods()
        if action == "status":
            return {"ready": self.pw is not None, "active_sessions": len(self.live), "max_sessions": self.config.max_sessions,
                    "process_memory_bytes": psutil.Process().memory_info().rss, "process_cpu_seconds": sum(psutil.Process().cpu_times()[:2])}
        if action in {"sessions", "profiles"}:
            return {action: self.store.list(action, p)}
        if action == "usage":
            return {"quota": self.store.get("quotas", p.org+":"+p.user, p), "recent_events": self.store.list("usage", p)}
        if action in {"task_status", "task_result"}:
            task = self.store.get("tasks", params["task_id"], p)
            task.pop("encrypted_steps", None)
            if action == "task_status":
                task = {k: v for k, v in task.items() if k not in {"steps", "results"}}
            return task
        s = self.session(sid, p)
        async with s.lock:
            s.last_used = time.monotonic()
            async with asyncio.timeout(self.config.operation_timeout):
                if action == "tabs":
                    return {"tabs": [{"tab_id": id, "url": observed_url(page.url), "title": await page.title(), "active": id == s.current}
                        for id, page in s.tabs.items() if not page.is_closed()]}
                if action == "screenshot": return await self.screenshot(s, p, params, uid("read"))
                if action == "snapshot":
                    return {"snapshot": (await s.page.locator("body").aria_snapshot())[:60000], "url": observed_url(s.page.url),
                            "title": await s.page.title(), "untrusted_content": True}
                if action == "inspect":
                    loc = s.page.locator(params["selector"])
                    elements = []
                    for i in range(min(await loc.count(), 100)):
                        el = loc.nth(i)
                        elements.append({"index": i, "tag": await el.evaluate("e=>e.tagName"),
                            "text": (await el.inner_text())[:200], "role": await el.get_attribute("role"),
                            "name": await el.get_attribute("aria-label"), "box": await el.bounding_box()})
                    return {"elements": elements, "untrusted_content": True}
                if action in {"console", "network"}:
                    return {action: list(getattr(s, action)), "content_redacted": True}
        raise Denied("unknown_action")

    async def write(self, p, action, sid, params, request_id, *, task_id=None):
        self.store.validate_principal(p)
        p.require("write")
        if not request_id or len(request_id) > 100:
            raise Denied("request_id_required_max_100")
        params = validate(action, params or {}, write=True)
        event = "cmd_" + __import__("hashlib").sha256((p.org+":"+p.user+":"+request_id).encode()).hexdigest()
        fingerprint = command_hash(action, sid, params)
        # The synchronous transaction runs before any await; unique key covers other writers too.
        try:
            previous = self.store.get("actions", event, p)
        except Denied:
            previous = None
        if previous:
            if previous["hash"] != fingerprint:
                raise Denied("request_id_payload_conflict")
            return {"success": previous["status"] == "completed", "duplicate": True, "status": previous["status"], "result": previous.get("result"), "error": previous.get("error")}
        self.store.put("actions", event, p, {"session_id": sid, "task_id": task_id, "action": action,
            "hash": fingerprint, "status": "running", "started": time.time()})
        started = time.monotonic()
        s = None
        try:
            self.store.charge(event+":action", p, "actions_count", session_id=sid, task_id=task_id)
            if action == "create_session":
                async with asyncio.timeout(self.config.operation_timeout):
                    result = await self.create(p, params, event)
            elif action == "delete_profile":
                p.require("operator")
                self.store.get("profiles", params["profile_id"], p)
                if any(s.profile_id == params["profile_id"] for s in self.live.values()):
                    raise Denied("profile_in_use")
                self.vault.delete(params["profile_id"])
                self.store.remove("profiles", params["profile_id"], p)
                result = {"deleted": True}
            elif action == "cancel_task":
                saved = self.store.get("tasks", params["task_id"], p)
                if saved["status"] not in {"completed", "failed", "cancelled"}:
                    t = self.tasks.get(params["task_id"])
                    if t:
                        t.cancel()
                        await asyncio.gather(t, return_exceptions=True)
                    self.store.patch("tasks", params["task_id"], p, {"status": "cancelled", "finished": time.time()})
                result = {"task_id": params["task_id"], "status": self.store.get("tasks", params["task_id"], p)["status"]}
            elif action == "resume_task":
                saved = self.store.get("tasks", params["task_id"], p)
                s = self.session(saved["session_id"], p)
                if saved["status"] != "waiting_for_user" or s.control != "agent":
                    raise Denied("task_not_ready_to_resume")
                self.store.patch("tasks", saved["id"], p, {"status": "running"})
                result = {"task_id": saved["id"], "status": "running"}
            else:
                s = self.session(sid, p)
                async with s.lock:
                    if s.stopped: raise Denied("session_not_live")
                    if s.control != "agent" and action != "close_session": raise Denied("operator_has_control")
                    if s.task_id and task_id != s.task_id:
                        raise Denied("task_has_control")
                    s.last_used = time.monotonic()
                    if action == "execute_steps":
                        result = self.queue(s, p, params, event)
                    elif action == "request_approval":
                        validate(params["action"], params["params"], write=True)
                        aid = uid("approval")
                        # Params are not persisted: they may contain a password or token.
                        self.store.put("approvals", aid, p, {"session_id": sid, "action": params["action"],
                            "hash": command_hash(params["action"], sid, params["params"]), "status": "pending", "expires": time.time()+300,
                            "tab_id": s.current, "page_url_hash": __import__("hashlib").sha256(s.page.url.encode()).hexdigest(),
                            "encrypted_params": self.vault.cipher.encrypt(json.dumps({"action": params["action"], "params": params["params"]}).encode()).decode()})
                        result = {"approval_id": aid, "status": "waiting_for_user", "approve_at": self.config.public_url+"/operator/"+sid}
                    else:
                        async with asyncio.timeout(self.config.operation_timeout):
                            if action in SENSITIVE: self.approved(s, p, action, params)
                            result = await self.perform(s, p, action, params, event, task_id)
            self.store.patch("actions", event, p, {"status": "completed", "result": result, "duration_seconds": time.monotonic()-started})
            logging.getLogger("browser.audit").info(json.dumps({"event": "browser_action", "user_id": p.user, "organization_id": p.org,
                "session_id": sid or result.get("session_id"), "task_id": task_id, "action": action, "status": "completed", "action_id": event}))
            return {"success": True, **result}
        except BaseException as exc:
            error = str(exc) if isinstance(exc, Denied) else ("operation_timeout" if isinstance(exc, TimeoutError) else type(exc).__name__)
            error_image = None
            failure = {"status": "failed", "error": error, "duration_seconds": time.monotonic()-started}
            if s and not s.stopped and not isinstance(exc, (Denied, asyncio.CancelledError)):
                try:
                    async with asyncio.timeout(3):
                        shot = await self.screenshot(s, p, {}, event+":error", task_id)
                        failure["screenshot_artifact_id"] = shot["artifact_id"]
                        error_image = shot["image"]
                except Exception: pass
            self.store.patch("actions", event, p, failure)
            if isinstance(exc, asyncio.CancelledError): raise
            logging.getLogger("browser.audit").info(json.dumps({"event": "browser_action", "user_id": p.user, "organization_id": p.org,
                "session_id": sid, "task_id": task_id, "action": action, "status": "failed", "error": error, "action_id": event}))
            return {"success": False, **failure, **({"image": error_image} if error_image else {})}

    async def perform(self, s, p, action, params, event, task_id):
        page = s.page
        loc = page.locator(params["selector"]) if "selector" in params and params["selector"] else None
        if action == "navigate":
            safe_url(params["url"])
            response = await page.goto(params["url"], wait_until="domcontentloaded")
            if response is not None:
                await page.wait_for_load_state("load")
            if params["ready_selector"]:
                await page.locator(params["ready_selector"]).wait_for(state="visible")
            return {"session_id": s.id, "url": observed_url(page.url), "title": await page.title(),
                    "http_status": response.status if response else None, "screenshot_available": True}
        if action in {"fill", "type"} and await loc.get_attribute("type") == "password":
            raise Denied("password_input_requires_manual_vnc")
        if action == "click": await loc.click()
        elif action == "fill": await loc.fill(params["text"])
        elif action == "type": await loc.press_sequentially(params["text"])
        elif action == "select": await loc.select_option(params["value"])
        elif action == "scroll": await page.mouse.wheel(params["x"], params["y"])
        elif action == "press_key": await page.keyboard.press(params["key"])
        elif action == "wait":
            if loc: await loc.wait_for(state=params["state"])
            else: await asyncio.sleep(params["milliseconds"]/1000)
        elif action == "switch_tab":
            if params["tab_id"] not in s.tabs or s.tabs[params["tab_id"]].is_closed(): raise Denied("tab_not_found")
            s.current = params["tab_id"]
            await s.page.bring_to_front()
        elif action == "new_tab":
            new = await s.context.new_page()
            s.current = next(k for k, v in s.tabs.items() if v is new)
            if params["url"]: await new.goto(safe_url(params["url"]), wait_until="load")
            return {"tab_id": s.current}
        elif action == "upload_file":
            f = self.store.get("actions", params["file_id"], p)
            if f.get("kind") != "upload": raise Denied("upload_not_found")
            await loc.set_input_files(str(self.artifacts / f["id"]))
        elif action == "download_file":
            async with page.expect_download() as pending: await loc.click()
            download = await pending.value
            # Chrome and tmpfs cap resources; a bounded artifact is checked before saving.
            fid = uid("file")
            path = self.artifacts / fid
            source_path = Path(await download.path())
            if source_path.stat().st_size > 20*1024*1024:
                await download.delete()
                raise Denied("download_too_large")
            ensure_budget(self.artifacts, source_path.stat().st_size)
            await download.save_as(path)
            if path.stat().st_size > 20*1024*1024:
                path.unlink()
                raise Denied("download_too_large")
            path.chmod(0o600)
            await download.delete()
            self.store.put("actions", fid, p, {"kind": "download", "session_id": s.id, "task_id": task_id})
            return {"file_id": fid}
        elif action == "close_session":
            await self.close(s, params["save_profile"])
            return {"session_id": s.id, "closed": True, "profile_id": s.profile_id}
        else: raise Denied("unknown_action")
        return {"session_id": s.id, "url": observed_url(s.page.url), "screenshot_available": True}

    def queue(self, s, p, params, event):
        for step in params["steps"]:
            if set(step) - {"action", "params", "expect"}: raise Denied("invalid_step")
            if step.get("action") not in {"navigate", "click", "fill", "type", "select", "scroll", "press_key", "switch_tab", "new_tab", "wait"}:
                raise Denied("step_action_denied")
            validate(step["action"], step.get("params", {}), True)
            if step.get("expect") and set(step["expect"]) - {"selector", "url_prefix"}: raise Denied("invalid_expectation")
        tid = uid("task")
        self.store.charge(event+":task", p, "tasks_count", session_id=s.id, task_id=tid)
        self.store.put("tasks", tid, p, {"description": params["description"], "session_id": s.id,
            "status": "queued", "steps": [{"action": step["action"]} for step in params["steps"]],
            "encrypted_steps": self.vault.cipher.encrypt(json.dumps(params["steps"]).encode()).decode(),
            "current_step": 0, "results": [], "started": time.time()})
        self.meter(s)
        s.task_id = tid
        self.tasks[tid] = asyncio.create_task(self.run_task(s, p, tid))
        return {"task_id": tid, "status": "queued"}

    async def run_task(self, s, p, tid):
        results = []
        try:
            self.store.patch("tasks", tid, p, {"status": "running"})
            saved = self.store.get("tasks", tid, p)
            plan = json.loads(self.vault.cipher.decrypt(saved["encrypted_steps"].encode()))
            for i, step in enumerate(plan):
                while self.store.get("tasks", tid, p)["status"] == "waiting_for_user":
                    if s.stopped: raise Denied("session_not_live")
                    await asyncio.sleep(.5)
                self.store.patch("tasks", tid, p, {"current_step": i})
                result = await self.write(p, step["action"], s.id, step.get("params", {}), f"{tid}:{i}", task_id=tid)
                results.append(result)
                self.store.patch("tasks", tid, p, {"results": results})
                if not result.get("success"):
                    raise Denied("step_failed:" + str(i))
                async with s.lock:
                    expected = step.get("expect", {})
                    if expected.get("selector") and not await s.page.locator(expected["selector"]).is_visible():
                        raise Denied("step_expectation_failed:"+str(i))
                    if expected.get("url_prefix") and not s.page.url.startswith(expected["url_prefix"]):
                        raise Denied("step_url_mismatch:"+str(i))
            self.store.patch("tasks", tid, p, {"status": "completed", "finished": time.time()})
        except asyncio.CancelledError:
            self.store.patch("tasks", tid, p, {"status": "cancelled", "finished": time.time()})
        except Exception as exc:
            self.store.patch("tasks", tid, p, {"status": "failed", "error": str(exc) if isinstance(exc, Denied) else type(exc).__name__, "finished": time.time()})
        finally:
            if not s.stopped:
                self.meter(s)
            s.task_id = None
            self.tasks.pop(tid, None)
