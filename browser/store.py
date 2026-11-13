"""Durable owner-scoped records. PostgreSQL in deployment, SQLite for unit tests."""
import hashlib
import time
import uuid
from dataclasses import dataclass
from sqlalchemy import create_engine, MetaData, Table, Column, String, Float, JSON, select, update, delete
from sqlalchemy.exc import IntegrityError

KINDS = ("users", "organizations", "api_keys", "profiles", "sessions", "tasks", "actions", "usage", "quotas", "billing_accounts", "approvals", "oauth")


def uid(prefix):
    return prefix + "_" + uuid.uuid4().hex


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class Principal:
    user: str
    org: str
    key: str
    scopes: frozenset

    def require(self, scope):
        if scope not in self.scopes:
            raise Denied("scope_denied")


class Denied(ValueError):
    pass


class Store:
    def __init__(self, url):
        connection_args = {"connect_timeout": 5, "options": "-c statement_timeout=5000 -c lock_timeout=5000"} if url.startswith("postgresql") else {}
        self.engine = create_engine(url, pool_pre_ping=True, connect_args=connection_args)
        metadata = MetaData()
        self.tables = {kind: Table(kind, metadata,
            Column("id", String(160), primary_key=True), Column("org", String(100), index=True),
            Column("user", String(100), index=True), Column("created", Float, nullable=False),
            Column("data", JSON, nullable=False)) for kind in KINDS}
        metadata.create_all(self.engine)

    def put(self, kind, id, p, data, *, conn=None):
        values = dict(id=id, org=p.org, user=p.user, created=time.time(), data=data)
        if conn is not None:
            conn.execute(self.tables[kind].insert().values(**values))
        else:
            with self.engine.begin() as c:
                c.execute(self.tables[kind].insert().values(**values))
        return {**data, "id": id}

    def get(self, kind, id, p, *, conn=None, lock=False):
        t = self.tables[kind]
        q = select(t).where(t.c.id == id, t.c.org == p.org, t.c.user == p.user)
        if lock:
            q = q.with_for_update()
        if conn is None:
            with self.engine.connect() as c:
                row = c.execute(q).mappings().first()
        else:
            row = conn.execute(q).mappings().first()
        if not row:
            raise Denied("resource_not_found")
        return {**row["data"], "id": row["id"], "created": row["created"]}

    def patch(self, kind, id, p, changes, *, conn=None):
        if conn is None:
            with self.engine.begin() as c:
                return self.patch(kind, id, p, changes, conn=c)
        old = self.get(kind, id, p, conn=conn, lock=True)
        data = {k: v for k, v in old.items() if k not in {"id", "created"}}
        data.update(changes)
        t = self.tables[kind]
        conn.execute(update(t).where(t.c.id == id, t.c.org == p.org, t.c.user == p.user).values(data=data))
        return {**data, "id": id}

    def list(self, kind, p, limit=100):
        t = self.tables[kind]
        with self.engine.connect() as c:
            return [{**r["data"], "id": r["id"], "created": r["created"]} for r in c.execute(
                select(t).where(t.c.org == p.org, t.c.user == p.user).order_by(t.c.created.desc()).limit(limit)).mappings()]

    def remove(self, kind, id, p):
        self.get(kind, id, p)
        t = self.tables[kind]
        with self.engine.begin() as c:
            c.execute(delete(t).where(t.c.id == id, t.c.org == p.org, t.c.user == p.user))

    def issue_key(self, p, scopes, quotas=None):
        import secrets
        raw = "dbk_" + secrets.token_urlsafe(32)
        self.put("api_keys", digest(raw), p, {"scopes": sorted(scopes), "revoked": False, "limits": quotas or {}, "month": "", "totals": {}})
        if not self.list("quotas", p):
            self.put("quotas", p.org + ":" + p.user, p, {"limits": quotas or {
                "actions_count": 10000, "sessions_count": 100, "tasks_count": 100,
                "screenshots_count": 1000, "browser_seconds": 36000}, "month": "", "totals": {}})
        return raw

    def authenticate(self, raw):
        t = self.tables["api_keys"]
        with self.engine.connect() as c:
            row = c.execute(select(t).where(t.c.id == digest(raw))).mappings().first()
        if not row or row["data"].get("revoked") or row["data"].get("expires", time.time()+1) <= time.time():
            raise Denied("invalid_credentials")
        p = Principal(row["user"], row["org"], row["id"], frozenset(row["data"]["scopes"]))
        parent_id = row["data"].get("parent_key")
        if parent_id:
            parent = self.get("api_keys", parent_id, p)
            if parent["revoked"] or parent.get("expires", time.time()+1) <= time.time() or not p.scopes <= set(parent["scopes"]):
                raise Denied("invalid_credentials")
        return p

    def validate_principal(self, p):
        record = self.get("api_keys", p.key, p)
        if record["revoked"] or record.get("expires", time.time()+1) <= time.time() or not p.scopes <= set(record["scopes"]):
            raise Denied("credentials_revoked_or_expired")
        if record.get("parent_key"):
            parent = self.get("api_keys", record["parent_key"], p)
            if parent["revoked"] or parent.get("expires", time.time()+1) <= time.time() or not p.scopes <= set(parent["scopes"]):
                raise Denied("credentials_revoked_or_expired")

    def charge(self, event, p, metric, value=1, session_id=None, task_id=None, enforce=True):
        """Event primary key + quota row lock make ledger and quota update atomic."""
        from datetime import datetime, timezone
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        try:
            with self.engine.begin() as c:
                quota = self.get("quotas", p.org + ":" + p.user, p, conn=c, lock=True)
                t = self.tables["usage"]
                if c.execute(select(t.c.id).where(t.c.id == event)).first():
                    return
                totals = dict(quota["totals"]) if quota["month"] == month else {}
                key = self.get("api_keys", p.key, p, conn=c, lock=True)
                key_totals = dict(key.get("totals", {})) if key.get("month") == month else {}
                key_current = key_totals.get(metric, 0) + value
                if enforce and (key_current > key.get("limits", {}).get(metric, float("inf")) or (metric == "browser_seconds" and value == 0 and key_current >= key.get("limits", {}).get(metric, float("inf")))):
                    raise Denied("key_quota_exceeded:" + metric)
                parent_id = key.get("parent_key")
                parent = self.get("api_keys", parent_id, p, conn=c, lock=True) if parent_id else None
                parent_totals = dict(parent.get("totals", {})) if parent and parent.get("month") == month else {}
                if parent:
                    parent_current = parent_totals.get(metric, 0)+value
                    if enforce and (parent_current > parent.get("limits", {}).get(metric, float("inf")) or (metric == "browser_seconds" and value == 0 and parent_current >= parent.get("limits", {}).get(metric, float("inf")))):
                        raise Denied("parent_key_quota_exceeded:" + metric)
                    parent_totals[metric] = parent_current
                current = totals.get(metric, 0) + value
                if enforce and (current > quota["limits"].get(metric, float("inf")) or (metric == "browser_seconds" and value == 0 and current >= quota["limits"].get(metric, float("inf")))):
                    raise Denied("quota_exceeded:" + metric)
                totals[metric] = current
                self.put("usage", event, p, dict(metric=metric, value=value, session_id=session_id, task_id=task_id, api_key_id=p.key), conn=c)
                self.patch("quotas", quota["id"], p, {"month": month, "totals": totals}, conn=c)
                key_totals[metric] = key_current
                self.patch("api_keys", p.key, p, {"month": month, "totals": key_totals}, conn=c)
                if parent:
                    self.patch("api_keys", parent_id, p, {"month": month, "totals": parent_totals}, conn=c)
        except IntegrityError:
            # A concurrent identical event has already committed.
            return

    def recover(self):
        """Never pretend an OS browser or an ambiguous write survived a restart."""
        with self.engine.begin() as c:
            for kind, states, replacement in [
                ("sessions", {"starting", "active", "closing"}, {"status": "lost", "control": "none", "usage_incomplete": True}),
                ("tasks", {"queued", "running", "waiting_for_user"}, {"status": "failed", "error": "service_restarted_session_lost"}),
                ("actions", {"running"}, {"status": "uncertain", "error": "service_restarted_do_not_retry"})]:
                t = self.tables[kind]
                for row in c.execute(select(t)).mappings():
                    if row["data"].get("status") in states:
                        c.execute(update(t).where(t.c.id == row["id"]).values(data={**row["data"], **replacement}))
