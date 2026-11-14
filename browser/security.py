import asyncio
import ipaddress
import json
import re
import socket
from urllib.parse import urlsplit, urlunsplit
from .store import Denied, digest


def safe_url(url):
    try:
        u = urlsplit(url)
        if u.scheme not in {"http", "https"} or not u.hostname or u.username or u.password or u.port not in {None, 80, 443}:
            raise ValueError()
        if len(url) > 4096 or any(c in url for c in "\r\n\x00\\"):
            raise ValueError()
        return url
    except ValueError:
        raise Denied("url_denied") from None


def observed_url(url):
    # URLs returned to agents must not echo authentication query/fragment values.
    try:
        u = urlsplit(url)
        return urlunsplit((u.scheme, u.netloc.split("@")[-1], u.path, "", ""))
    except ValueError:
        return "[invalid]"


def log_url(url):
    """Only origin is logged: query, path and fragment can all carry secrets."""
    try:
        u = urlsplit(url)
        return urlunsplit((u.scheme, u.netloc.split("@")[-1], "", "", ""))
    except ValueError:
        return "[invalid]"


def public_ip(value):
    ip = ipaddress.ip_address(value)
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def resolve_public(host, port, allowed=()):
    """Validate ALL answers and return numeric addresses used by the connector."""
    try:
        answers = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise Denied("dns_failed") from None
    addresses = list(dict.fromkeys(a[4][0] for a in answers))
    if not addresses or any(not public_ip(a) and not any(ipaddress.ip_address(a) in ipaddress.ip_network(n) for n in allowed) for a in addresses):
        raise Denied("destination_denied")
    return addresses


def command_hash(action, session_id, params):
    clean = {k: v for k, v in params.items() if k != "approval_id"}
    return digest(json.dumps([action, session_id, clean], sort_keys=True, separators=(",", ":")))


SECRET = re.compile(r"(?i)(bearer\s+\S+|(?:password|token|secret|api[_-]?key)\s*[:=]\s*\S+)")


def redact(value):
    return SECRET.sub("[REDACTED]", str(value))[:1000]
