"""Small CONNECT proxy. DNS answers are validated then connections use pinned IPs.
Run on an internal Docker network; only this service has outbound connectivity.
No request bodies/headers/URLs are logged. No upstream DNS re-resolution.
"""
import asyncio
import os
from urllib.parse import urlsplit
from .security import resolve_public, safe_url


async def relay(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def handle(reader, writer):
    upstream = None
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        if len(raw) > 32768:
            raise ValueError()
        lines = raw.decode("latin1").split("\r\n")
        method, target, version = lines[0].split(" ")
        if method == "CONNECT":
            u = urlsplit("https://" + target)
            safe_url("https://" + target)
            host, port = u.hostname, u.port or 443
            if port != 443:
                raise ValueError()
        else:
            safe_url(target)
            u = urlsplit(target)
            if u.scheme != "http":
                raise ValueError()
            host, port = u.hostname, u.port or 80
        allowed = tuple(filter(None, os.getenv("EGRESS_INTERNAL_CIDRS", "").split(",")))
        addresses = await asyncio.wait_for(resolve_public(host, port, allowed), 10)
        remote_reader, upstream = await asyncio.wait_for(asyncio.open_connection(addresses[0], port, limit=65536), 10)
        if method == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        else:
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            # Close each HTTP connection: no second absolute URL can bypass DNS validation.
            headers = [h for h in lines[1:] if h and h.split(":", 1)[0].lower() not in {
                "proxy-authorization", "proxy-connection", "connection", "host"}]
            first = f"{method} {path} {version}\r\nHost: {u.netloc}\r\nConnection: close\r\n"
            upstream.write((first + "\r\n".join(headers) + "\r\n\r\n").encode("latin1"))
            await upstream.drain()
        await writer.drain()
        async with asyncio.timeout(180):
            await asyncio.gather(relay(reader, upstream), relay(remote_reader, writer))
    except Exception:
        if not writer.is_closing():
            writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
    finally:
        writer.close()
        if upstream:
            upstream.close()


async def main():
    semaphore = asyncio.Semaphore(128)
    async def limited(r, w):
        async with semaphore:
            await handle(r, w)
    async def api_forward(reader, writer):
        upstream = None
        try:
            remote, upstream = await asyncio.wait_for(asyncio.open_connection("browser", 8000), 5)
            await asyncio.gather(relay(reader, upstream), relay(remote, writer))
        except Exception:
            pass
        finally:
            writer.close()
            if upstream: upstream.close()
    server = await asyncio.start_server(limited, "0.0.0.0", 8888, limit=65536)
    api = await asyncio.start_server(api_forward, "0.0.0.0", 8000, limit=65536)
    async with server, api:
        await asyncio.gather(server.serve_forever(), api.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
