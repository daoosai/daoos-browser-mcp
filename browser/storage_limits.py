"""Bound persistent files so a browser key cannot exhaust a shared host disk."""
import os
import shutil
from .store import Denied


def ensure_budget(directory, incoming_bytes, *, replacing=None, limit_env="MAX_ARTIFACT_BYTES"):
    limit = int(os.getenv(limit_env, str(256*1024*1024)))
    existing = sum(p.stat().st_size for p in directory.iterdir() if p.is_file())
    replaced = replacing.stat().st_size if replacing and replacing.exists() else 0
    if existing-replaced+incoming_bytes > limit:
        raise Denied("storage_capacity_exceeded")
    if shutil.disk_usage(directory).free < incoming_bytes+128*1024*1024:
        raise Denied("host_disk_reserve_reached")
