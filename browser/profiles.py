import io
import os
import shutil
import tarfile
from pathlib import Path
from cryptography.fernet import Fernet
from .store import Denied
from .storage_limits import ensure_budget


class Vault:
    def __init__(self, root, key):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.cipher = Fernet(key.encode())

    def path(self, id):
        # IDs are always server-generated, never caller-provided file paths.
        import re
        if not re.fullmatch(r"profile_[a-f0-9]{32}", id):
            raise Denied("invalid_profile")
        return self.root / (id + ".enc")

    def save(self, id, runtime):
        files = [p for p in Path(runtime).rglob("*") if p.is_file() and not p.is_symlink()]
        if sum(p.stat().st_size for p in files) > 64*1024*1024:
            raise Denied("profile_too_large")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for path in Path(runtime).rglob("*"):
                if path.is_symlink() or not path.is_file() or path.name.startswith("Singleton"):
                    continue
                if buffer.tell() > 64 * 1024 * 1024:
                    raise Denied("profile_too_large")
                tar.add(path, arcname=str(path.relative_to(runtime)), recursive=False)
        target = self.path(id)
        temp = target.with_suffix(".tmp")
        encrypted = self.cipher.encrypt(buffer.getvalue())
        ensure_budget(self.root, len(encrypted), replacing=target, limit_env="MAX_PROFILE_VAULT_BYTES")
        with open(temp, "wb") as f:
            os.chmod(temp, 0o600)
            f.write(encrypted)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, target)

    def restore(self, id, runtime):
        path = self.path(id)
        if not path.exists():
            return
        if path.stat().st_size > 100*1024*1024:
            raise Denied("profile_too_large")
        with tarfile.open(fileobj=io.BytesIO(self.cipher.decrypt(path.read_bytes())), mode="r:gz") as tar:
            members = tar.getmembers()
            if sum(m.size for m in members) > 64 * 1024 * 1024:
                raise Denied("profile_too_large")
            for m in members:
                if not m.isfile() or Path(m.name).is_absolute() or ".." in Path(m.name).parts:
                    raise Denied("invalid_profile_archive")
            tar.extractall(runtime, members=members, filter="data")

    def delete(self, id):
        self.path(id).unlink(missing_ok=True)
