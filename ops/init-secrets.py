"""Run once on the deployment host. Existing secrets are never overwritten."""
from pathlib import Path
import os
import secrets
from cryptography.fernet import Fernet

root = Path("secrets")
root.mkdir(mode=0o700, exist_ok=True)
password = secrets.token_urlsafe(32)
values = {"db_password": password, "pgpass": f"db:5432:browser:browser:{password}", "profile_key": Fernet.generate_key().decode()}
if any((root / name).exists() for name in values):
    raise SystemExit("Secret files already exist; refusing partial overwrite")
for name, value in values.items():
    path = root / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f: f.write(value+"\n")
    os.chown(path, 70 if name == "db_password" else 10001, 70 if name == "db_password" else 10001)
print("Created protected secrets; back up profile_key separately from encrypted profiles.")
