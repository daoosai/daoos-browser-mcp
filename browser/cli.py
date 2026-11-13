import argparse
import os
from pathlib import Path
import sys
from .store import Store, Principal, uid


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    provision = commands.add_parser("provision")
    provision.add_argument("--user", required=True)
    provision.add_argument("--org", required=True)
    provision.add_argument("--scopes", default="read,write")
    provision.add_argument("--key-output", type=Path, required=True)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--user", required=True)
    revoke.add_argument("--org", required=True)
    revoke.add_argument("--key-id", required=True)
    args = parser.parse_args()
    store = Store(os.environ["DATABASE_URL"])
    p = Principal(args.user, args.org, "provisioner", frozenset())
    if args.command == "provision":
        scopes = set(args.scopes.split(","))
        if not scopes <= {"read", "write", "operator"} or "read" not in scopes:
            parser.error("scopes must include read; allowed: read,write,operator")
        for kind, id in [("organizations", args.org), ("users", args.user), ("billing_accounts", args.org+":"+args.user)]:
            try: store.get(kind, id, p)
            except ValueError: store.put(kind, id, p, {"enabled": True})
        raw = store.issue_key(p, scopes)
        # Never print an API key into terminal history or execution logs.
        fd = os.open(args.key_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f: f.write(raw+"\n")
        print("Key written to protected file; transfer via your secret manager.")
    else:
        store.patch("api_keys", args.key_id, p, {"revoked": True})
        print("Key revoked, including child OAuth and operator credentials.")


if __name__ == "__main__": main()
