# Deployment and operations

Before deployment inspect available CPU, memory, swap and disk. Do not start a
multi-browser farm on this server. Defaults reserve up to 768 MiB for the browser
service, 128 MiB for PostgreSQL and 64 MiB for the gateway; those are limits, not
measured consumption. CPU limits are 0.75 / 0.15 / 0.15. Runtime profile tmpfs is
256 MiB and `/tmp` is 128 MiB, counted against the memory limit. Process count is
limited. Logs rotate at 5 MiB x 3 per service. Chromium's own user namespace and
the filesystem sandbox must pass `ops/check-launch.py`; no no-sandbox fallback.

The service currently supports exactly one API process. `MAX_SESSIONS` controls
capacity within it. Do not add uvicorn workers. Each active profile is exclusively
owned by a live session. Idle sessions close after 900 seconds. A full profile
archive is limited to 64 MiB uncompressed. Artifacts expire after 24 hours. Artifacts and the encrypted profile vault each
have a 256 MiB aggregate cap by default, plus a 128 MiB host disk reserve.
Uploads count against the action quota. Downloads are size-checked before copying
to persistent storage. Browser container swap and core dumps are disabled.

Load only the new dedicated AppArmor profile before first container creation:

```sh
sudo install -m 0644 ops/apparmor.profile /etc/apparmor.d/daoos-browser
sudo apparmor_parser -r /etc/apparmor.d/daoos-browser
```

This does not edit the host's standard bwrap/Chrome profiles or global sysctls.
The profile explicitly inherits execution inside the dedicated container, where
Docker still drops all host capabilities. The additional seccomp rules permit
modern bubblewrap syscalls and return ENOSYS for clone3 to use the permitted
clone fallback. `systempaths=unconfined` is necessary to mount a fresh PID-scoped
procfs; it applies only to this container. Bubblewrap then hides service secrets
and other sessions from Chromium and Chromium keeps its own renderer sandbox.

## Secrets and URLs

`ops/init-secrets.py` creates independent database and vault secrets without
printing them and refuses to overwrite existing files. Keep the secret directory
outside Git. `PGPASSFILE` avoids embedding a database password in the DSN.
Provision each user/key with the CLI (default read/write; operator scope must be
requested explicitly); transfer a key through a secret manager.
API keys are hashed in PostgreSQL. Revoke by its key ID with the CLI. Do not
share operator credentials with an agent client: issue separate read/write keys.

Set `PUBLIC_URL` to the exact externally approved HTTPS base, without a trailing
slash. `ops/caddy-browser.conf` is a proposed addition inside the existing domain
block. It includes path-aware OAuth discovery. Validate the complete proposed
Caddy configuration, back up the old one and obtain approval before applying or
reloading an existing production reverse proxy. Do not duplicate the domain block.
The internal app checks Host against the configured public authority and checks
Origin against its scheme/authority. Operator cookies require HTTPS.

For a different provider, implement BillingProvider outside browser commands.
Do not enable real payments in the MVP.

## Health and diagnosis

`/health` exposes only liveness. `/ready` checks the database and engine startup;
it does **not** prove that a browser can launch. `/ready`, `/metrics`, `/api/*` and
MCP require credentials. Check launch, the real screenshot and service health
before acceptance. MCP status includes process memory and CPU time; periodic
browser-specific samples are recorded when available. Container CPU/memory
limits, `memory.events` and logs provide independent diagnostics. Browser error
messages returned to clients are fixed codes, never raw Playwright call traces.

## Integration verification

`ops/compose-test.yaml` adds a disposable SPA and a single internal /32 egress
exception. It must not be part of the production invocation. Its `fixture.py`
contains no production credentials. The integration script verifies actual MCP,
SPA/ARIA/images, one-time approval, tasks, profile reuse, VNC control and
performs only observation/navigation on the CRM. Store screenshots and raw
reports privately; never commit customer data to this public repository.

For this audited host, `ops/compose-host.yaml` reuses the exact installed
Chromium 1248 cache read-only, without mounting any user profiles. Do not blindly
reuse that host path elsewhere. Normal image builds install the pinned Playwright
browser revision. On a space-constrained host, build on a separate approved
builder and transfer the immutable image. Never prune unrelated Docker data.

Native screenshots use the same X display as noVNC. The minimal window manager
has no executable menus or launch shortcuts. The Chromium app window is aligned
to the physical viewport. Full-page capture scrolls, stitches real pixel tiles and
restores the original position; sticky headers can repeat and dynamic page state
may change between tiles. Screenshots of an element require it to be in view;
request an explicit scroll command before capturing an off-screen element.

## Backup, recovery and upgrade

Run `ops/backup.sh` with BACKUP_DIR pointing to a protected encrypted backup
filesystem. The backup contains a PostgreSQL custom dump, encrypted profile
archives and the profile key; store the key separately in the actual backup
system. Schedule this script using the organization's backup system after the
backup destination and retention policy are chosen. No external destination is
assumed. Test pg_restore into a fresh dedicated database and reopen a saved
profile before relying on a backup. An untested backup is not proven recoverable.

Stop active tasks and close browsers before an upgrade to checkpoint profiles.
On unexpected restart, persistent task/action records remain, live sessions
become lost, pending tasks fail with a session-loss error and running actions
become uncertain. Never silently replay them. Restore from an encrypted profile
only via explicit create_session(profile_id=...). Unsaved login changes and the
last metering interval may be lost; the state records this limitation.

Database schema upgrades beyond this first release require explicit migrations.
Keep the previous immutable image for rollback; do not roll back a database
schema automatically. PostgreSQL and vault volumes are independent of containers.
