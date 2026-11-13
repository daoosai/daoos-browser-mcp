# DAOOS Browser MCP

Universal headed Chromium executor for external AI agents, with two MCP tools,
real image responses, durable tasks, encrypted profiles and the same browser in
protected noVNC. This repository has no LLM engine or payment UI.

**Acceptance status is recorded in [docs/report.md](docs/report.md).** Source
implementation and unit tests alone do not constitute a deployed, accepted MVP.

- [Architecture](docs/architecture.md)
- [Security and known limits](docs/security.md)
- [Deployment and operations](docs/operations.md)
- [Client connection instructions](docs/clients.md)
- [Initial infrastructure audit](docs/audit.md)

## Run

Python 3.14, Docker Compose, available disk and nested user namespace support are
required. Default service limits permit one active browser. Existing production
services and databases must not be repurposed.

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/python ops/init-secrets.py
# Set PUBLIC_URL to the final HTTPS base URL in a private .env file.
docker compose build browser
docker compose up -d
# Provision a key into a protected file, never stdout.
docker compose exec browser python -m browser.cli provision \
  --org daoos --user owner --scopes read,write,operator --key-output /data/operator-key
```

Publish only the loopback API gateway through an approved HTTPS reverse proxy.
There are no published VNC, X11, database or debugging ports. See operations for
host-specific browser reuse, resource checks, OAuth redirect setup and backups.

## MCP commands

`browser_read`: `methods`, `status`, `sessions`, `tabs`, `snapshot`, `screenshot`,
`inspect`, `console`, `network`, `task_status`, `task_result`, `usage`, `profiles`.

`browser_write`: `create_session`, `navigate`, `click`, `fill`, `type`, `select`,
`scroll`, `press_key`, `switch_tab`, `new_tab`, `upload_file`, `download_file`,
`wait`, `execute_steps`, `cancel_task`, `close_session`, `delete_profile`,
`request_approval`, `resume_task`.

`browser_read(action="methods", params={})` publishes precise per-action schemas.
All write calls require a unique `request_id`. Unknown fields/actions fail closed.
The parameter `session_id` names a browser, not an MCP transport session.

```json
{"action":"navigate","session_id":"session_...","params":{"url":"https://oknakomfort72.ru/crm/","ready_selector":"body"},"request_id":"unique-opaque-id"}
```

A screenshot result contains both structured metadata and a real MCP image
content block. Images are bounded, opt-in, and available as owner-protected
artifacts for 24 hours. Read commands never navigate or refresh the page.

Potentially mutating interactions require one-time operator approval. Request
it with `request_approval`, review it in the operator UI, then submit the exact
command with `approval_id` and a fresh request ID. Passwords are entered manually
through VNC. Profiles are encrypted on close; live browsers are never claimed to
survive a service restart.

## Verify

```sh
.venv/bin/python -m pytest -q
# Disposable fixture override: ONLY for integration testing.
docker compose -f compose.yaml -f ops/compose-host.yaml -f ops/compose-test.yaml up -d --no-build
docker compose exec -T browser python - < ops/integration.py
```

`ops/compose-host.yaml` references a Chromium cache discovered on the audited
server; other hosts should use the normal Dockerfile browser installation.
The integration fixture changes only its own temporary data. The CRM portion
navigates and observes; it never creates orders or sends messages.
