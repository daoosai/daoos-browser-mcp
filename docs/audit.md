# Initial audit — 2026-11-13 UTC

Repository: https://github.com/daoosai/daoos-browser-mcp
Baseline: `3e52cd363d8b07fbd01376af509ee84bd7ac878b` (main).
One initial commit, containing README, LICENSE and .gitignore. No browser engine,
MCP implementation, deployment code or existing tests were present. Work proceeds
on `feature/browser-mvp`; main is not modified.

The current executor is on a DAOOS/CRM host with existing Caddy, nginx, Core
services, OpenClaw, Flow, CRM-related applications and dedicated existing
PostgreSQL containers. They were inspected read-only. Neither their containers,
databases, application code, credentials nor website data were repurposed.

At audit start: 1 logical CPU; 3911 MiB RAM total, approximately 1223 MiB
available; 2047 MiB swap fully used. Root filesystem 28 GiB, approximately
3.8 GiB available before development. Disk pressure later caused one image
extraction to fail. Buildx was installed as a user-level Docker CLI plugin;
existing Docker and application daemons were not restarted. The final image
reuses cached build layers and a read-only existing Chromium installation.
Resources on this shared host vary while other workloads run.

Available reusable components: Python 3.14, Playwright 1.64.1, Chromium revision
1248, Xvfb, Docker, PostgreSQL 17 image, existing HTTPS termination. Only browser
binaries are reused; no existing user's browser profile or authorized cookies
are mounted. A running standalone x11vnc/noVNC server was not found in the
inspected host services/ports; OpenClaw has noVNC frontend assets, which alone do
not establish a reusable VNC session. New x11vnc/noVNC packages are contained in
the new service image.

Core's inspected browser_inspection implementation uses short-lived owner/run
scope for narrowly permitted Core pages and a managed inspection script. Its
OAuth module is coupled to Core identity and project grants. Replacing these
with a universal browser or sharing their credentials would broaden access.
They were left intact. Browser instead exposes a client-independent MCP executor
contract; Core connection requires a dedicated explicitly scoped service key.

DAOOS connector list_projects and list_runtime_nodes returned Internal error.
Consequently other registered servers, remote VNC infrastructure and live Core
registration could not be audited through that API. This report describes the
current host and the inspected source, not the entire DAOOS fleet.

New resources use the `daoos-browser` Docker project and dedicated volumes and
networks. The only persistent host security addition is the separate
`daoos-browser` AppArmor profile, needed for nested browser namespaces. Existing
standard bwrap/Chrome AppArmor profiles and global sysctls were not changed.
The proposed Caddy route is prepared and validated separately; applying it to
production needs the owner's approval under section 13 of the supplied task.
