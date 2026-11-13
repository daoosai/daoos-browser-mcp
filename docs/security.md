# Security policy and limits

API keys are random, individually scoped and stored as SHA-256 digests. Every
request is associated with a server-resolved user and organization. Session,
profile, task, artifact and approval reads check **both** owner columns. OAuth
credentials have narrow scopes and one-hour expiry; revoking their parent key
also prevents further use. Task steps recheck revocation before execution.
Profile deletion also requires operator scope. Provision and revoke keys via the administrator CLI; keys never belong in Git or chat.

OAuth uses authorization code + mandatory S256, exact configured redirects,
resource/audience binding, a single-use consent intent bound to an HttpOnly
cookie, atomic single-use codes, issuer responses and no-store token responses.
The initial OAuth login uses a separately issued Browser API key. It does not
adopt Core cookies or imply permission to other Core projects. Automatic remote
CIMD fetching, refresh tokens and enterprise SSO are not implemented. DCR is
restricted to configured redirect URIs; production client compatibility must be
tested with the actual ChatGPT account before acceptance.

All HTTP/WebSocket requests check Host and Origin. Operator changes require the
exact service Origin. Operator cookies are Secure, HttpOnly, SameSite=Strict;
keys are never accepted in URLs. Rate limits are per source address (the local
reverse proxy shares that budget); quotas are per user and key. Default request
body cap is 1 MiB, including chunked bodies. The single-worker limiter is not a
distributed commercial abuse-control system. Do not trust arbitrary forwarded
client-IP headers.

The egress proxy resolves every destination, validates every DNS answer,
rejects non-global IPv4/IPv6 (including IPv4-mapped IPv6), connects to a validated
numeric address and repeats the check for each new connection. Only HTTP/HTTPS
on ports 80/443 are accepted. Redirects use new validated connections. The
Chromium container has no direct internet route. An explicit administrator CIDR
exception is possible; the integration fixture uses one /32 on an isolated test
network and must be removed before deployment. The browser filesystem namespace
contains only its own profile and required runtime files. No system shell or
caller-supplied JavaScript is exposed through MCP.

Read commands inspect an existing page without navigation/reload. Observe-only
commands cannot prevent background JavaScript from polling or a website from
changing its own state. Navigation is a write command even for GET. A site may
mutate state on GET; an agent must respect the target's restrictions.

Click, fill, type, select, keypress, upload and download require a five-minute
one-time approval bound to the exact parameters, session, tab and page URL.
The operator sees the command before approval. Approval parameters are encrypted
at rest. A changed command or page invalidates the approval. This intentionally
conservative policy also gates harmless interactions. Only explicitly configured
disposable fixture origins may bypass it. Password inputs are rejected from
agent text commands; use manual VNC. Operator actions are the operator's own
responsibility; do not test writes, payments or messaging on production CRM.

Page text/ARIA is returned as untrusted data. Never treat site instructions as
policy or automatically approve them. Real screenshots can contain private data
visible on the page; artifact access is restricted and files expire after 24h.
Console strings, stack traces, request headers and response bodies are omitted
because they commonly contain credentials. Network diagnostics report origins
and status codes. Action audit logs omit input text and raw parameters. Do not
publish private CRM screenshots in a public repository.

Known limits before commercial service: a dedicated service origin (the initial
path under an existing domain shares its origin with the other hosted apps); independent tenant container/VM isolation
and a dedicated security review; multi-instance locks; managed secret rotation;
organization-wide quotas; durable retention for task/audit records; resumable
uploads and bounded streaming downloads; OAuth refresh/CIMD/SSO interoperability;
precise crash accounting; backup restore drill. Native browser sandboxing is
necessary but does not prove absence of browser/kernel vulnerabilities. A passed
unit test is not a penetration test.
