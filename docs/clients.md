# Connect clients

The final external endpoint is `<HTTPS_BASE_URL>/mcp`. Do not use the audit
server's loopback address from a remote client. Verify the deployed endpoint,
TLS, protected-resource metadata and approved OAuth redirects before connecting.

## ChatGPT

The deployed endpoint is `https://oknakomfort72.ru/browser/mcp`. The private
[DAOOS Browser plugin](https://chatgpt.com/plugins/plugins_6af7cf5ae9788191b93f0d3730258a9c)
is available for the owner to connect with OAuth. Its source contains no keys.

Enable developer mode where available in the account/workspace, create a private
MCP connection using the HTTPS endpoint and select OAuth. Follow the Browser
consent page using an individually provisioned Browser API key, not a website
password. Allow `read` and, when needed, `write`. Confirm that both tools appear.
Call create_session, navigate, screenshot and verify an actual image is rendered.
Client availability and workspace permission must be checked in the real account.

The server advertises protected-resource metadata and authorization-server
metadata, and implements PKCE authorization-code login. Redirects must be
configured exactly; do not add wildcard callbacks. It currently uses restricted
DCR and short-lived access tokens; refresh and remote client metadata fetching
are not implemented. Reauthorization is needed after expiry. An SDK connection
is not proof that ChatGPT OAuth consent and image rendering passed.

Official references: [MCP authentication](https://developers.openai.com/plugins/build/auth)
and [MCP client configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

## Codex

Add to the client's configuration, with a secret injected into the process
through its secret manager rather than committed to a file:

```toml
[mcp_servers.daoos_browser]
url = "https://oknakomfort72.ru/browser/mcp"
bearer_token_env_var = "DAOOS_BROWSER_API_KEY"
tool_timeout_sec = 120
```

Replace the URL with the actual approved endpoint. A key must include `read`;
`write` is required for browser control. Keep the client tool approval policy
alongside the server's own exact-command approval. Confirm discovery, screenshot
image content and reconnect. Follow the [official MCP configuration documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
for the installed client version.

## Core and OpenClaw

Configure a Streamable HTTP connection and a separate service key bound to the
intended user/organization. Core retains planning, retry policy and dangerous
action approvals. Browser receives structured commands and task plans, and Core
polls task_status/task_result. Never automatically retry a failed/uncertain
mutating command with a fresh request_id. The MCP endpoint is standalone; no Core
connection is required to use it. Core/OpenClaw live registration is a separate
acceptance check and is not implied by an example configuration.

## Manual login

1. Open `<HTTPS_BASE_URL>/operator/login` and sign in with an operator-scoped key.
2. Create a session through MCP; open its returned `vnc_url` in the same browser.
3. Take control; wait for the handoff; reconnect the screen.
4. Log in directly on the website. Never send its password through chat.
5. Return control, reconnect the screen in view-only mode, then resume a paused task.
6. Close with `save_profile=true`. Create a new session with that profile_id and
   verify the authorized page again. A profile saved before login is not an
   authorization persistence test.

## Key delivery on the audited server

An owner-only operator key is stored at `/data/operator-key`, and a separate
read/write client key at `/data/chatgpt-key`, inside `daoos-browser-browser-1`.
Retrieve them only through your existing authenticated server access, for example
in your own private terminal (never paste the result into chat or Git):

```sh
# Run on the DAOOS host. Paste directly into the corresponding protected form.
docker exec daoos-browser-browser-1 cat /data/chatgpt-key
# Separate operator login credential:
docker exec daoos-browser-browser-1 cat /data/operator-key
```

The client key goes on the Browser OAuth consent page; the operator key goes at
`https://oknakomfort72.ru/browser/operator/login`. Site passwords are a third,
independent credential and are entered only directly into the site's VNC screen.
A session idle for 15 minutes closes automatically. Reopen its saved profile
through MCP rather than assuming the previous live session still exists.
