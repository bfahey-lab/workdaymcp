# Workday MCP demo

A remote MCP server on Cloudflare Workers. Connect it in Claude Desktop, a
browser opens by itself with the real Workday login, and tools then run against
Agent Gateway with an employee-as-self token.

**Single-user demo.** Not for production — see Limits below.

## The two ways in

```
        auto-popup                              manual fallback
Claude ──401──► Worker ──► /authorize      you ──► /login
                              │                     │
                              └──► Workday login ◄──┘
                                        │
                              /workday/callback
                              exchanges code for token
                              │                     │
                    token in the grant        token in KV
```

**`/authorize` — the demo path.** Claude calls `/mcp`, gets `401` +
`WWW-Authenticate`, reads the discovery documents, registers itself, and opens a
browser. That 401 is the only thing that makes Claude open a window; everything
else follows from it. The Workday token ends up inside the grant behind Claude's
own token.

**`/login` — the fallback.** You open it yourself. Same Workday login, but the
token is stored in KV under a fixed key. Kept so a live demo is recoverable if
the popup misbehaves.

The callback is shared. It tells the two apart by whether a parked authorization
request exists.

Either way, the code-for-token exchange happens server-side with the client
secret — Workday's flow has no PKCE, so the secret is what protects it.

## Routes

| Route | Purpose |
| --- | --- |
| `/mcp` | MCP endpoint. Add this as a connector in Claude Desktop. |
| `/authorize` | Opened by Claude. Redirects to the Workday login. |
| `/login` | Manual fallback sign-in. |
| `/workday/callback` | Workday returns here with the code. |
| `/` | Prints the connector and sign-in URLs. |

## Tools

| Tool | Purpose |
| --- | --- |
| `workday_auth_status` | Reports tenant, expiry, and which path supplied the token. Never reveals the token. |
| `workday_search_workers` | Finds workers by name. Returns the `id` the next tool needs. |
| `workday_get_direct_reports` | Lists a worker's direct reports, given that `id`. |
| `workday_sign_out` | Revokes the grant and clears the stored token, so the next call re-prompts. |

No tool takes an access token argument — the token comes from whoever signed in,
so a tool cannot be talked into using someone else's.

### Demonstrating re-auth

Ask Claude to sign out of Workday, then run any Workday tool. Revoking the grant
deletes its access tokens, so Claude's next call gets a `401` and the browser
opens again — the same path a real expiry takes, without waiting an hour for one.

## Setup

**1. Register the agent in Workday ASOR.** A **delegate** agent (delegate = uses
a Redirect URI) with access **employee as self**. Record the Client ID and
Secret. Tenant alias is the path segment in your Workday URL:
`https://wd8.myworkday.com/<tenantalias>/d/home.html`

Set the Redirect URI to your deployed callback — Workday allows exactly **one**
per registration:

```
https://<worker>.<subdomain>.workers.dev/workday/callback
```

**2. Create a KV namespace** and put its id in `wrangler.jsonc`:

```powershell
npx wrangler kv namespace create OAUTH_KV
```

The binding must be `OAUTH_KV` — the OAuth library reads that exact name. The
label you give the namespace in the dashboard is cosmetic.

**3. Fill in `wrangler.jsonc`** (tenant alias, client id — both safe to commit),
then set the secret, which must **not** go in that file:

```powershell
npx wrangler secret put WORKDAY_CLIENT_SECRET
npx wrangler deploy
```

Dashboard alternative for the secret: your Worker → Settings → Variables and
Secrets → Add → type Secret → name it `WORKDAY_CLIENT_SECRET`.

**4. Add the connector in Claude Desktop** pointing at
`https://<worker>.<subdomain>.workers.dev/mcp`, and click Connect. The browser
should open on its own.

> After switching a Worker between authless and OAuth, **remove and re-add the
> connector**. Claude caches whether a server needs auth and will not re-check.

## Layout

| File | Role |
| --- | --- |
| `src/index.ts` | OAuth wiring, the four routes, the MCP handler. |
| `src/workday.ts` | Authorize URL, code exchange, token and pending-request storage. |
| `src/tools.ts` | MCP tools. Add new ones here. |

### Adding a tool

`resolveToken` picks the grant token first and the `/login` token second, so a
tool works from either path:

```ts
const resolved = await resolveToken(env, props);
if (!resolved) return signedOut(origin);

const response = await fetch(`https://${env.WORKDAY_REGION_HOST}/...`, {
    headers: { Authorization: `Bearer ${resolved.token.accessToken}` },
});
```

Note that `src/index.ts` rebuilds the MCP handler per request rather than caching
it, because it closes over one caller's token. Don't add caching there.

## Limits

- **One stored fallback token and one parked request**, both under fixed keys.
  Concurrent sign-ins clobber each other.
- **`userId` is the constant `"demo-user"`**, so all grants collapse onto one
  identity. Fine for one person; wrong for anything shared.
- **Refresh tokens are disabled** (`refreshTokenTTL: 0`), deliberately. The
  Workday token lives in the grant and cannot be renewed on its own, so a
  refreshable Claude token would eventually wrap a dead Workday one — Claude
  would keep renewing, never see a 401, and every tool call would fail against
  Workday instead. Without refresh, Claude's token simply expires and the whole
  flow re-runs, renewing the Workday token with it.
- **`iss` is not advertised**, though it is sent. `mcp-remote` 0.13.x drops the
  parameter before its SDK sees it, and advertising support makes that fatal.
  See the comment in `src/index.ts`; remove the workaround once it forwards it.

## Status

Confirmed working end to end against tenant `commitsrv_wcpdev1`: the `/authorize`
popup from Claude Desktop, the code exchange, and both worker tools chaining
search into direct reports.

Unconfirmed, carried over from `workday-agent-mcp-memory.md`:

- Whether delegate agents get refresh tokens.
- Token response shape. `expires_in` is used if present, treated as unknown if not.
- Region hosts outside the US.
