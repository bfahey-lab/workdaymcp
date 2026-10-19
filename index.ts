/**
 * OAuthProvider owns the front door. The part that matters for the demo: it
 * answers an unauthenticated /mcp with 401 + WWW-Authenticate, which is the one
 * thing that makes Claude Desktop open a browser by itself.
 *
 * It also serves the discovery documents, /token and /register. Everything else
 * falls through to appHandler below.
 */

import OAuthProvider, {
	OAuthError,
	type TokenExchangeCallbackOptions,
} from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { registerTools } from "./tools";
import {
	authorizeUrl,
	DEMO_USER_ID,
	exchangeCode,
	MAX_ACCESS_TOKEN_TTL_SECONDS,
	needsRefresh,
	parkAuthRequest,
	refreshToken,
	saveToken,
	secondsRemaining,
	takeLatestAuthRequest,
	type StoredToken,
} from "./workday";

const appHandler: ExportedHandler<Env> = {
	async fetch(request, env) {
		try {
			return await route(request, env);
		} catch (error) {
			// Without this the Worker throws and Cloudflare shows its opaque
			// "Error 1101" page, which says nothing about what went wrong. The
			// common case is a client whose registration is gone from KV while
			// the client still has its id cached on disk.
			const detail = error instanceof Error ? error.message : String(error);
			return text(
				`${detail}\n\n` +
					"If this says the client_id is invalid, the client's registration no " +
					"longer exists on this server. Clear the client's cached registration " +
					"(for mcp-remote, delete the ~/.mcp-auth folder) and connect again so " +
					"it registers afresh.",
				400,
			);
		}
	},
};

async function route(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);

	// Claude opens this in a browser after the 401. Park what it asked for
	// under its own id, drop that id in a cookie, then hand the user to
	// Workday. Workday's redirect back is a top-level navigation, so a
	// SameSite=Lax cookie returns with it — which is how the callback knows
	// which authorization it is finishing.
	if (url.pathname === "/authorize") {
		const authRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
		const id = crypto.randomUUID();
		await parkAuthRequest(env, id, authRequest);

		return new Response(null, {
			status: 302,
			headers: {
				Location: authorizeUrl(env),
				"Set-Cookie": txnCookie(id, url),
			},
		});
	}

	// Manual fallback. Clearing the cookie is what tells the callback this
	// login is not part of a Claude authorization.
	if (url.pathname === "/login") {
		return new Response(null, {
			status: 302,
			headers: {
				Location: authorizeUrl(env),
				"Set-Cookie": txnCookie("", url, 0),
			},
		});
	}

	if (url.pathname === "/workday/callback") {
		const code = url.searchParams.get("code");
		if (!code) return text(`Workday returned no code.${url.search}`, 400);

		// Always finish the NEWEST parked request, not the one the cookie names.
		//
		// The cookie is the theoretically correct correlator, but it is the wrong
		// answer in practice: mcp-remote runs two proxy instances, only one owns
		// the callback port, and each retry writes its PKCE verifier to a
		// state-keyed file that REPLACES the previous one. So the client can only
		// ever complete its most recent /authorize — every earlier parked request
		// is already unfinishable. Completing one lands a code the client has no
		// verifier for: "No code verifier saved for session".
		//
		// The cookie is still read, for the log line only.
		const txnId = readCookie(request, TXN_COOKIE);
		const pending = await takeLatestAuthRequest(env);

		console.log(
			`workday/callback: cookie=${txnId ? "present" : "absent"} pending=${
				pending ? "found" : "none"
			} state=${pending?.state ?? "-"}`,
		);

		let token: StoredToken;
		try {
			token = await exchangeCode(env, code);
		} catch (error) {
			return text(error instanceof Error ? error.message : String(error), 502);
		}

		if (!pending) {
			await saveToken(env, token);
			return text("Signed in to Workday. You can close this tab and return to Claude.");
		}

		// RFC 9207: the authorization response must carry `iss`, and our
		// metadata advertises that it does. The provider only emits it when
		// request.issuer is set, so guarantee it rather than trusting the
		// round trip — mcp-remote 0.13+ rejects the response without it.
		const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
			request: { ...pending, issuer: pending.issuer || url.origin },
			userId: DEMO_USER_ID,
			metadata: {},
			scope: pending.scope,
			props: token,
		});

		return new Response(null, {
			status: 302,
			headers: { Location: redirectTo, "Set-Cookie": txnCookie("", url, 0) },
		});
	}

	return text(
		`Workday MCP demo.\n\nConnector: ${url.origin}/mcp\nManual sign-in: ${url.origin}/login`,
	);
}

const mcpHandler = {
	fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		// Set by OAuthProvider from the grant behind the caller's token.
		const props = (ctx as ExecutionContext & { props?: StoredToken }).props;
		const origin = new URL(request.url).origin;

		// Rebuilt per request: it closes over one caller's token.
		const handler = createMcpHandler(
			() => {
				const server = new McpServer({ name: "Workday", version: "1.0.0" });
				registerTools(server, env, origin, props);
				return server;
			},
			{ route: "/mcp" },
		);

		return handler(request, env, ctx);
	},
};

/**
 * Refreshes the Workday token that rides inside the grant, on every token
 * exchange, so Claude's refresh also renews Workday.
 *
 * This is what makes refresh tokens safe here. The old objection was sound: a
 * refreshable Claude token would eventually wrap a dead Workday one, Claude
 * would keep renewing happily, never see a 401, never re-prompt, and every tool
 * call would fail against Workday instead. That is exactly what an overnight gap
 * produced. The answer was never "disable refresh" — it was "renew both
 * together", which needs a Workday refresh token. This tenant issues one.
 *
 * Two guarantees come out of this:
 *
 *  - Claude's access token never outlives the Workday token it wraps, because
 *    `accessTokenTTL` is clamped to the Workday token's remaining life. A stale
 *    Workday token can no longer hide behind a live Claude token.
 *  - A terminal refresh failure surfaces as `invalid_grant`, which is the 401
 *    that makes Claude re-run the interactive flow. Failure still recovers; it
 *    just is not the routine path any more.
 */
async function onTokenExchange(
	env: Env,
	options: TokenExchangeCallbackOptions,
): Promise<{ newProps: StoredToken; accessTokenTTL?: number }> {
	const current = options.props as StoredToken;

	let token = current;
	if (needsRefresh(current)) {
		if (!current.refreshToken) {
			// Pre-refresh-support grant, or a tenant that stopped issuing them.
			// Nothing to renew with, so end the grant rather than hand out a token
			// wrapping a Workday one that is about to die.
			throw new OAuthError("invalid_grant", {
				description: "Workday session expired and cannot be renewed; sign in again.",
			});
		}

		try {
			token = await refreshToken(env, current.refreshToken);
		} catch (error) {
			console.log(
				`workday/refresh failed on ${options.grantType}: ` +
					(error instanceof Error ? error.message : String(error)),
			);
			throw new OAuthError("invalid_grant", {
				description: "Could not renew the Workday session; sign in again.",
			});
		}
	}

	// Never promise more Claude-token life than the Workday token has left.
	// After a refresh this is the full 4 hours, so the clamp only binds on the
	// rare path where Workday itself returned something short-lived.
	const remaining = secondsRemaining(token);
	return {
		newProps: token,
		accessTokenTTL: Math.max(60, Math.min(MAX_ACCESS_TOKEN_TTL_SECONDS, remaining)),
	};
}

/**
 * Built per request rather than once at module scope: `tokenExchangeCallback`
 * receives no `env`, so the only way it can reach the Workday client secret is
 * by closing over one. Memoised on the env identity, which is stable for the
 * life of an isolate, so this is one construction per isolate in practice.
 */
let cachedProvider: { env: Env; provider: OAuthProvider } | undefined;

function getProvider(env: Env): OAuthProvider {
	if (cachedProvider?.env === env) return cachedProvider.provider;

	const provider = new OAuthProvider({
		apiRoute: "/mcp",
		apiHandler: mcpHandler,
		defaultHandler: appHandler,
		authorizeEndpoint: "/authorize",
		tokenEndpoint: "/token",
		clientRegistrationEndpoint: "/register",

		// Refresh tokens are on, and the default 30-day lifetime is the point:
		// coming back after two days must renew silently rather than reopen a
		// browser. onTokenExchange keeps the wrapped Workday token fresh.
		tokenExchangeCallback: (options) => onTokenExchange(env, options),
	});

	cachedProvider = { env, provider };
	return provider;
}

/**
 * Serves the provider, minus one advertised capability.
 *
 * We do emit `iss` on the authorization response (RFC 9207), and the provider
 * advertises `authorization_response_iss_parameter_supported: true` to say so.
 * But mcp-remote 0.13.x reads the callback and calls
 * `finishAuth(code)` — dropping `iss` before its SDK ever sees it. The SDK then
 * finds `iss` undefined, sees the capability advertised, and hard-fails with
 * IssuerMismatchError. No value we send can reach it.
 *
 * Removing the advertisement takes that branch out of play: an absent `iss` is
 * accepted instead of fatal. We still send it, and a client that forwards it
 * correctly still gets a full comparison — only clients that drop it skip the
 * check. That is the narrowest available workaround for someone else's bug, and
 * it can be deleted once mcp-remote forwards the parameter.
 */
const ISS_CAPABILITY = "authorization_response_iss_parameter_supported";

/**
 * Turns a rejected *refresh* into a re-authorization instead of a dead end.
 *
 * Another mcp-remote workaround, and the same shape as ISS_CAPABILITY above.
 * When a refresh fails, its SDK decides what to do by inspecting the error:
 *
 *   catch (e) {
 *     if (!(e instanceof OAuthError) || e.code === ServerError) { }  // fall through
 *     else throw e;                                                 // give up
 *   }
 *
 * A well-formed `invalid_grant` is an OAuthError that is not ServerError, so it
 * takes the `throw` branch and the interactive flow is never reached. The client
 * then keeps the dead refresh token on disk and fails identically on every
 * restart — permanently stuck until the token file is deleted by hand. Which is
 * wrong: `invalid_grant` is precisely the code that means "re-authorize".
 *
 * A body that does not parse as an OAuth error becomes ServerError, which the
 * SDK swallows, so it proceeds to startAuthorization and opens the browser. So
 * we answer a rejected refresh with a plain-text 500.
 *
 * This is what makes three separate situations recover on their own rather than
 * needing intervention:
 *
 *  - workday_sign_out revoking the grant (the demo depends on this)
 *  - the 30-day refresh token finally expiring
 *  - two proxy instances refreshing concurrently and leaving the token file
 *    holding a refresh token the grant no longer recognises
 *
 * Scoped deliberately to grant_type=refresh_token. Rewriting invalid_grant on an
 * authorization_code exchange would turn a replayed code into a fresh
 * authorization attempt, which is how you build a redirect loop.
 */
async function reauthorizeInsteadOfFailing(
	response: Response,
	grantType: string | undefined,
): Promise<Response> {
	if (grantType !== "refresh_token" || response.status !== 400) return response;

	const body = await response.clone().text();
	if (!body.includes('"invalid_grant"')) return response;

	console.log("token/refresh rejected (invalid_grant) -> asking the client to re-authorize");
	return text(
		"The grant behind this refresh token no longer exists. Re-authorization is required.",
		500,
	);
}

/** grant_type of a /token POST, read without consuming the provider's copy. */
async function readGrantType(request: Request): Promise<string | undefined> {
	if (request.method !== "POST") return undefined;
	try {
		const form = await request.clone().formData();
		const value = form.get("grant_type");
		return typeof value === "string" ? value : undefined;
	} catch {
		return undefined; // not form-encoded; let the provider reject it
	}
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const { pathname } = new URL(request.url);

		// Read before the provider consumes the body.
		const grantType = pathname === "/token" ? await readGrantType(request) : undefined;

		const response = await getProvider(env).fetch(request, env, ctx);

		if (pathname === "/token") {
			return reauthorizeInsteadOfFailing(response, grantType);
		}

		if (!pathname.startsWith("/.well-known/oauth-authorization-server") || !response.ok) {
			return response;
		}

		const metadata = (await response.json()) as Record<string, unknown>;
		delete metadata[ISS_CAPABILITY];

		const headers = new Headers(response.headers);
		headers.delete("Content-Length"); // the body just changed size
		return new Response(JSON.stringify(metadata), { status: response.status, headers });
	},
} satisfies ExportedHandler<Env>;

function text(message: string, status = 200): Response {
	return new Response(message, { status, headers: { "Content-Type": "text/plain" } });
}

const TXN_COOKIE = "wd_txn";

/** `Secure` is omitted on plain-http localhost so `wrangler dev` works. */
function txnCookie(id: string, url: URL, maxAge = 600): string {
	const secure = url.protocol === "https:" ? " Secure;" : "";
	return `${TXN_COOKIE}=${id}; Path=/; HttpOnly;${secure} SameSite=Lax; Max-Age=${maxAge}`;
}

function readCookie(request: Request, name: string): string | undefined {
	const header = request.headers.get("Cookie");
	if (!header) return undefined;

	for (const part of header.split(";")) {
		const [key, ...rest] = part.trim().split("=");
		if (key === name) return rest.join("=") || undefined;
	}
	return undefined;
}
