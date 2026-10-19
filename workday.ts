/**
 * The Workday half of the login, shared by both entry paths.
 *
 * Two ways in, one way out:
 *
 *   /authorize  Claude starts it (auto-popup). The pending request is parked in
 *               KV under its own id, and the callback finishes Claude's
 *               authorization with it.
 *   /login      You start it by hand (demo fallback). Nothing is parked, so the
 *               callback stores the token under a fixed key instead.
 *
 * The callback tells them apart by whether the browser carried a parked-request
 * cookie back from Workday.
 *
 * Single-user demo: one fallback token, shared by everyone who reaches /mcp.
 */

import type { AuthRequest } from "@cloudflare/workers-oauth-provider";

const TOKEN_KEY = "workday_token";
const PENDING_KEY = "pending_auth";

/**
 * Every grant is issued to this one user.
 *
 * There is no user database here — Workday decides who the token belongs to, and
 * this side only needs a stable key to file grants under. Shared so that sign-out
 * revokes grants under the same id that /workday/callback creates them with.
 */
export const DEMO_USER_ID = "demo-user";

export interface StoredToken {
	accessToken: string;
	/** Epoch ms, or undefined if Workday omitted expires_in. */
	expiresAt?: number;
	/**
	 * Workday's refresh token. Confirmed issued by this tenant's API client
	 * alongside a 4-hour access token.
	 *
	 * Optional because tokens stored before refresh support existed do not have
	 * one. Those simply cannot be renewed, and fall back to interactive re-auth.
	 */
	refreshToken?: string;
}

/**
 * Longest Claude access token we will issue, in seconds.
 *
 * Exported because the refresh margin below is derived from it, and the two must
 * not drift: see REFRESH_MARGIN_MS.
 */
export const MAX_ACCESS_TOKEN_TTL_SECONDS = 3600;

/**
 * Lifetime assumed when Workday's response omits `expires_in`.
 *
 * An unknown expiry must never read as "valid forever". That mistake is
 * self-concealing: the token is treated as live long after Workday has stopped
 * honouring it, needsRefresh stays false so it is never renewed, and
 * workday_auth_status cheerfully reports a working session while every API call
 * fails. One hour matches the longest Claude token we issue, so a wrong guess
 * corrects itself on the next exchange instead of persisting.
 *
 * The authorization_code grant is known to return expires_in (14400). Whether
 * the refresh grant does is unconfirmed, which is exactly why this exists.
 */
const ASSUMED_TOKEN_LIFETIME_SECONDS = 3600;

/**
 * Renew the Workday token when it has less than this long to live.
 *
 * This MUST exceed MAX_ACCESS_TOKEN_TTL_SECONDS, and that is the whole point.
 * The invariant being protected is that every Claude token we hand out is fully
 * covered by the Workday token behind it. A margin shorter than the token we
 * issue breaks it: with a 30-minute margin, a token minted when Workday had 59
 * minutes left would be valid for an hour and spend its last minute wrapping a
 * dead Workday token — failing against Workday instead of returning a 401 here,
 * which is precisely the bug refresh was meant to eliminate.
 *
 * The extra five minutes absorb clock skew and the round trip itself.
 */
const REFRESH_MARGIN_MS = (MAX_ACCESS_TOKEN_TTL_SECONDS + 300) * 1000;

/**
 * An absent expiry means "renew it", not "keep it". Only tokens stored before
 * postToken started defaulting the lifetime can reach here undefined, and the
 * safe reading of an unknown expiry is that it has already lapsed.
 */
export function needsRefresh(token: StoredToken): boolean {
	if (token.expiresAt === undefined) return true;
	return token.expiresAt - Date.now() < REFRESH_MARGIN_MS;
}

/** Seconds of Workday token life left, floored at 0; 0 when the expiry is unknown. */
export function secondsRemaining(token: StoredToken): number {
	if (token.expiresAt === undefined) return 0;
	return Math.max(0, Math.floor((token.expiresAt - Date.now()) / 1000));
}

/** Where the browser goes to log in. Only these two params are documented. */
export function authorizeUrl(env: Env): string {
	const url = new URL(
		`https://${env.WORKDAY_REGION_HOST}/auth/authorize/${env.WORKDAY_TENANT_ALIAS}`,
	);
	url.searchParams.set("client_id", env.WORKDAY_CLIENT_ID);
	url.searchParams.set("response_type", "code");
	return url.toString();
}

/**
 * Posts to Workday's token endpoint. Workday has no PKCE, so the client secret
 * is what protects this — which is why it happens here and not in Claude.
 *
 * `carriedRefreshToken` is kept when Workday's response omits one. A refresh
 * grant is not required to reissue a refresh token, and dropping it on that
 * response would silently end the chain: renewal would work exactly once and
 * then fall back to an interactive sign-in.
 */
async function postToken(
	env: Env,
	form: Record<string, string>,
	carriedRefreshToken?: string,
): Promise<StoredToken> {
	const response = await fetch(
		`https://${env.WORKDAY_REGION_HOST}/auth/oauth2/${env.WORKDAY_TENANT_ALIAS}/token`,
		{
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				...form,
				client_id: env.WORKDAY_CLIENT_ID,
				client_secret: env.WORKDAY_CLIENT_SECRET,
			}),
		},
	);

	const body = await response.text();
	if (!response.ok) {
		throw new Error(
			`Workday ${form.grant_type} failed (HTTP ${response.status}):\n${body}`,
		);
	}

	const parsed = JSON.parse(body);
	if (typeof parsed.access_token !== "string") {
		throw new Error(`No access_token in Workday's response:\n${body}`);
	}

	// Field NAMES and lifetimes only, never a token value. This is what told us
	// the tenant issues refresh tokens at all; keep it so a change in Workday's
	// response shape shows up in the log instead of as a silent regression.
	console.log(
		`workday/token: grant=${form.grant_type} fields=` +
			Object.keys(parsed).sort().join(",") +
			` refresh_token=${typeof parsed.refresh_token === "string" ? "PRESENT" : "absent"}` +
			` expires_in=${parsed.expires_in ?? "-"}` +
			` token_type=${parsed.token_type ?? "-"}`,
	);

	const knownLifetime = typeof parsed.expires_in === "number";
	if (!knownLifetime) {
		console.log(
			`workday/token: grant=${form.grant_type} omitted expires_in; ` +
				`assuming ${ASSUMED_TOKEN_LIFETIME_SECONDS}s so it is renewed rather than trusted`,
		);
	}

	return {
		accessToken: parsed.access_token,
		expiresAt:
			Date.now() +
			(knownLifetime ? parsed.expires_in : ASSUMED_TOKEN_LIFETIME_SECONDS) * 1000,
		refreshToken:
			typeof parsed.refresh_token === "string" ? parsed.refresh_token : carriedRefreshToken,
	};
}

/** Swaps the authorization code for a user-scoped token. */
export function exchangeCode(env: Env, code: string): Promise<StoredToken> {
	return postToken(env, { grant_type: "authorization_code", code });
}

/**
 * Renews a Workday token without the user present.
 *
 * This is the whole reason expiry no longer costs a browser round trip.
 */
export function refreshToken(env: Env, refreshTokenValue: string): Promise<StoredToken> {
	return postToken(
		env,
		{ grant_type: "refresh_token", refresh_token: refreshTokenValue },
		refreshTokenValue,
	);
}

// ---- Fallback token (the /login path) --------------------------------------

export async function saveToken(env: Env, token: StoredToken): Promise<void> {
	// Let KV expire it alongside the token itself when we know the lifetime.
	const ttl = token.expiresAt
		? Math.max(60, Math.floor((token.expiresAt - Date.now()) / 1000))
		: undefined;

	await env.OAUTH_KV.put(TOKEN_KEY, JSON.stringify(token), { expirationTtl: ttl });
}

export async function loadToken(env: Env): Promise<StoredToken | undefined> {
	const stored = await env.OAUTH_KV.get(TOKEN_KEY);
	if (!stored) return undefined;

	const token = JSON.parse(stored) as StoredToken;
	if (token.expiresAt !== undefined && token.expiresAt <= Date.now()) return undefined;
	return token;
}

/**
 * Drops the manual token.
 *
 * Sign-out has to clear this as well as the grant. Leaving it behind would let
 * every tool quietly fall back to it, so nothing would 401 and no re-auth prompt
 * would ever appear.
 */
export async function clearToken(env: Env): Promise<void> {
	await env.OAUTH_KV.delete(TOKEN_KEY);
}

// ---- Parked authorization (the /authorize path) ----------------------------

/**
 * Parks one pending request under its own id.
 *
 * Not a fixed key: mcp-remote routinely runs two proxy instances, and both call
 * /authorize with their own state and PKCE challenge. Keeping them separate is
 * what lets the callback tell how many are outstanding and pick the newest,
 * rather than silently completing whichever wrote last.
 */
interface Parked {
	request: AuthRequest;
	/** Epoch ms, so the newest can be picked when the cookie is missing. */
	at: number;
}

export async function parkAuthRequest(env: Env, id: string, request: AuthRequest): Promise<void> {
	const parked: Parked = { request, at: Date.now() };
	await env.OAUTH_KV.put(`${PENDING_KEY}:${id}`, JSON.stringify(parked), {
		expirationTtl: 600,
	});
}

/**
 * Takes the most recent parked request, and clears the rest.
 *
 * "Newest wins" is not a fallback, it is the rule — see the callback in
 * index.ts. mcp-remote replaces its PKCE verifier on every retry, so only its
 * latest /authorize is still completable; an older parked request can never be
 * finished and must never be able to satisfy a callback.
 *
 * Single-user demo, so this is safe. Genuinely concurrent sign-ins by different
 * users would need per-browser correlation; that is the trade being made.
 */
export async function takeLatestAuthRequest(env: Env): Promise<AuthRequest | undefined> {
	const { keys } = await env.OAUTH_KV.list({ prefix: `${PENDING_KEY}:` });
	if (keys.length === 0) return undefined;

	const parked = await Promise.all(
		keys.map(async ({ name }) => {
			const stored = await env.OAUTH_KV.get(name);
			return stored ? (JSON.parse(stored) as Parked) : undefined;
		}),
	);

	await Promise.all(keys.map(({ name }) => env.OAUTH_KV.delete(name)));

	return parked
		.filter((entry): entry is Parked => entry !== undefined)
		.sort((a, b) => b.at - a.at)[0]?.request;
}
