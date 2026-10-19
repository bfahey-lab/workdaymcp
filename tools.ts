/**
 * MCP tools wrapping the "Get Worker Info" Workday skill.
 *
 * Tools take the token from the caller's OAuth grant when there is one, and fall
 * back to the manually stored /login token otherwise. That fallback is what
 * keeps the demo recoverable if the auto-popup misbehaves live.
 *
 * No tool takes an access token argument — the token comes from who signed in,
 * so a tool cannot be talked into using someone else's.
 */

import type { CallToolResult, McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { agentGet, segment, shapeWorkerList, WorkdayApiError } from "./api";
import {
	clearToken,
	DEMO_USER_ID,
	loadToken,
	secondsRemaining,
	type StoredToken,
} from "./workday";

type Source = "connector sign-in" | "manual /login";

interface Resolved {
	token: StoredToken;
	source: Source;
}

/** Grant token first, stored token second. Expired ones count as absent. */
async function resolveToken(env: Env, props?: StoredToken): Promise<Resolved | undefined> {
	// An unknown expiry counts as expired. Treating it as valid is how a dead
	// session gets reported as a working one.
	const live = (token?: StoredToken) =>
		token?.accessToken && token.expiresAt !== undefined && token.expiresAt > Date.now()
			? token
			: undefined;

	const granted = live(props);
	if (granted) return { token: granted, source: "connector sign-in" };

	const stored = live(await loadToken(env));
	return stored ? { token: stored, source: "manual /login" } : undefined;
}

/**
 * Ends the Workday session so the next tool call prompts a fresh sign-in.
 *
 * Revoking the grant deletes its access tokens, so the token Claude holds stops
 * resolving and its next request to this server gets a 401 — which is what
 * reopens the Workday login. Shared by workday_sign_out and by the recovery
 * below, because "Workday rejected this token" and "the user asked to sign out"
 * need exactly the same cleanup.
 */
async function endSession(env: Env): Promise<number> {
	const { items } = await env.OAUTH_PROVIDER.listUserGrants(DEMO_USER_ID);
	await Promise.all(items.map((grant) => env.OAUTH_PROVIDER.revokeGrant(grant.id, DEMO_USER_ID)));
	await clearToken(env);
	return items.length;
}

export function registerTools(
	server: McpServer,
	env: Env,
	origin: string,
	props?: StoredToken,
): void {
	/** Runs one Agent Gateway call and shapes both outcomes into a tool result. */
	const call = async (build: (accessToken: string) => Promise<unknown>) => {
		const resolved = await resolveToken(env, props);
		if (!resolved) return signedOut(origin);

		try {
			const data = shapeWorkerList(await build(resolved.token.accessToken));
			return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
		} catch (error) {
			// Workday rejecting the token is the one failure the user cannot act on
			// while the session still looks valid from here. Reporting it is not
			// enough: the grant stays good, so nothing ever offers a login and the
			// only way out is calling sign-out by hand. End the session instead, so
			// simply retrying prompts the sign-in.
			if (error instanceof WorkdayApiError && (error.status === 401 || error.status === 403)) {
				console.log(`workday api ${error.status}: ending session to force re-auth`);
				await endSession(env);

				return {
					content: [
						{
							type: "text" as const,
							text:
								"Workday rejected the saved credentials, so this session has been " +
								"signed out. Run the same request again and Claude will open the " +
								"Workday login first.",
						},
					],
					isError: true,
				};
			}

			return {
				content: [{ type: "text" as const, text: describe(error) }],
				isError: true,
			};
		}
	};

	server.registerTool(
		"workday_auth_status",
		{
			title: "Check Workday sign-in",
			description:
				"Reports whether there is a live Workday access token for this session, " +
				"which tenant it is scoped to, and when it expires. Use this to confirm the " +
				"connection works, or to explain why another Workday tool failed. Proves the " +
				"token by making one minimal Workday call, so a session Workday has already " +
				"invalidated is reported as signed out rather than as working. Never reveals " +
				"the token itself.",
			inputSchema: z.object({}),
			// Not read-only: a session Workday has already rejected is signed out
			// here, so retrying prompts a login.
			annotations: { readOnlyHint: false, openWorldHint: true },
		},
		async (): Promise<CallToolResult> => {
			const resolved = await resolveToken(env, props);
			if (!resolved) return signedOut(origin);

			// A stored expiry says when we expect the token to die, not whether Workday
			// still honours it. Those came apart overnight: the expiry looked healthy,
			// every real call failed, and this tool insisted all was well. One cheap
			// call is what makes the answer trustworthy.
			//
			// Only a 401/403 changes the verdict. Anything else — Workday down, a
			// rejected parameter, a network blip — says nothing about the token and
			// must not turn a healthy session into a scary answer.
			let inconclusive: string | undefined;

			try {
				await agentGet(env, resolved.token.accessToken, "/common/v1/workers", {
					limit: 1,
					offset: 0,
				});
			} catch (error) {
				if (error instanceof WorkdayApiError && (error.status === 401 || error.status === 403)) {
					console.log(`workday auth_status ${error.status}: ending session to force re-auth`);
					await endSession(env);

					return {
						content: [
							{
								type: "text",
								text: [
									"Not signed in to Workday.",
									"",
									`Workday rejected the saved credentials (HTTP ${error.status}), so this ` +
										"session has been signed out. Ask the user to run a Workday tool " +
										"and Claude will open the Workday login first.",
								].join("\n"),
							},
						],
						isError: true,
					};
				}

				// Not an auth failure, so the token may well be fine. Say so plainly
				// instead of signing anything out over it.
				inconclusive = describe(error);
			}

			const minutesLeft = Math.round(secondsRemaining(resolved.token) / 60);

			return {
				content: [
					{
						type: "text",
						text: [
							inconclusive
								? "Signed in to Workday, but the check call did not complete."
								: "Signed in to Workday, and verified with a live call.",
							`Tenant: ${env.WORKDAY_TENANT_ALIAS}`,
							`Region: ${env.WORKDAY_REGION_HOST}`,
							"Access: employee as self",
							`Expires in: ${minutesLeft} minutes`,
							`Token from: ${resolved.source}`,
							...(inconclusive
								? ["", `Workday did not answer the check: ${inconclusive}`]
								: []),
						].join("\n"),
					},
				],
			};
		},
	);

	server.registerTool(
		"workday_sign_out",
		{
			title: "Sign out of Workday",
			description:
				"Signs this session out of Workday so the login can be demonstrated again. " +
				"Revokes the connector's grant and discards any manually stored token, which " +
				"makes the next Workday tool call prompt for sign-in. Use only when the user " +
				"asks to sign out, disconnect, or reset the connection — never to recover " +
				"from an error, and never before another Workday tool as a precaution.",
			inputSchema: z.object({}),
			annotations: {
				readOnlyHint: false,
				destructiveHint: true,
				idempotentHint: true,
				openWorldHint: false,
			},
		},
		async (): Promise<CallToolResult> => {
			const revoked = await endSession(env);

			return {
				content: [
					{
						type: "text",
						text: [
							`Signed out of Workday. Grants revoked: ${revoked}.`,
							"",
							"The next Workday tool call will ask to sign in again. Tell the " +
								"user to run one when they are ready, rather than calling one " +
								"yourself to test it.",
						].join("\n"),
					},
				],
			};
		},
	);

	server.registerTool(
		"workday_search_workers",
		{
			title: "Search workers",
			description:
				"Searches Workday for workers by name. Each match returns `id` (the " +
				"Workday ID that workday_get_direct_reports needs), `name`, " +
				"`businessTitle`, `email`, `phone`, `organization`, and `isManager`. " +
				"Start here whenever you have a name rather than an ID. `total` is how " +
				"many workers matched overall, which can exceed the number returned — say " +
				"so rather than implying the list is complete. Results are limited to " +
				"workers the signed-in user may see. If several people match, show the " +
				"user the options instead of picking one yourself.",
			inputSchema: z.object({
				search: z
					.string()
					.min(1)
					.describe(
						'Name to search for, e.g. "Logan" or "Logan McNeil". Spaces and ' +
							"punctuation are fine. Pass what the user said rather than guessing " +
							"at a fuller name.",
					),
				limit: z
					.number()
					.int()
					.min(1)
					.max(20)
					.optional()
					.describe(
						"Maximum matches to return, 1-20. Defaults to 20. Lower it only when " +
							"you already know the search names one specific person.",
					),
			}),
			annotations: { readOnlyHint: true, openWorldHint: true },
		},
		async ({ search, limit }) =>
			call((accessToken) =>
				agentGet(env, accessToken, "/common/v1/workers", {
					limit: limit ?? 20,
					offset: 0,
					search,
				}),
			),
	);

	server.registerTool(
		"workday_get_direct_reports",
		{
			title: "Get direct reports",
			description:
				"Lists the people reporting directly to a worker. Needs that worker's " +
				"Workday ID, which comes from the `id` field of workday_search_workers — " +
				"call that first if you only have a name. Returns direct reports only, not " +
				"the whole org beneath them; to go deeper, call this again on a report's " +
				"own id. A worker whose `isManager` is false has no reports, so there is " +
				"no need to call this for them.",
			inputSchema: z.object({
				workerId: z
					.string()
					.min(1)
					.describe(
						"The worker's Workday ID, exactly as returned by " +
							"workday_search_workers. Not a name, email or employee number.",
					),
			}),
			annotations: { readOnlyHint: true, openWorldHint: true },
		},
		async ({ workerId }) =>
			call((accessToken) =>
				agentGet(
					env,
					accessToken,
					`/common/v1/workers/${segment(workerId)}/directReports`,
					{ limit: 99 },
				),
			),
	);
}

/** Shared by every tool that needs a token, so the wording stays consistent. */
export function signedOut(origin: string): CallToolResult {
	return {
		content: [
			{
				type: "text",
				text:
					"Not signed in to Workday. Ask the user to reconnect the Workday " +
					"connector in Claude, which opens the Workday login. If that does not " +
					`work, they can sign in manually at ${origin}/login and try again.`,
			},
		],
		isError: true,
	};
}

function describe(error: unknown): string {
	if (error instanceof WorkdayApiError) {
		return error.detail ? `${error.message}\n\n${error.detail}` : error.message;
	}
	return error instanceof Error ? error.message : String(error);
}
