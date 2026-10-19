/**
 * Calls into Workday Agent Gateway with the signed-in user's token.
 *
 * Two headers matter: the bearer token, and wd-agent-tenant-alias — the tenant
 * alias travels in a header here, unlike the OAuth endpoints where it is part of
 * the URL path.
 *
 * Results are scoped by Workday to whoever signed in (employee as self), so
 * there is no filtering to do on this side.
 */

export class WorkdayApiError extends Error {
	constructor(
		message: string,
		readonly status?: number,
		readonly detail?: string,
	) {
		super(message);
		this.name = "WorkdayApiError";
	}
}

type QueryValue = string | number | undefined;

/** GET against Agent Gateway. `path` starts with "/" and is already encoded. */
export async function agentGet(
	env: Env,
	accessToken: string,
	path: string,
	params: Record<string, QueryValue> = {},
): Promise<unknown> {
	const url = new URL(`https://${env.WORKDAY_REGION_HOST}${path}`);
	for (const [key, value] of Object.entries(params)) {
		if (value !== undefined) url.searchParams.set(key, String(value));
	}

	let response: Response;
	try {
		response = await fetch(url.toString(), {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				"wd-agent-tenant-alias": env.WORKDAY_TENANT_ALIAS,
				Accept: "application/json",
			},
		});
	} catch (cause) {
		throw new WorkdayApiError(
			`Could not reach Workday at ${url.origin}.`,
			undefined,
			cause instanceof Error ? cause.message : String(cause),
		);
	}

	const body = await response.text();

	// The token outlives Claude's own token, so a 401 here means re-auth rather
	// than anything the model can fix by retrying.
	if (response.status === 401 || response.status === 403) {
		throw new WorkdayApiError(
			`Workday rejected the token (HTTP ${response.status}). Ask the user to ` +
				"reconnect the Workday connector to sign in again.",
			response.status,
			body,
		);
	}

	if (!response.ok) {
		throw new WorkdayApiError(
			`Workday returned HTTP ${response.status} for ${path}.`,
			response.status,
			body,
		);
	}

	if (body.length === 0) return null;

	try {
		return JSON.parse(body);
	} catch {
		throw new WorkdayApiError(
			`Workday returned a non-JSON response for ${path}.`,
			response.status,
			body,
		);
	}
}

/** Percent-encodes a Workday ID for use as a URL path segment. */
export function segment(id: string): string {
	return encodeURIComponent(id);
}

/**
 * Trims a worker list down to the fields worth putting in front of the model.
 *
 * Workday returns `{ data: [...], total }`, where `total` is the full match count
 * rather than the number returned — so a capped search can report how much it did
 * not show. Each worker also carries an `href` that just repeats `id` against a
 * different host; that goes.
 *
 * An unrecognised payload passes through untouched. The direct-reports response
 * is assumed to share this shape but has not been seen, so it must degrade to raw
 * JSON rather than silently emptying itself.
 */
export function shapeWorkerList(payload: unknown): unknown {
	if (!isRecord(payload) || !Array.isArray(payload.data)) return payload;

	return compact({
		workers: payload.data.map(shapeWorker),
		shown: payload.data.length,
		total: typeof payload.total === "number" ? payload.total : undefined,
	});
}

function shapeWorker(item: unknown): unknown {
	if (!isRecord(item)) return item;

	const org = isRecord(item.primarySupervisoryOrganization)
		? item.primarySupervisoryOrganization
		: undefined;

	return compact({
		// The identifier every other worker call needs.
		id: item.id,
		name: item.descriptor,
		businessTitle: item.businessTitle,
		email: item.primaryWorkEmail,
		phone: item.primaryWorkPhone,
		organization: org?.descriptor,
		isManager: item.isManager,
	});
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Drops absent keys so a sparse worker record does not render as a wall of nulls. */
function compact(record: Record<string, unknown>): Record<string, unknown> {
	return Object.fromEntries(
		Object.entries(record).filter(([, value]) => value !== undefined && value !== null),
	);
}
