import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

declare global {
	interface Env {
		/** OAuth state plus the manual /login token. Name fixed by the OAuth library. */
		OAUTH_KV: KVNamespace;
		/** Injected by the OAuth library before it calls our handlers. */
		OAUTH_PROVIDER: OAuthHelpers;

		/** e.g. "us.agent.workday.com" */
		WORKDAY_REGION_HOST: string;
		/** From https://wd8.myworkday.com/<tenantalias>/d/home.html */
		WORKDAY_TENANT_ALIAS: string;
		WORKDAY_CLIENT_ID: string;
		WORKDAY_CLIENT_SECRET: string;
	}
}

export {};
