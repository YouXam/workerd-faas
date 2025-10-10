import makeD1Database from './d1-api';

export interface D1Env {
	D1: string | D1Database
}

/**
 * Get a D1 database instance for use in worker code
 *
 * @param env - The worker environment object containing the D1 hostname
 * @returns A D1Database instance
 *
 * @example
 * ```typescript
 * import { getD1 } from 'wrkst-d1/client';
 *
 * export default {
 *   async fetch(request: Request, env: any) {
 *     const db = getD1(env);
 *     const result = await db.prepare('SELECT * FROM users WHERE id = ?')
 *       .bind(1)
 *       .first();
 *     return new Response(JSON.stringify(result));
 *   }
 * }
 * ```
 */
export function getD1(env: D1Env): ReturnType<typeof makeD1Database> {
	if (!env.D1) {
		throw new Error(
			'D1 environment not found in environment. Make sure your FaaS platform supports D1.\n' +
				"If you're developing locally, ensure that you have a D1 database instance configured and its binding name is 'D1'."
		);
	}

	if (typeof env.D1 !== 'string') {
		return env.D1 as unknown as ReturnType<typeof makeD1Database>;
	}

	const fetcher = {
		fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
			let url: URL;
			if (typeof input === 'string') {
				url = new URL(input, `http://${env.D1}`);
			} else if (input instanceof URL) {
				url = new URL(input.toString());
			} else {
				url = new URL(input.url);
			}
			url.hostname = env.D1 as string;

			if (init) {
				return fetch(url, init);
			} else if (input instanceof Request) {
				return fetch(url, input);
			} else {
				return fetch(url);
			}
		},
	};

	return makeD1Database({ fetcher });
}

export default getD1;
