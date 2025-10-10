export { D1DatabaseObject } from './database';

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		try {
			const hostname = new URL(request.url).hostname;
			if (!hostname.endsWith('.d1.worker')) {
				return fetch(request);
			}
			const uuid = hostname.slice(0, hostname.length - '.d1.worker'.length)!;
			const d1Fetcher = env.D1DatabaseObject.getByName(uuid);
			return await d1Fetcher.fetch(request);
		} catch (error) {
			return new Response(JSON.stringify({
				success: false,
				error: error instanceof Error ? error.message : 'D1 Gateway: Unknown error'
			}), {
				status: 500,
				headers: { 'Content-Type': 'application/json' }
			});
		}
	}
} satisfies ExportedHandler<Env>;
