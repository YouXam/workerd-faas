import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { D1DatabaseObject } from './database';
import makeD1Database from './shared/d1-api';
export { D1DatabaseObject };

const metadataSchema = z.object({
	main_module: z.string(),
	compatibility_date: z.string().optional(),
	compatibility_flags: z.array(z.string()).optional(),
	bindings: z.array(z.object({
		name: z.string(),
		text: z.string(),
	})).optional().default([]),
});

const deploymentSchema = z.object({
	strategy: z.literal('percentage'),
	versions: z.array(z.object({
		percentage: z.number().min(0).max(100),
		version_id: z.string().uuid(),
	})).min(1).max(1).refine(versions => versions[0].percentage === 100, {
		message: "Currently only 100% deployment is supported"
	}),
});

const aliasSchema = z.object({
	version_id: z.string().uuid(),
});

async function initializeDatabase(d1: any) {
	await d1.exec('CREATE TABLE IF NOT EXISTS functions (name TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');

	await d1.exec('CREATE TABLE IF NOT EXISTS versions (id TEXT PRIMARY KEY, function_name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (function_name) REFERENCES functions(name))');

	await d1.exec('CREATE TABLE IF NOT EXISTS aliases (function_name TEXT NOT NULL, alias_name TEXT NOT NULL, version_id TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (function_name, alias_name), FOREIGN KEY (function_name) REFERENCES functions(name), FOREIGN KEY (version_id) REFERENCES versions(id))');

}

function createApiResponse(result: any, success: boolean = true, errors: any[] = [], messages: any[] = []) {
	return {
		errors,
		messages,
		result,
		success,
	};
}

async function saveFileToPath(FILES: any, path: string, content: string) {
	await FILES.fetch(`http://dummy/${path}`, {
		method: 'PUT',
		body: content,
	});
}

async function loadFileFromPath(FILES: any, path: string): Promise<string | null> {
	const res = await FILES.fetch(`http://dummy/${path}`);
	if (!res.ok) return null;
	return await res.text();
}

async function listDirectory(FILES: any, path: string): Promise<{name: string, type: string}[]> {
	const res = await FILES.fetch(`http://dummy/${path}`);
	if (!res.ok) return [];
	return await res.json();
}

async function getWorkerFromCache(LOADER: any, functionName: string, versionId: string, FILES: any): Promise<any> {
	const cacheKey = `${functionName}-${versionId}`;

	return LOADER.get(cacheKey, async () => {
		const metadataPath = `${functionName}/${versionId}/metadata.json`;
		const metadataContent = await loadFileFromPath(FILES, metadataPath);

		if (!metadataContent) {
			throw new Error(`Metadata not found for ${functionName}@${versionId}`);
		}

		const metadata = JSON.parse(metadataContent);
		const files = await listDirectory(FILES, `${functionName}/${versionId}/`);

		const modules: Record<string, string> = {};

		for (const file of files) {
			if (file.type === 'file' && file.name !== 'metadata.json') {
				const content = await loadFileFromPath(FILES, `${functionName}/${versionId}/${file.name}`);
				if (content) {
					modules[file.name] = content;
				}
			}
		}

		const env: Record<string, string> = {};
		if (metadata.bindings) {
			for (const binding of metadata.bindings) {
				env[binding.name] = binding.text;
			}
		}

		return {
			compatibilityDate: metadata.compatibility_date || '2025-01-01',
			compatibility_flags: metadata.compatibility_flags || [],
			mainModule: metadata.main_module,
			modules,
			env,
		};
	});
}

async function resolveFunction(hostname: string, baseDomain: string, d1: any): Promise<{functionName: string, versionId: string} | null> {
	if (!hostname.endsWith(baseDomain)) {
		return null;
	}

	const subdomain = hostname.slice(0, -(baseDomain.length + 1));

	if (subdomain.includes('.')) {
		const parts = subdomain.split('.');
		if (parts.length === 2) {
			const [versionPrefix, functionName] = parts;

			const { results } = await d1.prepare(`
				SELECT id FROM versions
				WHERE function_name = ? AND id LIKE ?
			`).bind(functionName, `${versionPrefix}%`).all();

			if (results.length > 0) {
				return { functionName, versionId: results[0].id };
			}
		}

		const [aliasName, functionName] = parts;
		if (functionName) {
			const { results } = await d1.prepare(`
				SELECT version_id FROM aliases
				WHERE function_name = ? AND alias_name = ?
			`).bind(functionName, aliasName).all();

			if (results.length > 0) {
				return { functionName, versionId: results[0].version_id };
			}
		}
	} else {
		const functionName = subdomain;

		const { results } = await d1.prepare(`
			SELECT version_id FROM aliases
			WHERE function_name = ? AND alias_name = 'latest'
		`).bind(functionName).all();

		if (results.length > 0) {
			return { functionName, versionId: results[0].version_id };
		}

	}

	return null;
}

const managementApp = new Hono<{ Bindings: Env }>()
	.get('/health', async (c) => {
		return c.json({
			status: 'healthy',
			timestamp: Date.now(),
			service: 'FaaS Platform'
		});
	})
	.put('/accounts/:account_id/workers/scripts/:script_name', async (c) => {
		const { script_name } = c.req.param();
		const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });

		await initializeDatabase(d1);

		try {
			const formData = await c.req.formData();
			const metadataString = formData.get('metadata') as string;

			if (!metadataString) {
				return c.json(createApiResponse(null, false, [{
					code: 1001,
					message: 'Missing metadata in form data'
				}]), 400);
			}

			const metadata = metadataSchema.parse(JSON.parse(metadataString));
			const versionId = crypto.randomUUID();

			await d1.prepare(`
				INSERT OR IGNORE INTO functions (name) VALUES (?)
			`).bind(script_name).run();

			await d1.prepare(`
				INSERT INTO versions (id, function_name) VALUES (?, ?)
			`).bind(versionId, script_name).run();

			await saveFileToPath(c.env.FILES, `${script_name}/${versionId}/metadata.json`, JSON.stringify(metadata));

			for (const [key, value] of formData.entries()) {
				if (key !== 'metadata') {
					const fileContent = typeof value === 'string' ? value : await value.text();
					await saveFileToPath(c.env.FILES, `${script_name}/${versionId}/${key}`, fileContent);
				}
			}

			return c.json(createApiResponse({ id: versionId }));
		} catch (error) {
			return c.json(createApiResponse(null, false, [{
				code: 1002,
				message: error instanceof Error ? error.message : 'Unknown error'
			}]), 400);
		}
	})
	.post('/accounts/:account_id/workers/scripts/:script_name/deployments',
		zValidator('json', deploymentSchema),
		async (c) => {
			const { script_name } = c.req.param();
			const body = c.req.valid('json');
			const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });

			try {
				const versionId = body.versions[0].version_id;

				const { results } = await d1.prepare(`
					SELECT id FROM versions WHERE id = ? AND function_name = ?
				`).bind(versionId, script_name).all();

				if (results.length === 0) {
					return c.json(createApiResponse(null, false, [{
						code: 1003,
						message: 'Version not found'
					}]), 404);
				}

				await d1.prepare(`
					INSERT OR REPLACE INTO aliases (function_name, alias_name, version_id) VALUES (?, 'latest', ?)
				`).bind(script_name, versionId).run();

				return c.json(createApiResponse({
					id: versionId,
					created_on: new Date().toISOString(),
					strategy: 'percentage',
					source: 'api',
					versions: body.versions
				}));
			} catch (error) {
				return c.json(createApiResponse(null, false, [{
					code: 1004,
					message: error instanceof Error ? error.message : 'Unknown error'
				}]), 400);
			}
		}
	)
	.put('/accounts/:account_id/workers/scripts/:script_name/aliases/:alias_name',
		zValidator('json', aliasSchema),
		async (c) => {
			const { script_name, alias_name } = c.req.param();
			const body = c.req.valid('json');
			const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });

			try {
				const { results } = await d1.prepare(`
					SELECT id FROM versions WHERE id = ? AND function_name = ?
				`).bind(body.version_id, script_name).all();

				if (results.length === 0) {
					return c.json(createApiResponse(null, false, [{
						code: 1005,
						message: 'Version not found'
					}]), 404);
				}

				await d1.prepare(`
					INSERT OR REPLACE INTO aliases (function_name, alias_name, version_id) VALUES (?, ?, ?)
				`).bind(script_name, alias_name, body.version_id).run();

				return c.json(createApiResponse({}));
			} catch (error) {
				return c.json(createApiResponse(null, false, [{
					code: 1006,
					message: error instanceof Error ? error.message : 'Unknown error'
				}]), 400);
			}
		}
	)
	.get('/accounts/:account_id/workers/scripts/:script_name/versions', async (c) => {
		const { script_name } = c.req.param();
		const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });
		
		try {
			const { results } = await d1.prepare(`
				SELECT id, created_at FROM versions 
				WHERE function_name = ?
				ORDER BY created_at DESC
			`).bind(script_name).all();
			
			const versions = results.map((row: any) => ({
				id: row.id,
				created_on: row.created_at
			}));
			
			return c.json(createApiResponse(versions));
		} catch (error) {
			return c.json(createApiResponse(null, false, [{
				code: 1011,
				message: error instanceof Error ? error.message : 'Unknown error'
			}]), 400);
		}
	})
	.get('/accounts/:account_id/workers/scripts/:script_name/aliases', async (c) => {
		const { script_name } = c.req.param();
		const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });
		
		try {
			const { results } = await d1.prepare(`
				SELECT alias_name, version_id, created_at FROM aliases 
				WHERE function_name = ?
				ORDER BY created_at DESC
			`).bind(script_name).all();
			
			const aliases = results.map((row: any) => ({
				name: row.alias_name,
				version_id: row.version_id,
				created_on: row.created_at
			}));
			
			return c.json(createApiResponse(aliases));
		} catch (error) {
			return c.json(createApiResponse(null, false, [{
				code: 1012,
				message: error instanceof Error ? error.message : 'Unknown error'
			}]), 400);
		}
	})
	.all('*', async (c) => {
		return c.json(createApiResponse(null, false, [{
			code: 1007,
			message: 'Not found'
		}]), 404);
	});

const app = new Hono<{ Bindings: Env }>()
	.all('*', async (c) => {
		const hostname = c.req.header('host') || '';
		const baseDomain = c.env.BASE_DOMAIN;

		if (!baseDomain) {
			return c.json(createApiResponse(null, false, [{
				code: 1010,
				message: 'BASE_DOMAIN not configured'
			}]), 500);
		}

		if (hostname === baseDomain) {
			return managementApp.fetch(c.req.raw, c.env);
		}

		if (!hostname.endsWith(baseDomain)) {
			return c.json(createApiResponse(null, false, [{
				code: 1007,
				message: 'Not found'
			}]), 404);
		}

		const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });
		await initializeDatabase(d1);

		const resolved = await resolveFunction(hostname, baseDomain, d1);

		if (!resolved) {
			return c.json(createApiResponse(null, false, [{
				code: 1008,
				message: 'Function not found'
			}]), 404);
		}

		try {
			const worker = await getWorkerFromCache(c.env.LOADER, resolved.functionName, resolved.versionId, c.env.FILES);
			const workerInstance = await worker.getEntrypoint();
			return await workerInstance.fetch(c.req.raw);
		} catch (error) {
			return c.json(createApiResponse(null, false, [{
				code: 1009,
				message: error instanceof Error ? error.message : 'Worker execution failed'
			}]), 500);
		}
	});

export default {
	fetch: app.fetch,
} satisfies ExportedHandler<Env>;
