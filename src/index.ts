import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { D1DatabaseObject } from './database';
import makeD1Database from './shared/d1-api';
import { authenticateUser, generateToken, generateAuthCode, consumeAuthCode, generateOIDCState, validateOIDCState, UserPayload } from './auth';
import { getOIDCConfig, validateOIDCConfig, exchangeCodeForToken, getUserInfo } from './oidc';
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
	await d1.exec('CREATE TABLE IF NOT EXISTS users (account_id TEXT PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');

	await d1.exec('CREATE TABLE IF NOT EXISTS functions (name TEXT PRIMARY KEY, owner_account_id TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');

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
	.get('/oauth2/auth', async (c) => {
		const oidcConfig = getOIDCConfig(c.env);
		if (!validateOIDCConfig(oidcConfig)) {
			return c.json(createApiResponse(null, false, [{
				code: 2001,
				message: 'OIDC not configured'
			}]), 500);
		}

		const state = generateOIDCState();
		const authUrl = new URL(oidcConfig.authorization_endpoint);
		authUrl.searchParams.set('client_id', oidcConfig.client_id);
		authUrl.searchParams.set('redirect_uri', oidcConfig.redirect_uri);
		authUrl.searchParams.set('response_type', 'code');
		authUrl.searchParams.set('scope', 'openid profile email');
		authUrl.searchParams.set('state', state);

		return c.redirect(authUrl.toString());
	})
	.get('/auth/callback', async (c) => {
		const code = c.req.query('code');
		const state = c.req.query('state');

		if (!code || !state) {
			return c.json(createApiResponse(null, false, [{
				code: 2002,
				message: 'Missing code or state'
			}]), 400);
		}

		if (!validateOIDCState(state)) {
			return c.json(createApiResponse(null, false, [{
				code: 2003,
				message: 'Invalid state'
			}]), 400);
		}

		const oidcConfig = getOIDCConfig(c.env);
		const tokenResponse = await exchangeCodeForToken(code, oidcConfig);
		if (!tokenResponse) {
			return c.json(createApiResponse(null, false, [{
				code: 2004,
				message: 'Failed to exchange code for token'
			}]), 400);
		}

		const userInfo = await getUserInfo(tokenResponse.access_token, oidcConfig);
		if (!userInfo) {
			return c.json(createApiResponse(null, false, [{
				code: 2005,
				message: 'Failed to get user info'
			}]), 400);
		}

		const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });
		await initializeDatabase(d1);

		const { results } = await d1.prepare(`
			SELECT account_id, username, email FROM users WHERE email = ?
		`).bind(userInfo.email).all();

		let user: UserPayload;
		if (results.length === 0) {
			const accountId = crypto.randomUUID();
			const username = userInfo.preferred_username || userInfo.name || userInfo.email?.split('@')[0] || 'user';
			const email = userInfo.email || '';

			await d1.prepare(`
				INSERT INTO users (account_id, username, email) VALUES (?, ?, ?)
			`).bind(accountId, username, email).run();

			user = { account_id: accountId, username, email };
		} else {
			const row = results[0] as any;
			user = {
				account_id: row.account_id,
				username: row.username,
				email: row.email,
			};
		}

		const authCode = generateAuthCode(user);
		return c.redirect(`http://localhost:8976/oauth/callback?code=${authCode}`);
	})
	.post('/oauth2/token', async (c) => {
		const body = await c.req.parseBody();
		const code = body.code as string;

		if (!code) {
			return c.json({
				error: 'invalid_request',
				error_description: 'Missing code parameter'
			}, 400);
		}

		const user = consumeAuthCode(code);
		if (!user) {
			return c.json({
				error: 'invalid_grant',
				error_description: 'Invalid or expired authorization code'
			}, 400);
		}

		const jwtSecret = c.env.JWT_SECRET;
		if (!jwtSecret) {
			return c.json({
				error: 'server_error',
				error_description: 'JWT_SECRET not configured'
			}, 500);
		}

		const accessToken = await generateToken(user, jwtSecret);
		return c.json({
			access_token: accessToken,
			token_type: 'Bearer',
			expires_in: 31536000, // 1 year in seconds
		});
	})
	.put('/accounts/:account_id/workers/scripts/:script_name', async (c) => {
		const user = await authenticateUser(c);
		if (!user) {
			return c.json(createApiResponse(null, false, [{
				code: 2006,
				message: 'Unauthorized'
			}]), 401);
		}

		const { account_id, script_name } = c.req.param();
		if (account_id !== user.account_id) {
			return c.json(createApiResponse(null, false, [{
				code: 2007,
				message: 'Forbidden'
			}]), 403);
		}

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

			const { results: existingFunction } = await d1.prepare(`
				SELECT owner_account_id FROM functions WHERE name = ?
			`).bind(script_name).all();

			if (existingFunction.length > 0) {
				const funcRow = existingFunction[0] as any;
				if (funcRow.owner_account_id !== user.account_id) {
					return c.json(createApiResponse(null, false, [{
						code: 2007,
						message: 'Forbidden'
					}]), 403);
				}
			} else {
				await d1.prepare(`
					INSERT INTO functions (name, owner_account_id) VALUES (?, ?)
				`).bind(script_name, user.account_id).run();
			}

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
			const user = await authenticateUser(c);
			if (!user) {
				return c.json(createApiResponse(null, false, [{
					code: 2006,
					message: 'Unauthorized'
				}]), 401);
			}

			const { account_id, script_name } = c.req.param();
			if (account_id !== user.account_id) {
				return c.json(createApiResponse(null, false, [{
					code: 2007,
					message: 'Forbidden'
				}]), 403);
			}

			const body = c.req.valid('json');
			const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });

			try {
				const { results: functionCheck } = await d1.prepare(`
					SELECT owner_account_id FROM functions WHERE name = ?
				`).bind(script_name).all();

				if (functionCheck.length === 0) {
					return c.json(createApiResponse(null, false, [{
						code: 2007,
						message: 'Forbidden'
					}]), 403);
				}

				const funcRow = functionCheck[0] as any;
				if (funcRow.owner_account_id !== user.account_id) {
					return c.json(createApiResponse(null, false, [{
						code: 2007,
						message: 'Forbidden'
					}]), 403);
				}
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
			const user = await authenticateUser(c);
			if (!user) {
				return c.json(createApiResponse(null, false, [{
					code: 2006,
					message: 'Unauthorized'
				}]), 401);
			}

			const { account_id, script_name, alias_name } = c.req.param();
			if (account_id !== user.account_id) {
				return c.json(createApiResponse(null, false, [{
					code: 2007,
					message: 'Forbidden'
				}]), 403);
			}

			const body = c.req.valid('json');
			const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });

			try {
				const { results: functionCheck } = await d1.prepare(`
					SELECT owner_account_id FROM functions WHERE name = ?
				`).bind(script_name).all();

				if (functionCheck.length === 0) {
					return c.json(createApiResponse(null, false, [{
						code: 2007,
						message: 'Forbidden'
					}]), 403);
				}

				const funcRow = functionCheck[0] as any;
				if (funcRow.owner_account_id !== user.account_id) {
					return c.json(createApiResponse(null, false, [{
						code: 2007,
						message: 'Forbidden'
					}]), 403);
				}
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
		const user = await authenticateUser(c);
		if (!user) {
			return c.json(createApiResponse(null, false, [{
				code: 2006,
				message: 'Unauthorized'
			}]), 401);
		}

		const { account_id, script_name } = c.req.param();
		if (account_id !== user.account_id) {
			return c.json(createApiResponse(null, false, [{
				code: 2007,
				message: 'Forbidden'
			}]), 403);
		}

		const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });

		try {
			const { results: functionCheck } = await d1.prepare(`
				SELECT owner_account_id FROM functions WHERE name = ?
			`).bind(script_name).all();

			if (functionCheck.length === 0) {
				return c.json(createApiResponse(null, false, [{
					code: 2007,
					message: 'Forbidden'
				}]), 403);
			}

			const funcRow = functionCheck[0] as any;
			if (funcRow.owner_account_id !== user.account_id) {
				return c.json(createApiResponse(null, false, [{
					code: 2007,
					message: 'Forbidden'
				}]), 403);
			}
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
		const user = await authenticateUser(c);
		if (!user) {
			return c.json(createApiResponse(null, false, [{
				code: 2006,
				message: 'Unauthorized'
			}]), 401);
		}

		const { account_id, script_name } = c.req.param();
		if (account_id !== user.account_id) {
			return c.json(createApiResponse(null, false, [{
				code: 2007,
				message: 'Forbidden'
			}]), 403);
		}

		const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });

		try {
			const { results: functionCheck } = await d1.prepare(`
				SELECT owner_account_id FROM functions WHERE name = ?
			`).bind(script_name).all();

			if (functionCheck.length === 0) {
				return c.json(createApiResponse(null, false, [{
					code: 2007,
					message: 'Forbidden'
				}]), 403);
			}

			const funcRow = functionCheck[0] as any;
			if (funcRow.owner_account_id !== user.account_id) {
				return c.json(createApiResponse(null, false, [{
					code: 2007,
					message: 'Forbidden'
				}]), 403);
			}
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

		if (hostname === baseDomain || !hostname.endsWith(baseDomain)) {
			return managementApp.fetch(c.req.raw, c.env);
		}

		const d1 = makeD1Database({ fetcher: c.env.D1DatabaseObject.getByName('faas') });
		await initializeDatabase(d1);

		const resolved = await resolveFunction(hostname, baseDomain, d1);

		if (!resolved) {
			return managementApp.fetch(c.req.raw, c.env);
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
