export interface OIDCConfig {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	userinfo_endpoint: string;
	client_id: string;
	client_secret: string;
	redirect_uri: string;
}

export function getOIDCConfig(env: Env): OIDCConfig {
	return {
		issuer: env.OIDC_ISSUER || '',
		authorization_endpoint: env.OIDC_AUTHORIZATION_ENDPOINT || '',
		token_endpoint: env.OIDC_TOKEN_ENDPOINT || '',
		userinfo_endpoint: env.OIDC_USERINFO_ENDPOINT || '',
		client_id: env.OIDC_CLIENT_ID || '',
		client_secret: env.OIDC_CLIENT_SECRET || '',
		redirect_uri: env.OIDC_REDIRECT_URI || '',
	};
}

export function validateOIDCConfig(config: OIDCConfig): boolean {
	return !!(
		config.issuer &&
		config.authorization_endpoint &&
		config.token_endpoint &&
		config.userinfo_endpoint &&
		config.client_id &&
		config.client_secret &&
		config.redirect_uri
	);
}

export async function exchangeCodeForToken(
	code: string,
	config: OIDCConfig
): Promise<{ access_token: string } | null> {
	try {
		const response = await fetch(config.token_endpoint, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: config.client_id,
				client_secret: config.client_secret,
				redirect_uri: config.redirect_uri,
			}),
		});

		if (!response.ok) {
			return null;
		}

		return await response.json();
	} catch (error) {
		return null;
	}
}

export async function getUserInfo(
	accessToken: string,
	config: OIDCConfig
): Promise<{ sub: string; name?: string; email?: string; preferred_username?: string } | null> {
	try {
		const response = await fetch(config.userinfo_endpoint, {
			headers: {
				Authorization: `Bearer ${accessToken}`,
			},
		});

		if (!response.ok) {
			return null;
		}

		return await response.json();
	} catch (error) {
		return null;
	}
}
