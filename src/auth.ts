import { SignJWT, jwtVerify } from 'jose';
import { Context } from 'hono';

export interface UserPayload {
	account_id: string;
	username: string;
	email: string;
}

export interface JWTPayload extends UserPayload {
	iat: number;
	exp: number;
}

export async function generateToken(user: UserPayload, secret: string): Promise<string> {
	const encoder = new TextEncoder();
	const secretKey = encoder.encode(secret);

	return await new SignJWT({
		account_id: user.account_id,
		username: user.username,
		email: user.email,
	})
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuedAt()
		.setExpirationTime('365d')
		.sign(secretKey);
}

export async function verifyToken(token: string, secret: string): Promise<JWTPayload | null> {
	try {
		const encoder = new TextEncoder();
		const secretKey = encoder.encode(secret);

		const { payload } = await jwtVerify(token, secretKey);

		// Validate payload has required fields
		if (
			typeof payload.account_id === 'string' &&
			typeof payload.username === 'string' &&
			typeof payload.email === 'string' &&
			typeof payload.iat === 'number' &&
			typeof payload.exp === 'number'
		) {
			return payload as unknown as JWTPayload;
		}

		return null;
	} catch (error) {
		return null;
	}
}

export function extractToken(c: Context): string | null {
	const authHeader = c.req.header('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return null;
	}
	return authHeader.substring(7);
}

export async function authenticateUser(c: Context): Promise<UserPayload | null> {
	const token = extractToken(c);
	if (!token) {
		return null;
	}

	const jwtSecret = c.env.JWT_SECRET;
	if (!jwtSecret) {
		throw new Error('JWT_SECRET not configured');
	}

	return await verifyToken(token, jwtSecret);
}

// OAuth2 authorization code with embedded PKCE challenge (stateless)
interface AuthCodePayload {
	account_id: string;
	username: string;
	email: string;
	expires_at: number;
	code_challenge?: string;
	code_challenge_method?: 'S256' | 'plain';
}

/**
 * Generate authorization code with embedded user info and PKCE challenge
 * The code is a JWT-like structure that encodes all necessary information
 */
export async function generateAuthCode(
	user: UserPayload,
	secret: string,
	codeChallenge?: string,
	codeChallengeMethod?: 'S256' | 'plain'
): Promise<string> {
	const encoder = new TextEncoder();
	const secretKey = encoder.encode(secret);

	const payload: AuthCodePayload = {
		account_id: user.account_id,
		username: user.username,
		email: user.email,
		expires_at: Date.now() + 10 * 60 * 1000, // 10 minutes
		code_challenge: codeChallenge,
		code_challenge_method: codeChallengeMethod,
	};

	// Use SignJWT to create a secure, self-contained authorization code
	return await new SignJWT(payload as any)
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuedAt()
		.setExpirationTime('10m')
		.sign(secretKey);
}

/**
 * Consume and validate authorization code
 * Returns user payload and PKCE challenge if present
 */
export async function consumeAuthCode(
	code: string,
	secret: string
): Promise<{ user: UserPayload; codeChallenge?: string; codeChallengeMethod?: 'S256' | 'plain' } | null> {
	try {
		const encoder = new TextEncoder();
		const secretKey = encoder.encode(secret);

		const { payload } = await jwtVerify(code, secretKey);

		// Validate payload structure
		if (
			typeof payload.account_id === 'string' &&
			typeof payload.username === 'string' &&
			typeof payload.email === 'string' &&
			typeof payload.expires_at === 'number'
		) {
			// Check expiration
			if (Date.now() > payload.expires_at) {
				return null;
			}

			const user: UserPayload = {
				account_id: payload.account_id,
				username: payload.username,
				email: payload.email,
			};

			return {
				user,
				codeChallenge: payload.code_challenge as string | undefined,
				codeChallengeMethod: payload.code_challenge_method as 'S256' | 'plain' | undefined,
			};
		}

		return null;
	} catch (error) {
		return null;
	}
}

// PKCE (Proof Key for Code Exchange) validation - stateless
export async function validatePKCEVerifier(
	codeChallenge: string,
	codeChallengeMethod: 'S256' | 'plain',
	codeVerifier: string
): Promise<boolean> {
	if (codeChallengeMethod === 'S256') {
		// SHA256 hash the verifier and compare
		const encoder = new TextEncoder();
		const data = encoder.encode(codeVerifier);
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);

		// Convert to base64url
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		const hashBinary = String.fromCharCode(...hashArray);
		const base64 = btoa(hashBinary)
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=/g, '');

		return base64 === codeChallenge;
	} else {
		// Plain comparison
		return codeVerifier === codeChallenge;
	}
}

// Refresh token (stateless JWT with longer expiration)
export async function generateRefreshToken(user: UserPayload, secret: string): Promise<string> {
	const encoder = new TextEncoder();
	const secretKey = encoder.encode(secret);

	return await new SignJWT({
		account_id: user.account_id,
		username: user.username,
		email: user.email,
		type: 'refresh', // Mark as refresh token
	})
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuedAt()
		.setExpirationTime('365d') // 1 year
		.sign(secretKey);
}

export async function consumeRefreshToken(token: string, secret: string): Promise<UserPayload | null> {
	try {
		const encoder = new TextEncoder();
		const secretKey = encoder.encode(secret);

		const { payload } = await jwtVerify(token, secretKey);

		// Validate it's a refresh token
		if (payload.type !== 'refresh') {
			return null;
		}

		// Validate payload has required fields
		if (
			typeof payload.account_id === 'string' &&
			typeof payload.username === 'string' &&
			typeof payload.email === 'string'
		) {
			return {
				account_id: payload.account_id,
				username: payload.username,
				email: payload.email,
			} as UserPayload;
		}

		return null;
	} catch (error) {
		return null;
	}
}

