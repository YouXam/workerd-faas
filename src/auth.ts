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

// OAuth2 authorization code storage (in-memory for simplicity, should use persistent storage in production)
interface AuthCode {
	code: string;
	account_id: string;
	username: string;
	email: string;
	expires_at: number;
}

const authCodes = new Map<string, AuthCode>();

export function generateAuthCode(user: UserPayload): string {
	const code = crypto.randomUUID();
	authCodes.set(code, {
		code,
		account_id: user.account_id,
		username: user.username,
		email: user.email,
		expires_at: Date.now() + 10 * 60 * 1000, // 10 minutes
	});
	return code;
}

export function consumeAuthCode(code: string): UserPayload | null {
	const authCode = authCodes.get(code);
	if (!authCode) {
		return null;
	}

	if (Date.now() > authCode.expires_at) {
		authCodes.delete(code);
		return null;
	}

	authCodes.delete(code);
	return {
		account_id: authCode.account_id,
		username: authCode.username,
		email: authCode.email,
	};
}

// OIDC state management
interface OIDCState {
	state: string;
	expires_at: number;
}

const oidcStates = new Map<string, OIDCState>();

export function generateOIDCState(): string {
	const state = crypto.randomUUID();
	oidcStates.set(state, {
		state,
		expires_at: Date.now() + 10 * 60 * 1000, // 10 minutes
	});
	return state;
}

export function validateOIDCState(state: string): boolean {
	const oidcState = oidcStates.get(state);
	if (!oidcState) {
		return false;
	}

	if (Date.now() > oidcState.expires_at) {
		oidcStates.delete(state);
		return false;
	}

	oidcStates.delete(state);
	return true;
}
