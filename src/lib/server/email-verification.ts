import { generateRandomOTP } from "./utils";
import { db } from "./db";
import { ExpiringTokenBucket } from "./rate-limit";
import { encodeBase32 } from "@oslojs/encoding";

import type { RequestEvent } from "@sveltejs/kit";

export async function getUserEmailVerificationRequest(userId: number, id: string): Promise<EmailVerificationRequest | null> {
	const row = await db.queryOne<{ id: string, user_id: number, code: string, email: string, expires_at: string }>(
		"SELECT id, user_id, code, email, expires_at FROM email_verification_requests WHERE id = $1 AND user_id = $2",
		[id, userId]
	);
	if (row === null) {
		return row;
	}
	const request: EmailVerificationRequest = {
		id: row.id,
		userId: row.user_id,
		code: row.code,
		email: row.email,
		expiresAt: new Date(row.expires_at)
	};
	return request;
}

export async function createEmailVerificationRequest(userId: number, email: string): Promise<EmailVerificationRequest> {
	await deleteUserEmailVerificationRequest(userId);
	const idBytes = new Uint8Array(20);
	crypto.getRandomValues(idBytes);
	const id = encodeBase32(idBytes).toLowerCase();

	const code = generateRandomOTP();
	const expiresAt = new Date(Date.now() + 1000 * 60 * 10);
	await db.queryOne<{ id: string }>(
		"INSERT INTO email_verification_requests (id, user_id, code, email, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		[id, userId, code, email, expiresAt]
	);

	const request: EmailVerificationRequest = {
		id,
		userId,
		code,
		email,
		expiresAt
	};
	return request;
}

export async function deleteUserEmailVerificationRequest(userId: number): Promise<void> {
	await db.execute("DELETE FROM email_verification_requests WHERE user_id = $1", [userId]);
}

export function sendVerificationEmail(email: string, code: string): void {
	console.log(`To ${email}: Your verification code is ${code}`);
}

export function setEmailVerificationRequestCookie(event: RequestEvent, request: EmailVerificationRequest): void {
	event.cookies.set("email_verification", request.id, {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		expires: request.expiresAt
	});
}

export function deleteEmailVerificationRequestCookie(event: RequestEvent): void {
	event.cookies.set("email_verification", "", {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		maxAge: 0
	});
}

export async function getUserEmailVerificationRequestFromRequest(event: RequestEvent): Promise<EmailVerificationRequest | null> {
	if (event.locals.user === null) {
		return null;
	}
	const id = event.cookies.get("email_verification") ?? null;
	if (id === null) {
		return null;
	}
	const request = await getUserEmailVerificationRequest(event.locals.user.id, id);
	if (request === null) {
		deleteEmailVerificationRequestCookie(event);
	}
	return request;
}

export const sendVerificationEmailBucket = new ExpiringTokenBucket<number>(3, 60 * 10);

export interface EmailVerificationRequest {
	id: string;
	userId: number;
	code: string;
	email: string;
	expiresAt: Date;
}
