import { db } from "./db";

export function verifyEmailInput(email: string): boolean {
	return /^.+@.+\..+$/.test(email) && email.length < 256;
}

export async function checkEmailAvailability(email: string): Promise<boolean> {
	const row = await db.queryOne<{ count: number }>("SELECT COUNT(*) FROM users WHERE email = $1", [email]);
	if (row === null) {
		throw new Error("Failed to check email availability");
	}
	return row.count === 0;
}
