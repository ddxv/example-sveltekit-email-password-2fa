import { fail, redirect } from "@sveltejs/kit";
import { deleteSessionTokenCookie, invalidateSession } from "$lib/server/session";

import type { Actions, PageServerLoadEvent, RequestEvent } from "./$types";

export function load(event: PageServerLoadEvent) {
	return {
		message: "Hello World"
	};
}

export const actions: Actions = {
	default: action
};

async function action(event: RequestEvent) {
	if (event.locals.session === null) {
		return fail(401, {
			message: "Not authenticated"
		});
	}
	invalidateSession(event.locals.session.id);
	deleteSessionTokenCookie(event);
	return redirect(302, "/login");
}
