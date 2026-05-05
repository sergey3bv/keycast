import type { Handle } from "@sveltejs/kit";
import { redirect } from "@sveltejs/kit";

const protectedRoutes: string[] = ["/teams", "/keys", "/admin", "/support-admin"];

/** Must match `auth_routes_use_no_referrer` in `keycast/src/main.rs`. */
const noReferrerAuthPaths = new Set([
    "/reset-password",
    "/forgot-password",
    "/login",
    "/register",
    "/verify-email",
]);

export const handle: Handle = async ({ event, resolve }) => {
    const hasSession = event.cookies.get("keycast_session") || event.cookies.get("keycastUserPubkey");
    if (!hasSession && protectedRoutes.includes(event.url.pathname)) {
        throw redirect(303, "/");
    }

    const response = await resolve(event);
    if (noReferrerAuthPaths.has(event.url.pathname) && !response.headers.has("referrer-policy")) {
        response.headers.set("Referrer-Policy", "no-referrer");
    }
    return response;
};
