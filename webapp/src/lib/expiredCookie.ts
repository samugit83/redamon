/**
 * The attributes that end a cookie in the browser. `maxAge: 0` alone does not: Next re-reads a
 * response's Set-Cookie before sending it, and that re-read drops every falsy attribute, so the
 * header went out with no Max-Age and no Expires and the browser kept an empty session cookie
 * (a sign-out everywhere left `redamon-auth=` in place). A past Expires survives the re-read.
 */
export const EXPIRED_COOKIE = { maxAge: 0, expires: new Date(0) } as const
