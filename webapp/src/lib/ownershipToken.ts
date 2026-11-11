/**
 * The domain-ownership token: the value a project's TXT record publishes
 * (`redamon-verify=<token>`) when ownership verification is on.
 *
 * Every project gets its own random token when it is created. The column used
 * to default to a placeholder printed in the source, so one record published
 * with it verified every project on the install that kept it. Each create path
 * (the form's POST, MCP create_project, import) therefore replaces a missing,
 * blank or placeholder value with a fresh one, and Prisma's `@default(uuid())`
 * covers any path that sets nothing.
 *
 * Client-safe: the form imports the placeholder to warn about it.
 */
export const LEGACY_OWNERSHIP_TOKEN = 'your-secret-token-here'

/** True for a value that proves nothing: absent, blank, or the shared placeholder. */
export function isUnsetOwnershipToken(value: unknown): boolean {
  if (typeof value !== 'string') return true
  const trimmed = value.trim()
  return trimmed === '' || trimmed === LEGACY_OWNERSHIP_TOKEN
}

/** A random version-4 UUID, the same shape as Prisma's `uuid()` default. */
export function generateOwnershipToken(): string {
  return globalThis.crypto.randomUUID()
}

/** The token a new project is created with: the creator's own, or a fresh one. */
export function ownershipTokenForCreate(value: unknown): string {
  return isUnsetOwnershipToken(value) ? generateOwnershipToken() : (value as string)
}
