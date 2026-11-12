/**
 * What the three URL-import proxies share: the project id check, URL syntax checks
 * with the agent's codes, and the GitHub token, read on the server and sent
 * only for a GitHub link and never while an admin acts as another user (their
 * token would open that user's private repositories to the admin, and the
 * admin's would put the admin's into the user's project). Each route asks
 * `workspace:import` on the project itself, between the id check and importCaller.
 *
 * Server-side only.
 */
import { NextResponse } from 'next/server'
import type { PermissionContext } from '@/lib/authz/guards'
import { actingAsUserId } from '@/lib/workspaceImport/audit'
import { githubTokenForImport } from '@/lib/workspaceImport/githubToken'

export interface ImportCaller { userId: string; actingAs?: string }

/** The 400 of a request that names no project, answered before the session is read. */
export function importProjectProblem(projectId: unknown): NextResponse | null {
  if (typeof projectId === 'string' && projectId) return null
  return NextResponse.json({ error: 'projectId required', code: 'invalid_request' }, { status: 400 })
}

/** Whose import it is once the route's permission check passed: the effective user, and the account acted as. */
export async function importCaller(auth: PermissionContext): Promise<ImportCaller> {
  return { userId: auth.effective.userId, actingAs: await actingAsUserId() }
}

/** null when the URL is acceptable, else the 400 the agent would give. */
export function urlProblem(url: unknown): NextResponse | null {
  const refuse = (code: string, error: string) => NextResponse.json({ error, code }, { status: 400 })
  if (typeof url !== 'string' || !url.trim()) return refuse('invalid_url', 'The link is not a valid URL.')
  let u: URL
  try {
    u = new URL(url.trim())
  } catch {
    return refuse('invalid_url', 'The link is not a valid URL.')
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return refuse('unsupported_scheme', 'Only http and https links can be imported.')
  }
  if (u.username || u.password) {
    return refuse('credentials_in_url', 'The link holds a user name or password. Remove it; private GitHub repositories use the GitHub token in Global Settings.')
  }
  return null
}

export async function tokenFor(guard: { userId: string; actingAs?: string }, url: string): Promise<string> {
  if (guard.actingAs) return ''
  return githubTokenForImport(guard.userId, url)
}
