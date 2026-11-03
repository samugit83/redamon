/**
 * What the three URL-import proxies share: project access, URL syntax checks
 * with the agent's codes, and the GitHub token, read on the server and sent
 * only for a GitHub link and never while an admin acts as another user (their
 * token would open that user's private repositories to the admin, and the
 * admin's would put the admin's into the user's project).
 *
 * Server-side only.
 */
import { NextResponse } from 'next/server'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { actingAsUserId } from '@/lib/workspaceImport/audit'
import { githubTokenForImport } from '@/lib/workspaceImport/githubToken'

export type Guarded = { ok: true; userId: string; actingAs?: string } | { ok: false; response: NextResponse }

export async function guardImport(projectId: unknown): Promise<Guarded> {
  if (typeof projectId !== 'string' || !projectId) {
    return { ok: false, response: NextResponse.json({ error: 'projectId required', code: 'invalid_request' }, { status: 400 }) }
  }
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return { ok: false, response: eff }
  const access = await requireProjectAccess(eff, projectId)
  if (access instanceof NextResponse) return { ok: false, response: access }
  return { ok: true, userId: eff.userId, actingAs: await actingAsUserId() }
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
