import { NextRequest, NextResponse } from 'next/server'
import type { UserTradecraftResource } from '@prisma/client'
import prisma from '@/lib/prisma'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { auditActor } from '@/lib/auditActor'
import { loginUseRefusal } from '@/lib/tradecraft/actAs'
import { AGENT_ROUTES, Credentials, ReadNowRequest, ReadNowResult, SLUG_RE, WEBAPP_TIMEOUTS_MS } from '@/lib/tradecraft/agentContract'
import { readSettings } from '@/lib/tradecraft/catalog'
import { hasStoredLogin } from '@/lib/tradecraft/masking'
import { loadOwnResource } from '@/lib/tradecraft/resourceAccess'
import { tradecraftV2Enabled } from '@/lib/tradecraft/switch'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string; pageId: string }>
}

const READ_FAILED = 'Read now failed'

function failure(status: number, code: string, error: string, extra: Record<string, unknown> = {}): NextResponse {
  return NextResponse.json({ error, code, ...extra }, { status })
}
const V2_OFF = () => failure(404, 'tradecraft_v2_off', 'Tradecraft 2.0 is off for this account')
const PAGE_NOT_FOUND = () => failure(404, 'page_not_found', 'Page not found')

/** `<slug>:<n>`, the page ID the agent and the Map view show; n is a `tradecraft_page_ids` row. */
function pageNumber(row: UserTradecraftResource, pageId: string): number | null {
  const i = pageId.lastIndexOf(':')
  if (i <= 0) return null
  const slug = pageId.slice(0, i)
  const n = pageId.slice(i + 1)
  if (!SLUG_RE.test(slug) || slug !== row.slug || !/^[1-9][0-9]{0,9}$/.test(n)) return null
  return Number(n)
}

/** The page's entry in the resource's live generation, keyed by the account, the resource and the number. */
async function entryOf(ownerId: string, row: UserTradecraftResource, n: number) {
  return prisma.tradecraftEntry.findFirst({
    where: { userId: ownerId, resourceId: row.id, generation: row.generation, pageId: n },
    select: { url: true, title: true, storedText: true, fetchedAt: true },
  })
}

async function isBlocked(resourceId: string, url: string): Promise<boolean> {
  return (await prisma.tradecraftCuration.count({ where: { resourceId, url, blocked: true } })) > 0
}

type Opened =
  | { res: Response }
  | { id: string; row: UserTradecraftResource; pageId: string; entry: NonNullable<Awaited<ReturnType<typeof entryOf>>> }

/** The guards both handlers share, then the row and the page; the login rule before the row is read. */
async function open(request: NextRequest, p: RouteParams['params'], mode: 'read' | 'write'): Promise<Opened> {
  const { id, resourceId, pageId } = await p
  const denied = await requireUserAccess(request, id, { mode })
  if (denied) return { res: denied }
  const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
  if (selfRefused) return { res: selfRefused }
  if (mode === 'write') {
    const actor = await auditActor()
    if (!actor.actorId) return { res: NextResponse.json({ error: 'Unauthorized' }, { status: 401 }) }
  }
  if (!(await tradecraftV2Enabled(id))) return { res: V2_OFF() }
  // The text of a resource with a login is the private content §6.6 protects, and Read now would
  // also send the login: neither while an administrator acts as the account (R-161).
  const loginRefused = await loginUseRefusal({ ownerId: id, resourceId })
  if (loginRefused) return { res: loginRefused }
  const row = await loadOwnResource(id, resourceId)
  if (!row) return { res: failure(404, 'not_found', 'Resource not found') }
  const n = pageNumber(row, pageId)
  if (n === null) return { res: PAGE_NOT_FOUND() }
  const entry = await entryOf(id, row, n)
  if (!entry) return { res: PAGE_NOT_FOUND() }
  return { id, row, pageId, entry }
}

// GET /api/users/[id]/tradecraft-resources/[resourceId]/pages/[pageId]
// View page (§6.10): the stored text with the time it was fetched, shown by the browser as plain
// text; or "not stored" (a Live resource, or a page the quota or a block left without text).
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const o = await open(request, params, 'read')
    if ('res' in o) return o.res
    const { row, pageId, entry } = o
    const blocked = await isBlocked(row.id, entry.url)
    const stored = !blocked && entry.storedText !== null
    return NextResponse.json({
      pageId, url: entry.url, title: entry.title, blocked, stored,
      text: stored ? entry.storedText : '',
      fetchedAt: stored ? entry.fetchedAt?.toISOString() ?? null : null,
      storageMode: row.storageMode,
    })
  } catch (error) {
    return internalError(error, 'Failed to read the page')
  }
}

function isTimeout(err: AgentUnreachableError): boolean {
  return (err.cause_ as { name?: string } | undefined)?.name === 'TimeoutError'
}

// POST /api/users/[id]/tradecraft-resources/[resourceId]/pages/[pageId]
// Read now (§6.10): the agent downloads the page as the tool does and keeps nothing. The URL is
// the entry's the page ID names and the secrets are the row's: the body is never read (D-54).
// The agent ends the read at its deadline; this route waits that long plus a margin (D-52).
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const o = await open(request, params, 'write')
    if ('res' in o) return o.res
    const { id, row, entry } = o
    if (await isBlocked(row.id, entry.url)) return failure(409, 'page_blocked', 'This page is blocked: unblock it to read it')

    const account = row.githubTokenOverride ? null : await prisma.userSettings.findUnique({ where: { userId: id }, select: { githubAccessToken: true } })
    const githubToken = row.githubTokenOverride || account?.githubAccessToken || ''
    // The account's GitHub token stays with the account while someone acts as it (step 3.14).
    if (githubToken) {
      const actingAs = await refuseWhileActingAsOn(id, 'use_github_token')
      if (actingAs) return actingAs
    }
    const user = await prisma.tradecraftUserSettings.findUnique({ where: { userId: id }, select: { ingestion: true } })
    const payload = ReadNowRequest.parse({
      user_id: id,
      resource_id: row.id,
      url: entry.url,
      read_settings: readSettings(row, user, row.forcedType || row.resourceType),
      secrets: { github_token: githubToken || null, credentials: hasStoredLogin(row) ? Credentials.parse(row.credentials ?? {}) : null },
    })
    let res: Response
    try {
      res = await agentFetch(AGENT_ROUTES.readNow, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      }, { timeoutMs: WEBAPP_TIMEOUTS_MS.readNow })
    } catch (err) {
      if (err instanceof AgentUnreachableError && isTimeout(err)) {
        console.error(`[tradecraft] read_now_timeout user=${id}`)
        return failure(504, 'timeout', 'The page took too long to read: the site may be slow or unreachable')
      }
      console.error(`[tradecraft] read_now_unreachable user=${id}`)
      return failure(503, 'agent_unreachable', 'The agent could not be reached to read the page')
    }
    if (!res.ok) {
      console.error(`[tradecraft] read_now_agent_error user=${id} status=${res.status}`)
      return failure(502, 'agent_error', READ_FAILED, { upstreamStatus: res.status })
    }
    const answer = ReadNowResult.safeParse(await res.json().catch(() => null))
    if (!answer.success) {
      console.error(`[tradecraft] read_now_invalid_answer user=${id}`)
      return failure(502, 'internal_error', READ_FAILED)
    }
    return NextResponse.json({ result: answer.data })
  } catch (error) {
    return internalError(error, READ_FAILED)
  }
}
