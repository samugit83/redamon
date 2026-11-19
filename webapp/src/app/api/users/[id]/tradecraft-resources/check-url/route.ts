import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { auditActor } from '@/lib/auditActor'
import { loginUseRefusal } from '@/lib/tradecraft/actAs'
import {
  AGENT_ROUTES, CheckUrlRequest, CheckUrlResult, Credentials, WEBAPP_TIMEOUTS_MS,
} from '@/lib/tradecraft/agentContract'
import { effectiveSettings } from '@/lib/tradecraft/effectiveSettings'
import { loadOwnResource } from '@/lib/tradecraft/resourceAccess'
import {
  applyCredentials, fieldErrorResponse, hasCredentials, parseResourceFields, typeOptionsOf, type StoredCredentials,
} from '@/lib/tradecraft/v2/fields'

interface RouteParams {
  params: Promise<{ id: string }>
}

const FAILED = 'Check URL failed'

function failure(status: number, code: string, error: string, extra: Record<string, unknown> = {}): NextResponse {
  return NextResponse.json({ error, code, ...extra }, { status })
}

function isTimeout(err: AgentUnreachableError): boolean {
  const cause = err.cause_ as { name?: string } | undefined
  return cause?.name === 'TimeoutError'
}

// POST /api/users/[id]/tradecraft-resources/check-url
//   Body: { url, forcedType?, overrides?, githubTokenOverride?, credentials? }  (a URL being added)
//      or { resourceId, forcedType?, overrides?, githubTokenOverride?, credentials? }  (a saved resource)
// Check URL (§6.3): the agent fetches the homepage and the type's index, calls no model and saves
// nothing (AC-09); neither does this route. For a saved resource the URL and the secrets come
// from its row, and a masked value the form sends back is never what reaches the agent (D-54).
// The agent ends the check at its deadline; this route waits that long plus a margin (D-52).
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    return await check(request, id)
  } catch (error) {
    return internalError(error, FAILED)
  }
}

async function check(request: NextRequest, id: string): Promise<NextResponse> {
  const denied = await requireUserAccess(request, id, { mode: 'write' })
  if (denied) return denied
  const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
  if (selfRefused) return selfRefused
  const actor = await auditActor()
  if (!actor.actorId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const parsedBody = await readJsonBody(request)
  if (parsedBody instanceof NextResponse) return parsedBody
  const { body } = parsedBody
  const resourceId = typeof body.resourceId === 'string' && body.resourceId ? body.resourceId : null
  // The fields of the form, judged as an edit would judge them; the URL is the row's for a saved resource.
  const { url: bodyUrl, ...rest } = body
  const fields = parseResourceFields(resourceId ? rest : { ...rest, url: bodyUrl ?? '' }, 'update')
  if (!fields.ok) return fieldErrorResponse(fields.error)

  let url = fields.value.url ?? ''
  let forcedType: string = fields.value.forcedType ?? ''
  let overrides: unknown = fields.value.overrides ?? {}
  let token = fields.value.githubTokenOverride ?? ''
  // The login the form holds now: typed for a URL being added, or merged with a saved resource's
  // stored one, so a value sent back as "set" is the stored value and never the placeholder.
  const patch = fields.value.credentials
  let base: unknown = {}
  if (resourceId) {
    // A login's use is refused while someone acts as the account (§6.6): before the row is read.
    const loginRefused = await loginUseRefusal({ ownerId: id, resourceId })
    if (loginRefused) return loginRefused
    const row = await loadOwnResource(id, resourceId)
    if (!row) return failure(404, 'not_found', 'Resource not found')
    url = row.url
    forcedType = fields.value.forcedType ?? row.forcedType
    overrides = fields.value.overrides ?? row.overrides
    // A token typed in the form now wins; otherwise the stored one, never the placeholder.
    token = fields.value.githubTokenOverride ?? row.githubTokenOverride
    base = row.credentials
  }
  let login: StoredCredentials = {}
  if (patch !== null) {
    const applied = applyCredentials(base, patch ?? {})
    if (!applied.ok) return fieldErrorResponse(applied.error)
    login = applied.value
  }
  if (hasCredentials(login)) {
    const loginRefused = await loginUseRefusal({ ownerId: id, credentials: login })
    if (loginRefused) return loginRefused
  }
  const credentials = hasCredentials(login) ? Credentials.parse(login) : null

  const account = token ? null : await prisma.userSettings.findUnique({ where: { userId: id }, select: { githubAccessToken: true } })
  const githubToken = token || account?.githubAccessToken || ''
  // The account's GitHub token stays with the account while someone acts as it (step 3.14).
  if (githubToken) {
    const actingAs = await refuseWhileActingAsOn(id, 'use_github_token')
    if (actingAs) return actingAs
  }

  const user = await prisma.tradecraftUserSettings.findUnique({ where: { userId: id }, select: { ingestion: true } })
  const settings = effectiveSettings({ user, resource: overrides })
  const payload = CheckUrlRequest.parse({
    user_id: id,
    url,
    forced_type: forcedType,
    type_options: typeOptionsOf(settings.values),
    settings: settings.values,
    secrets: { github_token: githubToken || null, credentials },
  })

  let res: Response
  try {
    res = await agentFetch(AGENT_ROUTES.checkUrl, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    }, { timeoutMs: WEBAPP_TIMEOUTS_MS.checkUrl })
  } catch (err) {
    if (err instanceof AgentUnreachableError && isTimeout(err)) {
      console.error(`[tradecraft] check_url_timeout user=${id}`)
      return failure(504, 'timeout', 'The check took too long: the site may be slow or unreachable')
    }
    console.error(`[tradecraft] check_url_unreachable user=${id}`)
    return failure(503, 'agent_unreachable', 'The agent could not be reached to check the URL')
  }
  if (!res.ok) {
    console.error(`[tradecraft] check_url_agent_error user=${id} status=${res.status}`)
    return failure(502, 'agent_error', FAILED, { upstreamStatus: res.status })
  }
  const answer = CheckUrlResult.safeParse(await res.json().catch(() => null))
  if (!answer.success) {
    console.error(`[tradecraft] check_url_invalid_answer user=${id}`)
    return failure(502, 'internal_error', FAILED)
  }
  return NextResponse.json({ result: answer.data })
}
