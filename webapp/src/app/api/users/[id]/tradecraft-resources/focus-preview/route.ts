import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { auditActor } from '@/lib/auditActor'
import { loginUseRefusal } from '@/lib/tradecraft/actAs'
import { AGENT_ROUTES, PreviewRequest, PreviewResult, WEBAPP_TIMEOUTS_MS } from '@/lib/tradecraft/agentContract'
import { effectiveSettings } from '@/lib/tradecraft/effectiveSettings'
import { loadOwnResource } from '@/lib/tradecraft/resourceAccess'
import { SETTINGS_CONSTANTS } from '@/lib/tradecraft/settingsSpec'
import { validateUrl } from '@/lib/tradecraft/urls'
import { validateFocus, withOwnSkillTopics } from '@/lib/tradecraft/v2/focusFields'

interface RouteParams {
  params: Promise<{ id: string }>
}

const FAILED = 'The focus preview failed'
const SAMPLE_MAX: number = SETTINGS_CONSTANTS.previewEntries
const TITLE_MAX = 300
const MODEL_MAX = 300

function failure(status: number, code: string, error: string, extra: Record<string, unknown> = {}): NextResponse {
  return NextResponse.json({ error, code, ...extra }, { status })
}

const badField = (field: string, error: string, code = 'bad_field') => failure(400, code, error, { field })

function isTimeout(err: AgentUnreachableError): boolean {
  const cause = err.cause_ as { name?: string } | undefined
  return cause?.name === 'TimeoutError'
}

type Entry = { url: string; title: string }

/** Entries from a Check URL result, as the browser sent them back: bounded and checked like resource URLs. */
function parseEntries(input: unknown): { ok: true; entries: Entry[] } | { ok: false; res: NextResponse } {
  if (!Array.isArray(input) || input.length === 0 || input.length > SAMPLE_MAX) {
    return { ok: false, res: badField('entries', `Send 1 to ${SAMPLE_MAX} entries`) }
  }
  const entries: Entry[] = []
  for (const [i, e] of input.entries()) {
    const field = `entries[${i}]`
    if (!e || typeof e !== 'object' || Array.isArray(e)) return { ok: false, res: badField(field, 'An entry is {url, title}') }
    const { url, title = '' } = e as Record<string, unknown>
    if (typeof url !== 'string' || url.length > 2048) return { ok: false, res: badField(`${field}.url`, 'Not a URL') }
    const check = validateUrl(url)
    if (!check.ok) return { ok: false, res: badField(`${field}.url`, check.error, check.code ?? 'bad_url') }
    if (typeof title !== 'string' || title.length > TITLE_MAX) {
      return { ok: false, res: badField(`${field}.title`, `A title holds at most ${TITLE_MAX} characters`) }
    }
    entries.push({ url, title })
  }
  return { ok: true, entries }
}

/**
 * Up to SAMPLE_MAX entries of the resource's live map, spread evenly over it in page order, so
 * a large map is not judged by its first section only. Dropped entries are sampled too: the
 * focus being previewed decides again.
 */
async function sampleEntries(ownerId: string, resourceId: string, generation: number): Promise<Entry[]> {
  const where = { userId: ownerId, resourceId, generation }
  const ids = await prisma.tradecraftEntry.findMany({ where, select: { id: true }, orderBy: { id: 'asc' } })
  const picked = ids.length <= SAMPLE_MAX
    ? ids
    : Array.from({ length: SAMPLE_MAX }, (_, i) => ids[Math.floor((i * ids.length) / SAMPLE_MAX)])
  if (picked.length === 0) return []
  const rows = await prisma.tradecraftEntry.findMany({
    where: { ...where, id: { in: picked.map(p => p.id) } },
    select: { url: true, title: true },
    orderBy: { id: 'asc' },
  })
  return rows.map(r => ({ url: r.url, title: r.title.slice(0, TITLE_MAX) }))
}

function modelOf(input: unknown): { ok: true; model: string | null } | { ok: false; res: NextResponse } {
  if (input === undefined) return { ok: true, model: null }
  const model = typeof input === 'string' ? input.trim() : ''
  if (!model || model.length > MODEL_MAX) return { ok: false, res: badField('llmModel', 'Pick a model for this resource', 'model_required') }
  if (isLoopModel(model)) {
    return { ok: false, res: badField('llmModel', 'Agent in the Loop answers only inside a chat run; pick a provider model', 'loop_model_not_allowed') }
  }
  return { ok: true, model }
}

// POST /api/users/[id]/tradecraft-resources/focus-preview
//   Body: { focus, resourceId, llmModel? }   (a saved resource: a sample of its live map)
//      or { focus, entries, llmModel }       (the entries Check URL found for a resource being added)
// The focus preview (§6.14): the agent's title triage on at most 100 entries with the resource's
// model; nothing is saved, here or by the agent. A saved resource's entries come from its rows,
// never from the body (D-54). The agent ends the call at its deadline; this route waits that long
// plus a margin (D-52). The agent's per-user bucket limits the calls, keyed by `user_id`.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    return await preview(request, id)
  } catch (error) {
    return internalError(error, FAILED)
  }
}

async function preview(request: NextRequest, id: string): Promise<NextResponse> {
  const denied = await requireUserAccess(request, id, { mode: 'write' })
  if (denied) return denied
  const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
  if (selfRefused) return selfRefused
  // The preview spends the account's model: a person asks for it, never the internal key alone.
  const actor = await auditActor()
  if (!actor.actorId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const parsedBody = await readJsonBody(request)
  if (parsedBody instanceof NextResponse) return parsedBody
  const { body } = parsedBody

  if (body.focus === undefined) return badField('focus', 'Send the focus to preview', 'bad_focus')
  const focus = validateFocus(body.focus)
  if (!focus.ok) return badField(focus.field, focus.error, 'bad_focus')
  if (!('mode' in focus.value) || focus.value.mode === 'everything') {
    return badField(Object.keys(focus.value).length === 0 ? 'focus' : 'focus.mode', 'Everything keeps every page: pick Focused or Tag only to preview', 'bad_focus')
  }
  const ownFocus = await withOwnSkillTopics(id, focus.value)
  const chosen = modelOf(body.llmModel)
  if (!chosen.ok) return chosen.res

  const resourceId = typeof body.resourceId === 'string' && body.resourceId ? body.resourceId : null
  if ((resourceId === null) === (body.entries === undefined)) {
    return badField('resourceId', 'Send either the resource id or the entries Check URL found')
  }

  let entries: Entry[]
  let model: string
  let overrides: unknown = {}
  if (resourceId) {
    // A login's use is refused while someone acts as the account (§6.6): before the row is read.
    const loginRefused = await loginUseRefusal({ ownerId: id, resourceId })
    if (loginRefused) return loginRefused
    const row = await loadOwnResource(id, resourceId)
    if (!row) return failure(404, 'not_found', 'Resource not found')
    entries = await sampleEntries(id, resourceId, row.generation)
    if (entries.length === 0) {
      return failure(409, 'no_entries', 'This resource has no page list yet: refresh it first, or preview from Check URL in the form')
    }
    model = chosen.model ?? row.llmModel
    overrides = row.overrides
  } else {
    const parsed = parseEntries(body.entries)
    if (!parsed.ok) return parsed.res
    entries = parsed.entries
    if (!chosen.model) return badField('llmModel', 'Pick a model for this resource', 'model_required')
    model = chosen.model
  }

  // The values a refresh of this resource would carry (the account's "Always skip" above all), so
  // the agent reads the focus as the refresh will; a resource being added has no overrides yet.
  const user = await prisma.tradecraftUserSettings.findUnique({ where: { userId: id }, select: { ingestion: true } })
  const settings = effectiveSettings({ user, resource: overrides }).values
  const payload = PreviewRequest.parse({ user_id: id, model, focus: ownFocus, entries, settings })
  let res: Response
  try {
    res = await agentFetch(AGENT_ROUTES.previewFocus, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    }, { timeoutMs: WEBAPP_TIMEOUTS_MS.previewFocus })
  } catch (err) {
    if (err instanceof AgentUnreachableError && isTimeout(err)) {
      console.error(`[tradecraft] focus_preview_timeout user=${id}`)
      return failure(504, 'timeout', 'The preview took too long: try again, or with a smaller sample')
    }
    console.error(`[tradecraft] focus_preview_unreachable user=${id}`)
    return failure(503, 'agent_unreachable', 'The agent could not be reached to preview the focus')
  }
  if (!res.ok) {
    console.error(`[tradecraft] focus_preview_agent_error user=${id} status=${res.status}`)
    return failure(502, 'agent_error', FAILED, { upstreamStatus: res.status })
  }
  const answer = PreviewResult.safeParse(await res.json().catch(() => null))
  if (!answer.success) {
    console.error(`[tradecraft] focus_preview_invalid_answer user=${id}`)
    return failure(502, 'internal_error', FAILED)
  }
  return NextResponse.json({ result: answer.data })
}
