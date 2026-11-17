import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { accountContentRefusal, requireSelfPermission } from '@/lib/authz/selfService'
import { actingAsOn } from '@/lib/authz/actAsRefusals'
import { auditActor } from '@/lib/auditActor'
import { MAP_PAGE_SIZE, MAP_STATUSES, curate, isMapCursor, readMap, titlesAndUrlsOnly, type MapStatus } from '@/lib/tradecraft/curation'
import { hasStoredLogin } from '@/lib/tradecraft/masking'
import { loadOwnResource } from '@/lib/tradecraft/resourceAccess'
import { tradecraftV2Enabled } from '@/lib/tradecraft/switch'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

const V2_OFF = () => NextResponse.json({ error: 'Tradecraft 2.0 is off for this account', code: 'tradecraft_v2_off' }, { status: 404 })
const NOT_FOUND = () => NextResponse.json({ error: 'Resource not found' }, { status: 404 })
const bad = (field: string, error: string) => NextResponse.json({ error, code: 'bad_request', field }, { status: 400 })

// GET /api/users/[id]/tradecraft-resources/[resourceId]/map?query=&status=kept|dropped|blocked&tag=&cursor=&limit=
// The Map view (§6.10): the live generation's entries, 100 at a time, with the total. Titles,
// URLs, tags, the one-line description, source, status and the drop reason; never page text.
// The account's own content: the account itself or an administrator acting as it, never the user
// directory. While an administrator acts as the account, a resource with a login answers titles
// and URLs only (R-161): its tags, descriptions, sources and drop reasons were made from its
// private pages, and a tag filter would tell its tags too, so none is applied.
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const notOwn = await accountContentRefusal(request, id)
    if (notOwn) return notOwn
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    if (!(await tradecraftV2Enabled(id))) return V2_OFF()
    const sp = request.nextUrl.searchParams
    const status = sp.get('status') ?? 'kept'
    if (!(MAP_STATUSES as readonly string[]).includes(status)) return bad('status', `status is one of ${MAP_STATUSES.join(', ')}`)
    const query = sp.get('query') ?? ''
    if (query.length > 200) return bad('query', 'A search holds at most 200 characters')
    const tag = sp.get('tag') ?? ''
    if (tag.length > 64) return bad('tag', 'Not a tag')
    const cursor = sp.get('cursor')
    if (cursor !== null && !isMapCursor(cursor)) return bad('cursor', 'Not a cursor of this list')
    const limitText = sp.get('limit')
    const limit = limitText === null ? MAP_PAGE_SIZE : Number(limitText)
    if (!Number.isInteger(limit) || limit < 1 || limit > MAP_PAGE_SIZE) return bad('limit', `limit is 1 to ${MAP_PAGE_SIZE}`)

    const row = await loadOwnResource(id, resourceId)
    if (!row) return NOT_FOUND()
    const hidden = hasStoredLogin(row) && await actingAsOn(id)
    const page = await readMap(row, { query: query || undefined, status: status as MapStatus, tag: hidden ? undefined : tag || undefined, cursor, limit })
    return NextResponse.json(hidden ? { ...page, entries: page.entries.map(titlesAndUrlsOnly) } : page)
  } catch (error) {
    return internalError(error, 'Failed to read the map')
  }
}

// POST /api/users/[id]/tradecraft-resources/[resourceId]/map
//   Body, one operation: { op: 'pin', url } | { op: 'block', urls } | { op: 'block', matching: { query?, status?, tag? }, expectedCount }
//     | { op: 'unblock', urls } | { op: 'rename', url, title } | { op: 'restore', url }
// Curation (§6.10): applied to the map at once, kept across refreshes (lib/tradecraft/curation.ts).
// A block of all matching pages answers 409 `count_changed` when the search no longer matches the
// count the person confirmed.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    const actor = await auditActor()
    if (!actor.actorId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    if (!(await tradecraftV2Enabled(id))) return V2_OFF()
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const row = await loadOwnResource(id, resourceId)
    if (!row) return NOT_FOUND()
    const result = await curate(row, parsed.body, actor.actorId)
    if (!result.ok) {
      const { ok: _ok, status, ...body } = result
      return NextResponse.json(body, { status })
    }
    return NextResponse.json({ op: result.op, count: result.count })
  } catch (error) {
    return internalError(error, 'Failed to change the map')
  }
}
