import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { auditActor } from '@/lib/auditActor'
import { internalError } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import {
  editRecipes, markBulkRefreshOffered, readIngestionSettings, readRecipes, readSearchSettings, resetIngestionSettings,
  resetSearchSettings, saveIngestionSettings, saveSearchSettings, type SaveResult, type SearchSaveResult,
} from '@/lib/tradecraft/userSettings'
import { bulkRefreshOffer } from '@/lib/tradecraft/v2/list'

interface RouteParams {
  params: Promise<{ id: string }>
}

const BAD_BODY = 'Body must be {"ingestion": {<key>: <value>}}, {"search": {<key>: <value>, "synonyms"?: [...]}}, {"reset": "<section>" | "all" | "search"}, {"recipes": {"add" | "rename" | "delete": ...}} or {"bulkRefreshOffered": true}'

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

// Every answer still says `v2Enabled: true`: since the cut-over (T9.3) every account has 2.0, and
// a client of the switch era reads it so.
function settingsAnswer(result: SaveResult): NextResponse {
  if (!result.ok) {
    return NextResponse.json({ error: result.errors[0].message, code: 'invalid_settings', errors: result.errors }, { status: 400 })
  }
  return NextResponse.json({ v2Enabled: true, ingestion: result.view })
}

function searchAnswer(result: SearchSaveResult): NextResponse {
  if (!result.ok) {
    return NextResponse.json({ error: result.errors[0].message, code: 'invalid_settings', errors: result.errors }, { status: 400 })
  }
  return NextResponse.json({ v2Enabled: true, search: result.view })
}

// GET /api/users/[id]/tradecraft-settings
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    const [ingestion, recipes, search, offerBulkRefresh] = await Promise.all([
      readIngestionSettings(id), readRecipes(id), readSearchSettings(id), bulkRefreshOffer(id),
    ])
    return NextResponse.json({ v2Enabled: true, ingestion, recipes, search, offerBulkRefresh })
  } catch (error) {
    return internalError(error, 'Failed to read the Tradecraft settings')
  }
}

// PUT /api/users/[id]/tradecraft-settings
//   Body, exactly one of: { ingestion: { <key>: <value> } } | { reset: "<section>" | "all" | "search" }
//     | { search: { <key>: <value>, synonyms?: [{ term, expansion }] } } (Configure search, Q11: user level only;
//       the agent reads it from the next message, nothing is re-ingested)
//     | { recipes: { add: { name, topics, kinds } } | { rename: { id, name } } | { delete: "<id>" } }
//     | { bulkRefreshOffered: true } (the person answered the Save & refresh all offer, either way, T9.1)
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    // The internal key passes the account rule, but these are a person's choices: a request
    // without one changes nothing.
    const actor = await auditActor()
    if (!actor.actorId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const { body } = parsed
    const keys = Object.keys(body)
    if (keys.length !== 1) return NextResponse.json({ error: BAD_BODY }, { status: 400 })
    if (body.bulkRefreshOffered === true) {
      await markBulkRefreshOffered(id)
      return NextResponse.json({ v2Enabled: true, offerBulkRefresh: false })
    }
    if (isPlainObject(body.ingestion)) {
      return settingsAnswer(await saveIngestionSettings(id, body.ingestion))
    }
    if (isPlainObject(body.search)) {
      return searchAnswer(await saveSearchSettings(id, body.search))
    }
    if (body.reset === 'search') {
      return searchAnswer(await resetSearchSettings(id))
    }
    if (typeof body.reset === 'string') {
      return settingsAnswer(await resetIngestionSettings(id, body.reset))
    }
    if (isPlainObject(body.recipes)) {
      const result = await editRecipes(id, body.recipes)
      if (!result.ok) {
        return NextResponse.json({ error: result.error, code: result.code, ...(result.field ? { field: result.field } : {}) }, { status: result.status })
      }
      return NextResponse.json({ v2Enabled: true, recipes: result.recipes })
    }
    return NextResponse.json({ error: BAD_BODY }, { status: 400 })
  } catch (error) {
    return internalError(error, 'Failed to save the Tradecraft settings')
  }
}
