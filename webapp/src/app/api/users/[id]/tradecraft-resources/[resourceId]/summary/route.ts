import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { auditActor } from '@/lib/auditActor'
import { SUMMARY_SOURCES } from '@/lib/tradecraft/agentContract'
import { lockOwnResource } from '@/lib/tradecraft/resourceAccess'
import { tradecraftV2Enabled } from '@/lib/tradecraft/switch'
import { resourceViewOf } from '@/lib/tradecraft/v2/list'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

/** §6.9: a summary written by a person holds at most this many characters. */
const SUMMARY_MAX_CHARS = 6000

const KEYS = new Set(['source', 'text', 'locked'])

class NotFound extends Error {}

function bad(field: string, error: string): NextResponse {
  return NextResponse.json({ field, code: 'bad_field', error }, { status: 400 })
}

// PUT /api/users/[id]/tradecraft-resources/[resourceId]/summary
//   Body: { source?: 'generated' | 'manual', text?: string, locked?: boolean }
// The summary editor (§6.9, R-164): saved at once, no ingestion. Text a person writes is
// "Written by me"; a refresh keeps it, and keeps a locked summary, at the swap (S03's rule).
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    const actor = await auditActor()
    if (!actor.actorId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    if (!(await tradecraftV2Enabled(id))) {
      return NextResponse.json({ error: 'Tradecraft 2.0 is off for this account', code: 'tradecraft_v2_off' }, { status: 404 })
    }

    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const { body } = parsed
    const keys = Object.keys(body)
    if (keys.length === 0 || keys.some(k => !KEYS.has(k))) {
      return NextResponse.json({ error: 'Body is { source?, text?, locked? }', code: 'bad_request' }, { status: 400 })
    }
    const data: { summary?: string; summarySource?: string; summaryLocked?: boolean } = {}
    if (body.source !== undefined) {
      if (!(SUMMARY_SOURCES as readonly unknown[]).includes(body.source)) return bad('source', 'The source is "generated" or "manual"')
      data.summarySource = body.source as string
    }
    if (body.text !== undefined) {
      if (typeof body.text !== 'string') return bad('text', 'The summary is text')
      if (body.text.length > SUMMARY_MAX_CHARS) return bad('text', `A summary holds at most ${SUMMARY_MAX_CHARS} characters`)
      if (!body.text.trim()) return bad('text', 'A summary written by you cannot be empty')
      // Generated text comes from the model alone: text a person sends is theirs.
      if (data.summarySource === 'generated') return bad('source', 'Text you write is "manual"; Regenerate writes a generated one')
      data.summary = body.text
      data.summarySource = 'manual'
    }
    if (body.locked !== undefined) {
      if (typeof body.locked !== 'boolean') return bad('locked', 'locked is true or false')
      data.summaryLocked = body.locked
    }

    try {
      await prisma.$transaction(async (tx) => {
        if (!(await lockOwnResource(tx, id, resourceId))) throw new NotFound()
        await tx.userTradecraftResource.update({ where: { id: resourceId }, data })
      })
    } catch (err) {
      if (err instanceof NotFound) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
      throw err
    }
    return NextResponse.json({ resource: await resourceViewOf(id, resourceId) })
  } catch (error) {
    return internalError(error, 'Failed to save the summary')
  }
}
