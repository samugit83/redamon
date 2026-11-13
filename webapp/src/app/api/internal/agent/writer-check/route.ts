/**
 * POST /api/internal/agent/writer-check: may this person's agent session start a run on this
 * project now, or is another person writing it (step 5.11 follow-up; SH-40, OQ-35)?
 *
 * The chat ticket refuses a second writer when the socket opens (/api/agent/ws-ticket), but runs
 * start over the socket for as long as it stays open: a socket opened before another person's scan,
 * agent run, triage run or mute-rule apply started would otherwise start runs beside it. So before
 * each run starts (a message, an approval, an answer to its question, a tool confirmation, a resume)
 * the agent asks here (agentic/writer_check.py) with its verified ticket's ids, and the answer is
 * the ticket's own: 200 `{allowed: true}`, or 409 `{error, code: 'project_writer_busy', busy}` naming
 * who holds the project (secondWriterResponse). The owner is read from the database, never taken
 * from the agent; the person is the ticket's `sub` (an admin acting as the owner is the owner;
 * `actorId`, the admin, only reaches the log line). Only with sharing in force and the `refuse`
 * policy; an unreadable source lets the owner through and refuses anyone else.
 *
 * The internal key is global, so this route trusts the ids only as the agent's verified ticket's.
 * The agent reads no answer, or a 5xx (a failure here), as unverified, with the same rule: the
 * owner's run starts, anyone else's does not. Every other answer (this route's 400, a 401, a 404 from
 * a webapp older than the agent) refuses everyone, the owner included: the session id is the
 * browser's, so an answer the body can provoke must never let a run through. The session id follows
 * the ticket's own rule (isWsSessionId), so a ticket the mint signed is never refused here.
 *
 * Asked outside the project's graph lock (projectGraphLock.ts): an agent run holds no lock, and the
 * lock names an operation, not a person, so a held lock cannot say whose start it is. Two people
 * starting within the same instant can both pass (README.SECURITY_POSTURE §20).
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { logValue, withRouteErrors } from '@/lib/routeErrors'
import { secondWriterResponse } from '@/lib/authz/projectWriters'
import { isWsSessionId } from '@/lib/wsTicket'

export const runtime = 'nodejs'

const MAX_ID = 200

interface WriterCheck {
  userId: string
  projectId: string
  sessionId: string
  actorId: string | null
}

const id = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= MAX_ID

function parse(body: unknown): WriterCheck | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null
  const b = body as Record<string, unknown>
  if (!id(b.userId) || !id(b.projectId) || !isWsSessionId(b.sessionId)) return null
  if (b.actorId !== undefined && b.actorId !== null && !id(b.actorId)) return null
  return { userId: b.userId, projectId: b.projectId, sessionId: b.sessionId, actorId: (b.actorId as string | null | undefined) ?? null }
}

export const POST = withRouteErrors('Could not check who else is writing the project', async (request: NextRequest) => {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const check = parse(await request.json().catch(() => null))
  if (!check) {
    return NextResponse.json({ error: 'Not an agent writer check', code: 'invalid_writer_check' }, { status: 400 })
  }
  const refused = await secondWriterResponse({ projectId: check.projectId, personId: check.userId })
  if (!refused) return NextResponse.json({ allowed: true })
  console.warn(`[rbac] agent run refused code=project_writer_busy session=${logValue(check.sessionId)}${check.actorId ? ` actor=${logValue(check.actorId)}` : ''}`)
  return refused
})
