import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { requireSession } from '@/lib/session'
import { agentErrorResponse, callAgent } from '../../../agentProxy'

const FAILED = 'Failed to interact with session'

export const POST = withRouteErrors(FAILED, async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const { id } = await params
  const body = await request.json().catch(() => null)
  if (!body || typeof body !== 'object') {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }
  // The agent waits up to 40s on the session manager; ours must outlast it.
  const call = await callAgent(`/sessions/${encodeURIComponent(id)}/interact`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, FAILED, { timeoutMs: 45_000 })
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
