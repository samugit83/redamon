import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { requireSession } from '@/lib/session'
import { agentErrorResponse, callAgent } from '../../../agentProxy'

const FAILED = 'Failed to kill job'

export const POST = withRouteErrors(FAILED, async (
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const { id } = await params
  const call = await callAgent(`/jobs/${encodeURIComponent(id)}/kill`, { method: 'POST' }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
