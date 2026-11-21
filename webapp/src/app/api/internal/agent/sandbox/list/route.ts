/**
 * GET /api/internal/agent/sandbox/list (group 1, B.10, B.12): every running sandbox with its host
 * and bearer, for the agent's fan-out (`/sessions`, the hold watcher, the emergency stop). The master
 * key only: this list carries every instance's token and never reaches a browser (the admin
 * Operations view reads `listSandboxes`, which strips them).
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { agentSandboxList, sandboxFailureResponse } from '@/lib/sandbox/gateway'

export const runtime = 'nodejs'

const FAILED = 'Could not list the Kali sandboxes'

export async function GET(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  try {
    return NextResponse.json(await agentSandboxList())
  } catch (err) {
    return sandboxFailureResponse(err, FAILED)
  }
}
