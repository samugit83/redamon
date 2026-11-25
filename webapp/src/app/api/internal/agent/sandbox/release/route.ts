/**
 * POST /api/internal/agent/sandbox/release (group 1, B.8, B.10): the agent releases a lease at the
 * end of a unit of work, `{userId, leaseId}`. The master key only. No account re-check: releasing
 * only lets a sandbox stop sooner. 204 on success.
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { releaseSandboxLease, sandboxFailureResponse } from '@/lib/sandbox/gateway'
import { validLeaseId, validUserId } from '@/lib/sandbox/orchestratorClient'

export const runtime = 'nodejs'

const FAILED = 'Could not release the Kali sandbox lease'

const invalid = (code: string) =>
  NextResponse.json({ error: 'Not a valid sandbox release request', code }, { status: 400 })

export async function POST(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const body: unknown = await request.json().catch(() => null)
  if (!body || typeof body !== 'object' || Array.isArray(body)) return invalid('invalid_sandbox_request')
  const { userId, leaseId } = body as Record<string, unknown>
  if (!validUserId(userId)) return invalid('invalid_user_id')
  if (!validLeaseId(leaseId)) return invalid('invalid_sandbox_request')
  try {
    await releaseSandboxLease(userId, leaseId)
    return new NextResponse(null, { status: 204 })
  } catch (err) {
    return sandboxFailureResponse(err, FAILED)
  }
}
