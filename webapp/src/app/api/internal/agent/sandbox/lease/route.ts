/**
 * POST /api/internal/agent/sandbox/lease (group 1, B.8, B.10): the agent takes or renews a lease on
 * a person's sandbox instance, `{userId, instance, leaseId, kind}`; the same call renews an existing
 * `leaseId`. The master key only. The account is re-read on every take and renewal (gateway.ts), so
 * a disabled or stripped account's sandbox loses its leases and stops. Answers the orchestrator's
 * `{expires_at, state, stop_at, warn}`, or its 404 / 409 codes.
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { leaseSandbox, sandboxFailureResponse } from '@/lib/sandbox/gateway'
import { isLeaseKind, validInstance, validLeaseId, validUserId } from '@/lib/sandbox/orchestratorClient'

export const runtime = 'nodejs'

const FAILED = 'Could not take or renew the Kali sandbox lease'

const invalid = (code: string) =>
  NextResponse.json({ error: 'Not a valid sandbox lease request', code }, { status: 400 })

export async function POST(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const body: unknown = await request.json().catch(() => null)
  if (!body || typeof body !== 'object' || Array.isArray(body)) return invalid('invalid_sandbox_request')
  const { userId, instance, leaseId, kind } = body as Record<string, unknown>
  if (!validUserId(userId)) return invalid('invalid_user_id')
  if (!validInstance(instance) || !validLeaseId(leaseId) || !isLeaseKind(kind)) return invalid('invalid_sandbox_request')
  try {
    return NextResponse.json(await leaseSandbox(userId, { instance, leaseId, kind }))
  } catch (err) {
    return sandboxFailureResponse(err, FAILED)
  }
}
