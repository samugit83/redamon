/**
 * POST /api/internal/agent/sandbox/ensure (group 1, B.10): the agent asks for the Kali sandbox of
 * the person it works for, `{userId, projectId?, checkProjectId?, wait?, actingAs?}`, and gets its
 * address and per-instance tokens (200) or a start in progress (202). `checkProjectId` is refused
 * like `projectId` when the project is outside the person's list, but never asks the orchestrator
 * to mount it (triage's CVE lookup: G-14).
 *
 * The master key only (isInternalRequest; the scanner key is refused). The person is the agent's
 * claim, taken from a ticket, token or job it verified; this route cannot check who the agent acts
 * for (group 3, R9), but re-reads the account and computes the folders itself (gateway.ts): the
 * project id is a hint checked against that list, never added to it. The answer carries the
 * instance's tokens, so neither it nor the body is ever logged.
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { ensureSandbox, ensureStatus, sandboxFailureResponse } from '@/lib/sandbox/gateway'
import { validProjectId, validUserId } from '@/lib/sandbox/orchestratorClient'

export const runtime = 'nodejs'

const FAILED = 'Could not get the Kali sandbox for the agent'

const invalid = (code: string) =>
  NextResponse.json({ error: 'Not a valid sandbox request', code }, { status: 400 })

export async function POST(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const body: unknown = await request.json().catch(() => null)
  if (!body || typeof body !== 'object' || Array.isArray(body)) return invalid('invalid_sandbox_request')
  const { userId, projectId, checkProjectId, wait, actingAs } = body as Record<string, unknown>
  if (!validUserId(userId)) return invalid('invalid_user_id')
  for (const id of [projectId, checkProjectId]) {
    if (id !== undefined && id !== null && !validProjectId(id)) return invalid('invalid_project_id')
  }
  if ((wait !== undefined && typeof wait !== 'boolean') || (actingAs !== undefined && typeof actingAs !== 'boolean')) {
    return invalid('invalid_sandbox_request')
  }
  try {
    const answer = await ensureSandbox(userId, {
      needProject: (projectId as string | null | undefined) ?? null,
      checkProject: (checkProjectId as string | null | undefined) ?? null,
      wait: wait !== false,
      actingAs: actingAs === true,
    })
    return NextResponse.json(answer, { status: ensureStatus(answer) })
  } catch (err) {
    return sandboxFailureResponse(err, FAILED)
  }
}
