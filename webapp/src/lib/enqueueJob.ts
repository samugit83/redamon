/**
 * Create a JobQueue row (Scan Queue plan). Shared by every producer: the refusal
 * modal (Phase 3), the scheduler (Phase 4), and the org batch (Phase 6). Callers
 * own authorization (guardProject / internal key); this only writes the row.
 *
 * The settings fingerprint is computed HERE, at enqueue, so the dispatcher can
 * detect a config change between enqueue and dispatch and refuse to run the new
 * config (C-4). The version is deliberately NOT captured (C-3): it is chosen at
 * dispatch by prepareVersionsForFullScan.
 */
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { envelopeForKind, settingsFingerprint } from '@/lib/jobQueue'
import { resolveTrufflehogFingerprintExtra } from '@/lib/trufflehogStart'
import { authProfileFingerprintExtra } from '@/lib/authProfileFingerprint'

export const QUEUEABLE_KINDS = [
  'full_recon', 'partial_recon', 'gvm', 'github_hunt', 'trufflehog',
  'supply_chain', 'supply_chain_repo', 'ai_attack',
] as const

export type QueueableKind = (typeof QUEUEABLE_KINDS)[number]

export function isQueueableKind(kind: string): kind is QueueableKind {
  return (QUEUEABLE_KINDS as readonly string[]).includes(kind)
}

export interface EnqueueInput {
  projectId: string
  userId: string
  kind: string
  payload?: Record<string, unknown>
  /** manual 10 > scheduled 0 > batch item -10. Default manual. */
  priority?: number
  scheduleId?: string | null
  batchId?: string | null
}

export interface EnqueueResult {
  ok: boolean
  status: number
  error?: string
  id?: string
}

export async function enqueueJob(input: EnqueueInput): Promise<EnqueueResult> {
  const { projectId, userId, kind } = input
  const payload = input.payload ?? {}

  if (!isQueueableKind(kind)) {
    return { ok: false, status: 400, error: `Unknown scan kind: ${kind}` }
  }

  // An ai_attack payload can carry an inline api_key (a secret). It must never be
  // stored in a queue row, so such a job is not queueable at all (Phase 3 / Security).
  if (kind === 'ai_attack') {
    const apiKey = payload.api_key
    if (typeof apiKey === 'string' && apiKey.trim() !== '') {
      return {
        ok: false,
        status: 400,
        error: 'This AI scan carries an inline API key, which must not be stored in a queue. Cancel and retry once memory frees.',
      }
    }
  }

  const project = await prisma.project.findUnique({ where: { id: projectId } })
  if (!project) return { ok: false, status: 404, error: 'Project not found' }

  // TruffleHog's targets live on a per-source profile, not the Project row, so
  // the fingerprint has to fetch it before hashing (section 4 / C-4).
  const fingerprintExtra = {
    ...(await resolveTrufflehogFingerprintExtra(kind, projectId, payload)),
    ...(await authProfileFingerprintExtra(kind, projectId)),
  }
  const settingsHash = settingsFingerprint(
    kind, project as unknown as Record<string, unknown>, fingerprintExtra,
  )
  const envelopeBytes = BigInt(envelopeForKind(kind))

  const row = await prisma.jobQueue.create({
    data: {
      projectId,
      userId,
      kind,
      payload: payload as Prisma.InputJsonValue,
      settingsHash,
      envelopeBytes,
      priority: input.priority ?? 10,
      scheduleId: input.scheduleId ?? null,
      batchId: input.batchId ?? null,
      status: 'queued',
    },
    select: { id: true },
  })

  return { ok: true, status: 201, id: row.id }
}
