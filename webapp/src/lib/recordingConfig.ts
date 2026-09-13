import prisma from '@/lib/prisma'
import { signTag } from '@/lib/redamonCtx'

export interface ActiveRecordingBlock {
  tag: string
  scope_hosts: string[]
  expires_at: string
}

/**
 * The `active_recording` block for the capture-config, or null when no recording
 * should be injected. Single global slot (the config is admin-global): the
 * newest unexpired active session whose project exists AND has captureProxyEnabled.
 * The operator tag is minted here with INTERNAL_API_KEY (source=operator).
 */
export async function activeRecordingBlock(now: Date = new Date()): Promise<ActiveRecordingBlock | null> {
  try {
    const session = await prisma.recordingSession.findFirst({
      where: { state: 'active', expiresAt: { gt: now } },
      orderBy: { startedAt: 'desc' },
      include: { project: { select: { id: true, captureProxyEnabled: true } } },
    })
    if (!session || !session.project || !session.project.captureProxyEnabled) return null

    const key = process.env.INTERNAL_API_KEY || ''
    if (!key || key === 'changeme') return null

    const tag = signTag({
      source: 'operator',
      project_id: session.projectId,
      user_id: session.userId,
      session_id: session.id,
    }, key)

    return {
      tag,
      scope_hosts: session.scopeHosts || [],
      expires_at: session.expiresAt.toISOString(),
    }
  } catch {
    // Fail closed: a recording-table error must never inject a tag, and must
    // never take down the (much more important) capture-config response.
    return null
  }
}
