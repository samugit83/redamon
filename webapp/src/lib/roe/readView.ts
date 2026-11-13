/**
 * What anyone who may read a project's Rules of Engagement (`roe:read`) sees of them, a read
 * collaborator included (OQ-53, SH-28): the document's metadata (file name, type, size, upload date,
 * how many superseded documents are kept) and the scope and time window the engagement enforces.
 * Never the client's name or contacts, the emergency contact, the extracted text, the parsed JSON or
 * the document itself: those stay the owner's (`share: secret` in recon_settings/registry.yaml), and
 * the two downloads refuse anyone else (projectReadView.ts).
 *
 * The limits come from the registry's `engagement_limits` group (what scan start enforces), so a
 * limit added there is shown here without a change; the derived `roeEnabled` is answered as
 * `enforced`, computed the way recon and the orchestrator compute it.
 */
import prisma from '@/lib/prisma'
import { deriveRoeEnabled } from '@/lib/engagement'
import { engagementLimitFields } from '@/lib/reconSettings/registry'

export interface RoeReadView {
  document: { name: string; mimeType: string; size: number; uploadedAt: string | null } | null
  /** Superseded documents kept; their metadata is GET .../roe/revisions. */
  revisions: number
  engagement: { type: string; startDate: string; endDate: string }
  /** Whether scan start applies the limits (a ceiling, an excluded host or the time window). */
  enforced: boolean
  limits: Record<string, unknown>
}

/** The limit columns the view carries: enforced at scan start, ordinary, stored (not derived). */
export const ROE_LIMIT_KEYS: readonly string[] = Object.freeze(
  engagementLimitFields()
    .filter(f => f.share !== 'secret' && f.deny_reason !== 'derived')
    .map(f => f.key),
)

const ENGAGEMENT_KEYS = ['roeEngagementType', 'roeEngagementStartDate', 'roeEngagementEndDate'] as const

/** The stored parse records when the current document was applied; anything else reads as unknown. */
function uploadedAtOf(parsed: unknown): string | null {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
  const at = (parsed as Record<string, unknown>).appliedAt
  if (typeof at !== 'string') return null
  const d = new Date(at)
  return Number.isNaN(d.getTime()) ? null : d.toISOString()
}

const asString = (v: unknown): string => (typeof v === 'string' ? v : '')

export function buildRoeReadView(
  row: Record<string, unknown>,
  stored: { documentBytes: number; revisions: number },
): RoeReadView {
  const name = asString(row.roeDocumentName)
  const hasDocument = stored.documentBytes > 0 || name !== ''
  const limits: Record<string, unknown> = {}
  for (const key of ROE_LIMIT_KEYS) limits[key] = row[key] ?? null
  return {
    document: hasDocument
      ? { name, mimeType: asString(row.roeDocumentMimeType), size: stored.documentBytes, uploadedAt: uploadedAtOf(row.roeParsedJson) }
      : null,
    revisions: stored.revisions,
    engagement: {
      type: asString(row.roeEngagementType),
      startDate: asString(row.roeEngagementStartDate),
      endDate: asString(row.roeEngagementEndDate),
    },
    enforced: deriveRoeEnabled(row as Parameters<typeof deriveRoeEnabled>[0]),
    limits,
  }
}

/**
 * The view of one project, or null when it does not exist. The document's size is read in the
 * database (`octet_length`), so the bytes never leave it; the parse is read only for its date.
 */
export async function roeReadView(projectId: string): Promise<RoeReadView | null> {
  const select: Record<string, true> = { roeDocumentName: true, roeDocumentMimeType: true, roeParsedJson: true }
  for (const key of [...ROE_LIMIT_KEYS, ...ENGAGEMENT_KEYS]) select[key] = true
  const row = await prisma.project.findUnique({ where: { id: projectId }, select })
  if (!row) return null
  const [sizes, revisions] = await Promise.all([
    prisma.$queryRaw<Array<{ bytes: number | null }>>`
      SELECT octet_length(roe_document_data)::int AS bytes FROM projects WHERE id = ${projectId}
    `,
    prisma.roeDocumentRevision.count({ where: { projectId } }),
  ])
  return buildRoeReadView(row as Record<string, unknown>, { documentBytes: Number(sizes[0]?.bytes ?? 0), revisions })
}
