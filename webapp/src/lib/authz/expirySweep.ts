/**
 * The RBAC expiry sweep (step 4.15; SH-14, DV-09, T19), run by POST /api/internal/rbac/sweep,
 * which the orchestrator's reaper loop calls every RBAC_SWEEP_INTERVAL seconds (the webapp has no
 * scheduler). Expiry is judged lazily wherever access is read, so an expired share, override,
 * break-glass row or link already counts for nothing and correctness never waits on this sweep: it
 * writes the `.expired` audit rows and removes the dead rows.
 *
 * - expired shares: `project.share.expired`, removed; then, as after a revoke, the collaborator's
 *   live work on that project stops (`onAccessReduced`, step 5.9; best effort: a close the agent
 *   does not confirm logs `[rbac] socket-close failed` and the expiry stands);
 * - expired overrides: `user.override_expired`, removed (capabilities.ts already ignores them);
 * - expired break-glass rows, and expired unused invite and reset links: removed (their creation
 *   is audited and names the expiry). A used link is kept, the record of how an account was set up.
 * - device sessions (step 6.10): a row revoked or expired more than 30 days ago is removed, with the
 *   address and browser it kept (no audit row: the revocation was audited, an expiry is not news).
 * - audit retention (step 6.6): Root's change whose delay is over moves into force (audited
 *   `instance.audit_retention_activated`), then the audit_log rows older than the retention go, except
 *   the rows the code reads back (lib/authz/auditRetention.ts); with RBAC_GOVERNANCE_ENABLED only, and
 *   its answer's `auditRetention` exists only then.
 *
 * Each part runs only with its switch on, so with a switch off nothing of it is read
 * (*.flags.off.test.ts): shares and break-glass with sharing in force (RBAC_SHARING_ENABLED and the
 * instance policy), overrides with RBAC_PERMISSIONS_ENABLED, links with RBAC_IDENTITY_ENABLED, device
 * sessions with RBAC_GOVERNANCE_ENABLED (whose `removed.devices` exists only then, so the answer with
 * the switch off is the one before it).
 *
 * Any webapp copy may answer, and two may sweep at once: each audited row is removed by a delete
 * conditional on its expiry, in the transaction that writes its audit row, and only a delete that
 * removed the row writes it. Postgres makes a second delete of the same row wait for the first and
 * then match nothing, and a share renewed after the read no longer matches, so each expiry is
 * audited once and nothing live is removed.
 */
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { now } from './clock'
import { rbacFlags } from './flags'
import { sharingInForce } from './sharingPolicy'
import { sweepDeviceSessions } from './deviceSessions'
import { sweepAuditRetention, type RetentionSweep } from './auditRetention'
import { onAccessReduced } from './revocation'

/** Audited rows of one kind handled per sweep; the rest wait for the next sweep. */
export const SWEEP_BATCH = 500
// Expired shares whose sockets are closed at once (as endSessionsOf's batches).
const SOCKET_CLOSE_BATCH = 8

export type SweepPart = 'shares' | 'breakGlass' | 'overrides' | 'links' | 'devices' | 'auditRetention'
type CorePart = Exclude<SweepPart, 'devices' | 'auditRetention'>

export interface SweepResult {
  at: string
  /**
   * Rows removed per part; null when the part's switch is off (or its gate could not be read).
   * `devices` only with the governance switch on.
   */
  removed: Record<CorePart, number | null> & { devices?: number | null }
  /** Expired shares whose sockets the agent did not confirm closed. */
  socketCloseFailed: number
  /** The parts that failed; their rows stay for the next sweep. */
  failed: SweepPart[]
  /** Audit retention: the days applied and the rows deleted; null when it failed. Governance switch only. */
  auditRetention?: RetentionSweep | null
}

interface ShareEnded { userId: string; projectId: string }

const iso = (d: Date | null) => (d ? d.toISOString() : null)

async function sweepShares(at: Date, ended: ShareEnded[]): Promise<number> {
  const rows = await prisma.projectCollaborator.findMany({
    where: { expiresAt: { lte: at } },
    select: {
      projectId: true, userId: true, access: true, rawData: true, runScans: true, useAgent: true,
      exploit: true, manage: true, expiresAt: true, grantedById: true,
    },
    orderBy: { expiresAt: 'asc' },
    take: SWEEP_BATCH,
  })
  let removed = 0
  for (const row of rows) {
    const gone = await auditedTransaction(prisma, async (tx) => {
      const { count } = await tx.projectCollaborator.deleteMany({
        where: { projectId: row.projectId, userId: row.userId, expiresAt: { lte: at } },
      })
      if (count !== 1) return false
      await writeAuditTx(tx, {
        actorId: null,
        projectId: row.projectId,
        action: 'project.share.expired',
        targetType: 'user',
        targetId: row.userId,
        before: {
          access: row.access, rawData: row.rawData, runScans: row.runScans, useAgent: row.useAgent,
          exploit: row.exploit, manage: row.manage, expiresAt: iso(row.expiresAt), grantedById: row.grantedById,
        },
        source: 'system',
      })
      return true
    })
    if (gone) {
      removed += 1
      ended.push({ userId: row.userId, projectId: row.projectId })
    }
  }
  return removed
}

async function sweepOverrides(at: Date): Promise<number> {
  const rows = await prisma.userPermissionOverride.findMany({
    where: { expiresAt: { lte: at } },
    select: { userId: true, permission: true, effect: true, expiresAt: true, reason: true },
    orderBy: { expiresAt: 'asc' },
    take: SWEEP_BATCH,
  })
  let removed = 0
  for (const row of rows) {
    const gone = await auditedTransaction(prisma, async (tx) => {
      const { count } = await tx.userPermissionOverride.deleteMany({
        where: { userId: row.userId, permission: row.permission, expiresAt: { lte: at } },
      })
      if (count !== 1) return false
      // The same override fields as user.permissions_changed records (userPermissionAdmin.ts).
      await writeAuditTx(tx, {
        actorId: null,
        action: 'user.override_expired',
        targetType: 'user',
        targetId: row.userId,
        before: { permission: row.permission, effect: row.effect, expiresAt: iso(row.expiresAt), reason: row.reason },
        source: 'system',
      })
      return true
    })
    if (gone) removed += 1
  }
  return removed
}

async function sweepBreakGlass(at: Date): Promise<number> {
  const { count } = await prisma.projectBreakGlass.deleteMany({ where: { expiresAt: { lte: at } } })
  return count
}

async function sweepLinks(at: Date): Promise<number> {
  const { count } = await prisma.userInvite.deleteMany({ where: { expiresAt: { lte: at }, usedAt: null } })
  return count
}

/** Stops the live work of each ended share; the number whose sockets the agent did not confirm closed. Never throws. */
async function closeEndedShares(ended: readonly ShareEnded[]): Promise<number> {
  let failed = 0
  for (let i = 0; i < ended.length; i += SOCKET_CLOSE_BATCH) {
    const batch = ended.slice(i, i + SOCKET_CLOSE_BATCH)
    const results = await Promise.all(batch.map(({ userId, projectId }) => onAccessReduced(projectId, userId, 'share_expired')))
    const refused = results.filter((r) => 'error' in r.sockets).length
    failed += refused
    const rest = ended.length - i - batch.length
    // A whole batch refused: the agent is down, and each further call would wait out its timeout.
    if (rest > 0 && refused === batch.length) {
      console.error(`[rbac] socket-close failed for ${rest} more expired share(s): the agent did not answer`)
      failed += rest
      break
    }
  }
  return failed
}

export async function sweepExpired(): Promise<SweepResult> {
  const at = now()
  const flags = rbacFlags()
  const removed: SweepResult['removed'] = { shares: null, breakGlass: null, overrides: null, links: null }
  if (flags.governance) removed.devices = null
  const failed: SweepPart[] = []
  const ended: ShareEnded[] = []

  const run = async (part: Exclude<SweepPart, 'auditRetention'>, sweep: () => Promise<number>) => {
    try {
      removed[part] = await sweep()
    } catch (err) {
      failed.push(part)
      console.error(`[rbac] sweep failed part=${part}:`, err)
    }
  }

  if (flags.identity) await run('links', () => sweepLinks(at))
  if (flags.permissions) await run('overrides', () => sweepOverrides(at))
  if (flags.sharing) {
    let inForce = false
    try {
      inForce = (await sharingInForce()).enabled
    } catch (err) {
      failed.push('shares', 'breakGlass')
      console.error('[rbac] sweep failed part=shares,breakGlass: the sharing policy could not be read:', err)
    }
    if (inForce) {
      await run('shares', () => sweepShares(at, ended))
      await run('breakGlass', () => sweepBreakGlass(at))
    }
  }

  if (flags.governance) await run('devices', () => sweepDeviceSessions(at))
  let auditRetention: RetentionSweep | null | undefined
  if (flags.governance) {
    try {
      auditRetention = await sweepAuditRetention(at)
    } catch (err) {
      auditRetention = null
      failed.push('auditRetention')
      console.error('[rbac] sweep failed part=auditRetention:', err)
    }
  }

  const socketCloseFailed = ended.length ? await closeEndedShares(ended) : 0
  if (Object.values(removed).some((n) => n) || auditRetention?.deleted || auditRetention?.activated) {
    const shown = (n: number | null) => (n === null ? 'off' : String(n))
    console.info(
      `[rbac] sweep removed shares=${shown(removed.shares)} breakglass=${shown(removed.breakGlass)} `
      + `overrides=${shown(removed.overrides)} links=${shown(removed.links)}`
      + (removed.devices !== undefined ? ` devices=${shown(removed.devices)}` : '')
      + (auditRetention?.deleted ? ` audit_rows=${auditRetention.deleted} (retention ${auditRetention.days} days)` : '')
      + (auditRetention?.activated ? ' audit_retention_change_applied' : '')
      + (socketCloseFailed ? ` socket_close_failed=${socketCloseFailed}` : ''),
    )
  }
  return { at: at.toISOString(), removed, socketCloseFailed, failed, ...(auditRetention !== undefined ? { auditRetention } : {}) }
}
