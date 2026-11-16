/**
 * Whether a resource's live version was ingested as it is configured today (§3.3, §6.13): the
 * card's "Ingested with older settings" badge. Three things make it stale:
 *   - its effective settings changed (the account's or its own overrides, `type.*` included);
 *   - its forced site type changed, which is no setting but changes what ingestion builds;
 *   - it is Stored, and its last ingestion did not take the Stored path: its pages are stored at
 *     the next ingestion.
 * Stored → Live is never stale: the stored text is deleted at once (§6.13), and the report's
 * stored counts go with it (`v2/update.ts`), so a later Live → Stored is stale again.
 *
 * The hash the job request carries is `ingestionHash`, so the one the agent writes at the swap
 * is compared with today's here. Auto (no forced type) keeps the plain settings hash, so the
 * resources ingested before the type joined it stay current.
 */
import type { IngestionReport } from './agentContract'
import { sha256Hex } from './effectiveSettings'
import { forcedStorageMode } from './storageModes'

export function ingestionHash(settingsHash: string, forcedType: string): string {
  return forcedType ? sha256Hex(`${settingsHash}|forced_type:${forcedType}`).slice(0, 16) : settingsHash
}

/**
 * The ingestion stored its pages, or counted the ones the quota or a size limit left out. The
 * second case is current: a re-ingestion under the same limits stores nothing more, so a badge
 * there could never be cleared.
 */
function tookStoredPath(report: IngestionReport): boolean {
  const s = report.stored
  return s.pages + s.notStoredQuota + s.notStoredSize > 0
}

export function isStale(
  row: { settingsHash: string; forcedType: string; resourceType: string; storageMode: string },
  currentSettingsHash: string,
  report: IngestionReport | null,
): boolean {
  // A resource 2.0 never ingested has no hash: it shows the "before 2.0" badge instead.
  if (row.settingsHash === '') return false
  if (row.settingsHash !== ingestionHash(currentSettingsHash, row.forcedType)) return true
  if (row.storageMode !== 'stored' || !report || report.kept === 0) return false
  // A CVE archive never stores text, whatever its row says.
  if (forcedStorageMode(row.forcedType || row.resourceType) === 'live') return false
  return !tookStoredPath(report)
}
