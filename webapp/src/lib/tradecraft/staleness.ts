/**
 * Whether a resource's live version was ingested as it is configured today (§3.3, §6.13): the
 * card's "Ingested with older settings" badge. Three things make it stale:
 *   - its effective settings changed (the account's or its own overrides, `type.*` included);
 *   - its forced site type changed, which is no setting but changes what ingestion builds;
 *   - it became Stored after a Live ingestion: its pages are stored at the next ingestion.
 * Stored → Live is never stale: the stored text is deleted at once (§6.13).
 *
 * The hash the job request carries is `ingestionHash`, so the one the agent writes at the swap
 * is compared with today's here. Auto (no forced type) keeps the plain settings hash, so the
 * resources ingested before the type joined it stay current.
 */
import type { IngestionReport } from './agentContract'
import { sha256Hex } from './effectiveSettings'

export function ingestionHash(settingsHash: string, forcedType: string): string {
  return forcedType ? sha256Hex(`${settingsHash}|forced_type:${forcedType}`).slice(0, 16) : settingsHash
}

export function isStale(
  row: { settingsHash: string; forcedType: string; storageMode: string },
  currentSettingsHash: string,
  report: IngestionReport | null,
): boolean {
  // A resource 2.0 never ingested has no hash: it shows the "before 2.0" badge instead.
  if (row.settingsHash === '') return false
  if (row.settingsHash !== ingestionHash(currentSettingsHash, row.forcedType)) return true
  return row.storageMode === 'stored' && !!report && report.kept > 0 && report.stored.pages === 0
}
