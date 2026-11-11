/**
 * Recon coverage carried by the graph.
 *
 * The recon pipeline records, on each covered `Domain`, which finding sources it
 * could not fully re-check this run (a circuit breaker opened, a host went
 * unreachable, Nuclei was truncated): `recon_coverage_at`, `recon_coverage_gaps`
 * (a JSON array of `{ source, ... }`), `recon_skipped_hosts`, `recon_nuclei_truncated`.
 *
 * The orchestrator cannot count this from logs (it only parses while a viewer
 * streams, replays from container start, and reaps the container ~30s after
 * exit), so the graph record is the carrier. This module reads it at run close
 * to stamp `ScanJob.degradedSources`, and for the delta/report views.
 */
import { getGraphSession } from '@/app/api/graph/neo4j'
import { IP_HOSTNAME_SELECT, type ScopeFields, resolveScopeGroups } from '@/lib/scopeGroups'

/** A single parsed coverage gap. Only `source` is relied on here. */
export interface CoverageGap {
  source: string
  [key: string]: unknown
}

/**
 * Parse a `recon_coverage_gaps` value into an array of gaps, or `null` when it
 * is not a JSON array of objects with a string `source` of <=64 chars. An
 * imported/exported bundle is untrusted, so anything malformed is rejected
 * rather than trusted or coerced.
 */
export function parseCoverageGaps(raw: unknown): CoverageGap[] | null {
  let value = raw
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value)
    } catch {
      return null
    }
  }
  if (!Array.isArray(value)) return null
  const out: CoverageGap[] = []
  for (const entry of value) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
    const source = (entry as { source?: unknown }).source
    if (typeof source !== 'string' || source.length === 0 || source.length > 64) return null
    out.push(entry as CoverageGap)
  }
  return out
}

/**
 * The project's current scan roots, lower-cased, for the coverage filters
 * below; null when there is nothing to filter by (IP mode, no target).
 */
export const SCOPE_SELECT = {
  ipMode: true, domainBatchMode: true, domainBatchHosts: true, targetDomain: true, subdomainList: true,
  // An IP project's hostname policy is part of its scope: which scanned names
  // still count as covered hosts is the current policy's call (design §6.3).
  ...IP_HOSTNAME_SELECT,
} as const

export function currentScanRoots(project: ScopeFields): Set<string> | null {
  const roots = resolveScopeGroups(project).groups.map(g => g.scanRoot.toLowerCase())
  return roots.length ? new Set(roots) : null
}

/**
 * Is this coverage entry about a current scan root (§4.11.7)? The org Domain
 * keeps a removed root's entries until the next full recon clears the graph.
 * A gap carries its `root`; a gap with none (written before roots were tagged)
 * is kept. `null` roots keep everything.
 */
export function gapInScope(gap: CoverageGap, roots: ReadonlySet<string> | null): boolean {
  if (!roots || typeof gap.root !== 'string' || !gap.root) return true
  return roots.has(gap.root.toLowerCase())
}

/** Is a skipped `host:port` under a current scan root? Its root is the longest
 *  scan root it equals or sits under; none means a removed root's host. */
export function skippedHostInScope(hostPort: string, roots: ReadonlySet<string> | null): boolean {
  if (!roots) return true
  const host = hostPort.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase()
  for (const r of roots) if (host === r || host.endsWith(`.${r}`)) return true
  return false
}

/**
 * The number of distinct degraded finding sources across every covered `Domain`
 * of a project's latest run, or `null` when coverage is unknown.
 *
 * Returns `null` when no `Domain` carries `recon_coverage_at` (the run predates
 * the feature, or wrote nothing), or when any gaps value fails to parse. Returns
 * `0` when coverage was recorded and clean. Never throws.
 */
export async function readDegradedSourceCount(
  projectId: string, roots: ReadonlySet<string> | null = null,
): Promise<number | null> {
  let session
  try {
    session = getGraphSession()
  } catch {
    return null
  }
  try {
    const res = await session.run(
      `MATCH (d:Domain {project_id: $pid})
       WHERE d.recon_coverage_at IS NOT NULL
       RETURN d.recon_coverage_gaps AS gaps`,
      { pid: projectId },
    )
    if (!res.records.length) return null
    const sources = new Set<string>()
    for (const record of res.records) {
      const gaps = parseCoverageGaps(record.get('gaps'))
      if (gaps === null) return null // fail closed on any unparseable record
      for (const gap of gaps) if (gapInScope(gap, roots)) sources.add(gap.source)
    }
    return sources.size
  } catch {
    return null
  } finally {
    try {
      await session.close()
    } catch {
      /* already closed */
    }
  }
}
