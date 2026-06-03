import { HIDDEN_KEYS } from '../../utils'
import type { TableRow } from '../../hooks/useTableData'

export interface GroupedRows {
  /** Sorted (ascending, locale-aware) list of distinct node types present. */
  sortedTypes: string[]
  /** Count of nodes per type. */
  typeCounts: Map<string, number>
  /** Rows partitioned by node type. */
  rowsByType: Map<string, TableRow[]>
}

const PRIORITY_DYNAMIC_KEYS = [
  'first_seen',
  'last_seen',
  'first_seen_job_id',
  'last_seen_job_id',
]

/**
 * Partitions a flat list of TableRows by node.type and computes per-type counts
 * + a sorted type list. Pure — no side effects.
 */
export function groupRowsByType(rows: readonly TableRow[]): GroupedRows {
  const typeCounts = new Map<string, number>()
  const rowsByType = new Map<string, TableRow[]>()

  for (const row of rows) {
    const t = row.node.type
    typeCounts.set(t, (typeCounts.get(t) ?? 0) + 1)
    if (!rowsByType.has(t)) rowsByType.set(t, [])
    rowsByType.get(t)!.push(row)
  }

  const sortedTypes = Array.from(typeCounts.keys()).sort((a, b) => a.localeCompare(b))
  return { sortedTypes, typeCounts, rowsByType }
}

/**
 * Derives the dynamic column keys for a given list of rows: the sorted union of
 * every property key found across the rows, minus HIDDEN_KEYS and the special
 * "name" key (which is always rendered as a fixed column).
 *
 * Pure — no side effects. Result is locale-sorted ascending.
 */
export function deriveDynamicColumnKeys(rows: readonly TableRow[]): string[] {
  const keys = new Set<string>()
  for (const r of rows) {
    for (const k of Object.keys(r.node.properties)) {
      if (HIDDEN_KEYS.has(k)) continue
      if (k === 'name') continue
      keys.add(k)
    }
  }
  const prioritized = PRIORITY_DYNAMIC_KEYS.filter(key => keys.delete(key))
  const remaining = Array.from(keys).sort((a, b) => a.localeCompare(b))
  return [...prioritized, ...remaining]
}

/**
 * Toggles the membership of `key` in the hidden-columns set.
 * Returns a NEW array (does not mutate input).
 */
export function toggleHiddenColumn(currentHidden: readonly string[], key: string): string[] {
  const set = new Set(currentHidden)
  if (set.has(key)) set.delete(key)
  else set.add(key)
  return Array.from(set)
}
