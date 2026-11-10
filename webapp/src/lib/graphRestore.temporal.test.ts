/**
 * R-38: a restored finding must be prunable.
 *
 * The export and the Scan Timeline snapshot flatten every Neo4j DateTime to
 * `YYYY-MM-DDTHH:MM:SSZ` (graphSerialize.ts). Written back as that string, the
 * recon prune's `n.updated_at < datetime($since)` is null, so a finding restored
 * from an export or a version was never pruned nor stamped stale. A restore now
 * writes RedAmon's own timestamps back as DateTimes, and leaves every other
 * string alone: `matched_at` is a URL, and js_recon stores `discovered_at` as a
 * string in exactly the exported shape.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import { isDateTime, type Session } from 'neo4j-driver'
import { serializeGraphValue } from './graphSerialize'
import { restoreGraph, restoredTemporal } from './graphRestore'

function fakeSession(): { session: Session; written: () => Array<Record<string, unknown>> } {
  const calls: Array<{ cypher: string; params: Record<string, unknown> }> = []
  const run = vi.fn(async (cypher: string, params: Record<string, unknown> = {}) => {
    calls.push({ cypher, params })
    return { records: [] }
  })
  const written = () => calls
    .filter(c => c.cypher.includes('apoc.create.node') || c.cypher.includes('apoc.merge.node'))
    .flatMap(c => c.params.nodes as Array<{ properties: Record<string, unknown> }>)
    .map(n => n.properties)
  return { session: { run } as unknown as Session, written }
}

async function restoreOne(properties: Record<string, unknown>) {
  const { session, written } = fakeSession()
  await restoreGraph(session, [{ labels: ['Vulnerability'], properties, _exportId: 'v1' }], [],
    { projectId: 'p1' })
  return written()[0]
}

describe('restoreGraph — timestamps come back as DateTimes (R-38)', () => {
  test('the prune and revive timestamps are DateTimes after a restore', async () => {
    const props = await restoreOne({
      id: 'v1', source: 'nuclei',
      updated_at: '2026-10-01T08:30:15Z', stale_since: '2026-10-02T09:00:00Z',
      created_at: '2026-09-30T23:59:59Z', muted_at: '2026-10-03T00:00:01Z',
      triaged_at: '2026-10-04T12:00:00Z',
    })
    for (const key of ['updated_at', 'stale_since', 'created_at', 'muted_at', 'triaged_at']) {
      expect(isDateTime(props[key]), key).toBe(true)
    }
    const updated = props.updated_at as { toString(): string; timeZoneOffsetSeconds: number }
    expect(updated.toString()).toBe('2026-10-01T08:30:15Z')
    expect(updated.timeZoneOffsetSeconds).toBe(0)
  })

  test('a restored DateTime exports to the same bytes it was restored from', async () => {
    const props = await restoreOne({ id: 'v1', updated_at: '2026-10-01T08:30:15Z' })
    expect(serializeGraphValue(props.updated_at)).toBe('2026-10-01T08:30:15Z')
  })

  test('strings that are not an exported DateTime stay strings', async () => {
    const props = await restoreOne({
      id: 'v1',
      matched_at: 'https://app.example.com/login',
      discovered_at: '2026-10-01T08:30:15Z',
      created_at: '2026-10-01T08:30:15.123456+00:00',
      updated_at: 'unknown',
      name: '2026-10-01T08:30:15Z',
    })
    expect(props).toMatchObject({
      matched_at: 'https://app.example.com/login',
      discovered_at: '2026-10-01T08:30:15Z',
      created_at: '2026-10-01T08:30:15.123456+00:00',
      updated_at: 'unknown',
      name: '2026-10-01T08:30:15Z',
    })
  })

  test('an impossible date is left as it was rather than failing the restore', () => {
    expect(restoredTemporal('updated_at', '2026-13-45T25:61:61Z')).toBe('2026-13-45T25:61:61Z')
    expect(restoredTemporal('updated_at', '2026-02-30T00:00:00Z')).toBe('2026-02-30T00:00:00Z')
  })

  test('values that are not strings pass through untouched', () => {
    expect(restoredTemporal('updated_at', null)).toBeNull()
    expect(restoredTemporal('updated_at', 7)).toBe(7)
  })
})
