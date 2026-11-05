/**
 * The one-time backfill that keeps Jev running on projects that existed before
 * per-project provider selection (scripts/backfill-jev-provider-selection.mjs): each
 * such project gets its owner's single TypeSafe row selected, nothing created after the
 * new code first started is touched, and an AuditLog marker written in the same
 * transaction makes a second boot do nothing.
 *
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, beforeEach, afterEach } from 'vitest'
import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { setNowForTests } from '@/lib/plugins/clock'
import {
  CUTOFF_ACTION, LEGACY_PROVIDER_TYPE, MARKER_ACTION, backfillJevProviderSelection,
} from '../../scripts/backfill-jev-provider-selection.mjs'

let db: FakePrisma

const selection = (id: string) => db.rows('project').find((p) => p.id === id)!.jevProviderId
const markers = () => db.rows('auditLog').filter((r) => r.action === MARKER_ACTION)
const cutoffs = () => db.rows('auditLog').filter((r) => r.action === CUTOFF_ACTION)

/** Records each project write; `fail` makes the first one throw. */
function instrument(fail = false) {
  const writes: string[] = []
  const tx = db.$transaction.bind(db)
  ;(db as unknown as Record<string, unknown>).$transaction = (fn: (t: FakePrisma) => Promise<unknown>) =>
    tx(async (t) => {
      const p = t.project as unknown as Record<string, (a: unknown) => Promise<unknown>>
      const update = p.update
      p.update = async (a) => {
        writes.push('update')
        if (fail) throw new Error('connection reset')
        return update(a)
      }
      p.updateMany = async () => { throw new Error('updateMany would leave updatedAt unmoved') }
      return fn(t)
    })
  return writes
}

beforeEach(() => {
  db = createFakePrisma()
})

describe('backfillJevProviderSelection', () => {
  test('the legacy type is the TypeSafe one every pre-selection row had', () => {
    expect(LEGACY_PROVIDER_TYPE).toBe('jev')
    expect(MARKER_ACTION).toBe('system.jev_provider_selection_backfill')
  })

  test("selects the owner's TypeSafe row on every unselected project, whatever its hooks", async () => {
    db.seed('userLlmProvider', [
      { id: 'alice-jev', userId: 'alice', providerType: 'jev' },
      { id: 'alice-chat', userId: 'alice', providerType: 'anthropic' },
    ])
    db.seed('project', [
      { id: 'p-on', userId: 'alice', jevProviderId: null, nucleiAiUseJev: true },
      { id: 'p-off', userId: 'alice', jevProviderId: null },
    ])
    expect(await backfillJevProviderSelection(db)).toEqual({ done: true, projects: 2, owners: 1, ambiguousOwners: 0 })
    expect(selection('p-on')).toBe('alice-jev')
    expect(selection('p-off')).toBe('alice-jev')
  })

  test("a project's own owner only, and an existing selection is never replaced", async () => {
    db.seed('userLlmProvider', [
      { id: 'alice-jev', userId: 'alice', providerType: 'jev' },
      { id: 'bob-jev', userId: 'bob', providerType: 'jev' },
    ])
    db.seed('project', [
      { id: 'p-alice', userId: 'alice', jevProviderId: null },
      { id: 'p-bob', userId: 'bob', jevProviderId: null },
      { id: 'p-chosen', userId: 'alice', jevProviderId: 'alice-other' },
      { id: 'p-carol', userId: 'carol', jevProviderId: null },
    ])
    await backfillJevProviderSelection(db)
    expect(selection('p-alice')).toBe('alice-jev')
    expect(selection('p-bob')).toBe('bob-jev')
    expect(selection('p-chosen')).toBe('alice-other')
    expect(selection('p-carol')).toBeNull()
  })

  test('an OpenRouter row is never a legacy row, and an owner with two rows gets no guess', async () => {
    db.seed('userLlmProvider', [
      { id: 'dave-or', userId: 'dave', providerType: 'jev_openrouter' },
      { id: 'erin-1', userId: 'erin', providerType: 'jev' },
      { id: 'erin-2', userId: 'erin', providerType: 'jev' },
    ])
    db.seed('project', [
      { id: 'p-dave', userId: 'dave', jevProviderId: null },
      { id: 'p-erin', userId: 'erin', jevProviderId: null },
    ])
    expect(await backfillJevProviderSelection(db)).toEqual({ done: true, projects: 0, owners: 0, ambiguousOwners: 1 })
    expect(selection('p-dave')).toBeNull()
    expect(selection('p-erin')).toBeNull()
  })

  test('writes with update (so updatedAt moves), never updateMany', async () => {
    db.seed('userLlmProvider', [{ id: 'alice-jev', userId: 'alice', providerType: 'jev' }])
    db.seed('project', [{ id: 'p1', userId: 'alice', jevProviderId: null }])
    const writes = instrument()
    await backfillJevProviderSelection(db)
    expect(writes).toEqual(['update'])
  })

  test('writes the AuditLog marker with its counts, under the advisory lock', async () => {
    db.seed('userLlmProvider', [{ id: 'alice-jev', userId: 'alice', providerType: 'jev' }])
    db.seed('project', [{ id: 'p1', userId: 'alice', jevProviderId: null }])
    await backfillJevProviderSelection(db)
    expect(markers()).toEqual([expect.objectContaining({
      action: MARKER_ACTION, targetType: 'system', source: 'system',
      after: { projects: 1, owners: 1, ambiguousOwners: 0 },
    })])
    expect(db.rawCalls.some((c) => c.sql.includes('pg_advisory_xact_lock') && c.values[0] === MARKER_ACTION)).toBe(true)
  })

  test('a second run is a no-op, so a selection cleared after the upgrade stays cleared', async () => {
    db.seed('userLlmProvider', [{ id: 'alice-jev', userId: 'alice', providerType: 'jev' }])
    db.seed('project', [{ id: 'p1', userId: 'alice', jevProviderId: null }])
    await backfillJevProviderSelection(db)
    await db.project.update({ where: { id: 'p1' }, data: { jevProviderId: null } })
    expect(await backfillJevProviderSelection(db)).toEqual({ done: false })
    expect(selection('p1')).toBeNull()
    expect(markers()).toHaveLength(1)
    expect(cutoffs()).toHaveLength(1)
  })

  test('two copies booting together: one does the work, the other finds the marker', async () => {
    db.seed('userLlmProvider', [{ id: 'alice-jev', userId: 'alice', providerType: 'jev' }])
    db.seed('project', [{ id: 'p1', userId: 'alice', jevProviderId: null }])
    const results = await Promise.all([backfillJevProviderSelection(db), backfillJevProviderSelection(db)])
    expect(results.filter((r) => r.done)).toHaveLength(1)
    expect(results.filter((r) => !r.done)).toEqual([{ done: false }])
    expect(markers()).toHaveLength(1)
    expect(selection('p1')).toBe('alice-jev')
  })

  test('a failure rolls back every selection and writes no marker, so the next boot retries', async () => {
    db.seed('userLlmProvider', [{ id: 'alice-jev', userId: 'alice', providerType: 'jev' }])
    db.seed('project', [{ id: 'p1', userId: 'alice', jevProviderId: null }])
    instrument(true)
    await expect(backfillJevProviderSelection(db)).rejects.toThrow('connection reset')
    expect(selection('p1')).toBeNull()
    expect(markers()).toHaveLength(0)
    expect(cutoffs()).toHaveLength(1)
  })
})

describe('the cutoff: only what existed when the new code first started', () => {
  const T0 = Date.parse('2026-11-05T08:00:00.000Z')
  let t = T0
  beforeEach(() => {
    t = T0
    setNowForTests(() => new Date(t))
  })
  afterEach(() => setNowForTests(null))

  test('a retry after a failed first run leaves alone the projects and rows created after it', async () => {
    db.seed('userLlmProvider', [{ id: 'alice-jev', userId: 'alice', providerType: 'jev' }])
    db.seed('project', [{ id: 'p-old', userId: 'alice', jevProviderId: null, createdAt: new Date(t) }])
    t += 60_000
    const original = db.$transaction
    instrument(true)
    await expect(backfillJevProviderSelection(db)).rejects.toThrow('connection reset')
    ;(db as unknown as Record<string, unknown>).$transaction = original

    // Served for a while without the backfill: a project created with no selection,
    // and a second TypeSafe row added under the new many-rows rule.
    t += 60_000
    db.seed('project', [{ id: 'p-new', userId: 'alice', jevProviderId: null, createdAt: new Date(t) }])
    db.seed('userLlmProvider', [{ id: 'alice-jev-2', userId: 'alice', providerType: 'jev' }])

    t += 60_000
    expect(await backfillJevProviderSelection(db)).toEqual({ done: true, projects: 1, owners: 1, ambiguousOwners: 0 })
    expect(selection('p-old')).toBe('alice-jev')
    expect(selection('p-new')).toBeNull()
  })
})

describe('the webapp entrypoint', () => {
  const dockerfile = readFileSync(path.resolve(__dirname, '../../Dockerfile'), 'utf8')
  const entry = dockerfile.split('\n').find((l) => l.startsWith('RUN printf') && l.includes('entrypoint'))!

  test('runs the backfill after db push and before the server, never fatally', () => {
    const push = entry.indexOf('db push')
    const backfill = entry.indexOf('backfill-jev-provider-selection.mjs')
    const server = entry.indexOf('exec node server.js')
    expect(backfill).toBeGreaterThan(push)
    expect(server).toBeGreaterThan(backfill)
    // No `|| exit`: the script logs a failure and the next boot retries it.
    expect(entry).toMatch(/node scripts\/backfill-jev-provider-selection\.mjs 2>&1\\n/)
  })
})
