/**
 * The quota editor's logic (step 6.8): the browser copy of the fields and bounds matches the server's,
 * the three states of an entry field survive a round trip, typed limits are checked, and the Save sends
 * only what changed.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/instance/quotaModel.test.ts
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { QUOTA_BOUNDS, QUOTA_FIELDS as SERVER_FIELDS } from '@/lib/authz/quotas'
import {
  QUOTA_FIELDS, QUOTA_FIELD_SPECS, draftErrors, draftOf, emptyEntryCells, entryOf, entrySummary, quotaPatch,
} from './quotaModel'

describe('the browser copy', () => {
  test('fields and bounds are the server\'s (lib/authz/quotas.ts)', () => {
    expect([...QUOTA_FIELDS]).toEqual([...SERVER_FIELDS])
    expect(QUOTA_FIELD_SPECS.map((s) => s.field)).toEqual([...SERVER_FIELDS])
    for (const s of QUOTA_FIELD_SPECS) expect({ min: s.min, max: s.max }).toEqual(QUOTA_BOUNDS[s.field])
  })
})

describe('the draft', () => {
  const store = {
    defaults: { maxProjects: 3, llmDailyCalls: null },
    perSet: { s1: { maxProjects: null, maxMcpTokens: 2 } },
    perUser: { u1: { maxConcurrentScans: 0 } },
  }

  test('defaults: a value left out or null is unlimited; entries keep "not set", null and a number apart', () => {
    const d = draftOf(store)
    expect(d.defaults.maxProjects).toEqual({ mode: 'limit', value: '3' })
    expect(d.defaults.maxConcurrentScans).toEqual({ mode: 'unlimited', value: '' })
    expect(d.defaults.llmDailyCalls).toEqual({ mode: 'unlimited', value: '' })
    expect(d.perSet.s1.maxProjects).toEqual({ mode: 'unlimited', value: '' })
    expect(d.perSet.s1.maxConcurrentScans).toEqual({ mode: 'inherit', value: '' })
    expect(entryOf(d.perSet.s1)).toEqual({ maxProjects: null, maxMcpTokens: 2 })
    expect(entryOf(d.perUser.u1)).toEqual({ maxConcurrentScans: 0 })
    expect(draftOf(undefined).perSet).toEqual({})
  })

  test('nothing changed: no patch', () => {
    expect(quotaPatch(draftOf(store), draftOf(store))).toBeNull()
  })

  test('the patch names only what changed: the defaults, a changed entry, a removed one (null), a new one', () => {
    const saved = draftOf(store)
    const draft = draftOf(store)
    draft.defaults = { ...draft.defaults, maxProjects: { mode: 'unlimited', value: '' }, maxMcpTokenExpiryDays: { mode: 'limit', value: '90' } }
    delete draft.perUser.u1
    draft.perSet.s2 = { ...emptyEntryCells(), maxConcurrentScans: { mode: 'limit', value: '1' } }
    expect(quotaPatch(saved, draft)).toEqual({
      defaults: { maxMcpTokenExpiryDays: 90 },
      perSet: { s2: { maxConcurrentScans: 1 } },
      perUser: { u1: null },
    })
  })

  test('a new entry left entirely "not set" sends nothing; an entry emptied is removed', () => {
    const saved = draftOf(store)
    const draft = draftOf(store)
    draft.perSet.s3 = emptyEntryCells()
    expect(quotaPatch(saved, draft)).toBeNull()
    draft.perUser.u1 = emptyEntryCells()
    expect(quotaPatch(saved, draft)).toEqual({ perUser: { u1: null } })
  })

  test('typed limits are checked against the bounds', () => {
    const d = draftOf(store)
    d.defaults.maxProjects = { mode: 'limit', value: '-1' }
    d.defaults.maxMcpTokenExpiryDays = { mode: 'limit', value: '0' }
    d.perSet.s1.maxMcpTokens = { mode: 'limit', value: '2.5' }
    d.perUser.u1.maxConcurrentScans = { mode: 'limit', value: '' }
    expect(Object.keys(draftErrors(d)).sort()).toEqual([
      'defaults.maxMcpTokenExpiryDays', 'defaults.maxProjects', 'perSet.s1.maxMcpTokens', 'perUser.u1.maxConcurrentScans',
    ])
    expect(draftErrors(draftOf(store))).toEqual({})
  })

  test('summary in words', () => {
    expect(entrySummary({ maxProjects: 2, maxConcurrentScans: null })).toBe('Projects owned 2, Scans at once unlimited')
    expect(entrySummary({})).toBe('nothing set')
  })
})
