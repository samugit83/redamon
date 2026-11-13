/**
 * The projects page's reading of a list row's own access (step 4.5, UI-06): which rows are shared
 * with the person, the level badge, and who shared it.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/sharedProjects.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { accessBadge, isSharedWithMe, sharedByLabel, splitProjectList } from './sharedProjects'
import type { MyAccess } from './authz/projectAccess'

const owner = { name: 'Alice', email: 'alice@example.test' }
const OWNED: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner }
const READ: MyAccess = { level: 'read', toggles: { rawData: false }, via: 'share', owner }
const RAW: MyAccess = { level: 'read', toggles: { rawData: true }, via: 'share', owner }

describe('isSharedWithMe / splitProjectList', () => {
  test('a row without myAccess (sharing off) or at the owner level is the person\'s own', () => {
    expect(isSharedWithMe({})).toBe(false)
    expect(isSharedWithMe({ myAccess: null })).toBe(false)
    expect(isSharedWithMe({ myAccess: OWNED })).toBe(false)
    expect(isSharedWithMe({ myAccess: READ })).toBe(true)
  })

  test('keeps the list order inside each part', () => {
    const rows = [{ id: 'a', myAccess: READ }, { id: 'b' }, { id: 'c', myAccess: OWNED }, { id: 'd', myAccess: RAW }]
    const { owned, shared } = splitProjectList(rows)
    expect(owned.map((r) => r.id)).toEqual(['b', 'c'])
    expect(shared.map((r) => r.id)).toEqual(['a', 'd'])
  })
})

describe('accessBadge', () => {
  test('Read, and Raw data & files when the share gives it', () => {
    expect(accessBadge(READ)).toBe('Read')
    expect(accessBadge(RAW)).toBe('Read + Raw data')
    expect(accessBadge(OWNED)).toBe('Owner')
  })
})

describe('sharedByLabel', () => {
  test('the owner myAccess names, else the row\'s owner, name and email when both are known', () => {
    expect(sharedByLabel({ myAccess: READ })).toBe('Alice (alice@example.test)')
    expect(sharedByLabel({ myAccess: { ...READ, owner: { name: null, email: 'a@example.test' } } })).toBe('a@example.test')
    expect(sharedByLabel({ myAccess: { ...READ, owner: { name: 'Al', email: null } } })).toBe('Al')
    expect(sharedByLabel({ myAccess: { ...READ, owner: { name: null, email: null } }, user: { name: 'Row owner', email: 'r@example.test' } }))
      .toBe('Row owner (r@example.test)')
    expect(sharedByLabel({ myAccess: { ...READ, owner: { name: null, email: null } } })).toBe('another account')
  })
})
