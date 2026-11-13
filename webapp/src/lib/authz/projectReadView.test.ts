/**
 * HD-27: the owner's secrets never reach a non-owner's project read.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { fieldsWhere, fieldKeys } from '@/lib/reconSettings/registry'
import { SHARE_SECRET_FIELDS, ownerOnlyRefusal, projectReadView } from './projectReadView'

const FAKE = 'rbac-fake-share-secret-0001'

/** A row holding every registry column, each secret one carrying the fake token. */
function fullRow(): Record<string, unknown> {
  const row: Record<string, unknown> = {}
  for (const key of fieldKeys()) row[key] = SHARE_SECRET_FIELDS.includes(key) ? FAKE : `value-of-${key}`
  row.id = 'proj-1'
  row.userId = 'owner-1'
  row.user = { id: 'owner-1', name: 'Owner', email: 'owner@e2e.local' }
  row.scopeGroups = []
  return row
}

const OWNER = { level: 'owner' }
const READ = { level: 'read' }

describe('projectReadView', () => {
  test('owner sees everything', () => {
    const row = fullRow()
    const view = projectReadView(row, OWNER)
    expect(view).toEqual(row)
    expect(JSON.stringify(view)).toContain(FAKE)
  })

  test('read collaborator sees no secret field', () => {
    const view = projectReadView(fullRow(), READ)
    for (const key of SHARE_SECRET_FIELDS) expect(view, key).not.toHaveProperty(key)
    expect(JSON.stringify(view)).not.toContain(FAKE)
    // Everything else is the owner's row, unchanged.
    expect(Object.keys(view).length).toBe(Object.keys(fullRow()).length - SHARE_SECRET_FIELDS.length)
    expect(view.targetDomain).toBe('value-of-targetDomain')
  })

  test('no decided access reads as a non-owner', () => {
    expect(JSON.stringify(projectReadView(fullRow(), null))).not.toContain(FAKE)
    expect(JSON.stringify(projectReadView(fullRow(), undefined))).not.toContain(FAKE)
  })

  test('the row passed in is left whole', () => {
    const row = fullRow()
    projectReadView(row, READ)
    expect(row.cypherfixGithubToken).toBe(FAKE)
  })

  test('every readable:false field except userId is share:secret', () => {
    const withheld = fieldsWhere(f => f.readable === false).map(f => f.key)
    expect(withheld).toContain('userId')
    for (const key of withheld.filter(k => k !== 'userId')) expect(SHARE_SECRET_FIELDS, key).toContain(key)
  })

  test('custom headers are secret', () => {
    for (const key of [
      'httpxCustomHeaders', 'katanaCustomHeaders', 'zapAjaxSpiderCustomHeaders', 'hakrawlerCustomHeaders',
      'jsReconEndpointCustomHeaders', 'ffufCustomHeaders', 'arjunCustomHeaders', 'kiterunnerHeaders',
    ]) {
      expect(SHARE_SECRET_FIELDS, key).toContain(key)
    }
    const view = projectReadView({ httpxCustomHeaders: [`X-Api-Key: ${FAKE}`], kiterunnerHeaders: [FAKE] }, READ)
    expect(view).toEqual({})
  })

  test("the owner's id stays readable", () => {
    expect(SHARE_SECRET_FIELDS).not.toContain('userId')
    const view = projectReadView(fullRow(), READ)
    expect(view.userId).toBe('owner-1')
    expect(view.user).toEqual({ id: 'owner-1', name: 'Owner', email: 'owner@e2e.local' })
  })
})

describe('ownerOnlyRefusal', () => {
  test('the owner passes', () => {
    expect(ownerOnlyRefusal(OWNER, 'roe:read', 'x')).toBeNull()
  })

  test('anyone else gets 403 owner_only naming the permission', async () => {
    for (const access of [READ, null, undefined]) {
      const res = ownerOnlyRefusal(access, 'roe:read', 'Only the owner may download it.')
      expect(res?.status).toBe(403)
      expect(await res?.json()).toEqual({ error: 'Only the owner may download it.', code: 'owner_only', permission: 'roe:read' })
    }
  })
})
