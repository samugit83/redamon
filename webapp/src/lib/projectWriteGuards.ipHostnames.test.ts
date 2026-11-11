/**
 * guardProjectWrite judges the EFFECTIVE row (the stored row with the change
 * applied) and copies back what the rules normalized, including a policy field the
 * change did not carry: the scan_all confirmation a mode change resets (design §9).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: { userSettings: { findUnique: async () => null } } }))
vi.mock('@/lib/reconSettings/jevEngine', async orig => ({
  ...(await orig<typeof import('@/lib/reconSettings/jevEngine')>()),
  validateJevEngineChange: async () => null,
}))
vi.mock('@/lib/userSkills', async orig => ({
  ...(await orig<typeof import('@/lib/userSkills')>()),
  normalizeUserSkillToggles: async (_db: unknown, _owner: unknown, value: unknown) => ({ ...(value as object), normalized: true }),
}))

import { guardProjectWrite } from './projectWriteGuards'

const STORED = {
  userId: 'owner', ipMode: true, engagementKind: 'internal',
  ipHostnameMode: 'scan_all', ipHostnameInclude: [] as string[], ipHostnameExclude: [] as string[],
  ipHostnamePassiveExpand: true, ipHostnameScanAllConfirmed: true, ipHostnameMaxScanned: 100, ipHostnamePassiveMaxNames: 500,
}

describe('guardProjectWrite and the hostname policy', () => {
  test('a partial change is judged on the stored row', async () => {
    const updateData: Record<string, unknown> = { ipHostnameMode: 'record_filter' }
    expect(await guardProjectWrite({ existing: STORED, updateData, actorUserId: 'owner' }))
      .toContain('ipHostnameInclude')
  })

  test('the normalized fields come back into the write, the untouched ones stay out', async () => {
    const updateData: Record<string, unknown> = { ipHostnameMode: 'record_filter', ipHostnameInclude: ['*Example.com'] }
    expect(await guardProjectWrite({ existing: STORED, updateData, actorUserId: 'owner' })).toBeNull()
    expect(updateData).toEqual({
      ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'], ipHostnameScanAllConfirmed: false,
    })
  })

  test('a stored row without the policy columns adds none to the write', async () => {
    const updateData: Record<string, unknown> = { katanaDepth: 3 }
    expect(await guardProjectWrite({ existing: { userId: 'owner' }, updateData, actorUserId: 'owner' })).toBeNull()
    expect(updateData).toEqual({ katanaDepth: 3 })
  })

  test('the skill toggles normalized on the effective row reach the write', async () => {
    const updateData: Record<string, unknown> = { attackSkillConfig: { builtIn: {} } }
    expect(await guardProjectWrite({ existing: { userId: 'owner' }, updateData, actorUserId: 'owner' })).toBeNull()
    expect(updateData.attackSkillConfig).toEqual({ builtIn: {}, normalized: true })
  })

  test('without a stored row the change is judged alone, and normalized in place', async () => {
    const refused: Record<string, unknown> = { ipMode: true, ipHostnameMode: 'scan_all' }
    expect(await guardProjectWrite({ existing: null, updateData: refused, actorUserId: 'owner' }))
      .toContain('ipHostnameScanAllConfirmed')
    const accepted: Record<string, unknown> = { ipMode: true, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*Example.com'] }
    expect(await guardProjectWrite({ existing: null, updateData: accepted, actorUserId: 'owner' })).toBeNull()
    expect(accepted.ipHostnameInclude).toEqual(['*.example.com'])
  })
})
