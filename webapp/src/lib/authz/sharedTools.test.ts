/**
 * sharedToolAccess with the escape hatch off (HD-28): admins by their database role,
 * members only through a legacy grant they kept at the upgrade, everyone else nothing.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const findFirst = vi.fn()
const create = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { auditLog: { findFirst: (...a: unknown[]) => findFirst(...a), create: (...a: unknown[]) => create(...a) } },
}))

import { SHARED_TOOLS, sharedToolAccess, resetSharedToolsForTests, type SharedTool } from './sharedTools'
import { setFlagsForTests } from './flags'

const CREATED = new Date('2026-01-02T03:04:05Z')
const principal = (role: string, legacyGrants: string[] = []) => ({ id: `u-${role}`, role, legacyGrants, createdAt: CREATED })

beforeEach(() => {
  findFirst.mockReset()
  create.mockReset()
  resetSharedToolsForTests()
  setFlagsForTests({})
})
afterEach(() => setFlagsForTests(null))

describe('sharedToolAccess (escape hatch off)', () => {
  test('the five shared tools', () => {
    expect([...SHARED_TOOLS]).toEqual(['kali_terminal', 'shell_sessions_all', 'tunnels', 'emergency_stop_all', 'nuclei_templates_all'])
  })

  test('admin: every shared tool, through the database role, with no read', async () => {
    for (const tool of SHARED_TOOLS) {
      expect(await sharedToolAccess(principal('admin'), tool)).toEqual({ allowed: true, via: 'admin' })
    }
    expect(findFirst).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
  })

  test('legacy: each grant opens its own tool and no other', async () => {
    const opens: Record<string, SharedTool> = { kali_terminal: 'kali_terminal', shell_sessions: 'shell_sessions_all', tunnels: 'tunnels' }
    for (const [grant, tool] of Object.entries(opens)) {
      for (const t of SHARED_TOOLS) {
        expect(await sharedToolAccess(principal('standard', [grant]), t), `${grant} -> ${t}`)
          .toEqual(t === tool ? { allowed: true, via: 'legacy' } : { allowed: false, via: null })
      }
    }
    expect(create).not.toHaveBeenCalled()
  })

  test('legacy: no grant opens the global emergency stop or every Nuclei template', async () => {
    const all = principal('standard', ['kali_terminal', 'shell_sessions', 'tunnels'])
    expect(await sharedToolAccess(all, 'emergency_stop_all')).toEqual({ allowed: false, via: null })
    expect(await sharedToolAccess(all, 'nuclei_templates_all')).toEqual({ allowed: false, via: null })
  })

  test('none: a member without grants gets no shared tool, and nothing is read', async () => {
    for (const tool of SHARED_TOOLS) {
      expect(await sharedToolAccess(principal('standard'), tool)).toEqual({ allowed: false, via: null })
    }
    expect(findFirst).not.toHaveBeenCalled()
  })

  test('an unknown grant value or role opens nothing', async () => {
    expect(await sharedToolAccess(principal('standard', ['admin', 'shell_sessions_all']), 'shell_sessions_all'))
      .toEqual({ allowed: false, via: null })
    expect(await sharedToolAccess(principal('Admin'), 'kali_terminal')).toEqual({ allowed: false, via: null })
  })
})
