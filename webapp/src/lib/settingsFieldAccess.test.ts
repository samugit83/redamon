/**
 * A collaborator's project form judges each change with the server's settings classes (step 5.7,
 * SH-26, SH-08): a Read + Write share changes ordinary settings and tightens gates; loosening a gate
 * needs Manage (and Exploitation & shells for the exploit gates); the scope needs Manage to narrow and
 * the owner to widen; secrets are the owner's. The owner, and the form without `myAccess` (sharing
 * off), are never refused (DV-30). The judgment runs in the browser, so it must reach no module that
 * reads the database.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/settingsFieldAccess.test.ts
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { catalogPickRefusal, fieldChangeRefusal, writeAccessSummary } from './settingsFieldAccess'

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const SHARED_BY = 'Alice (alice@e2e.local)'
const write = (t: Partial<Record<'runScans' | 'useAgent' | 'exploit' | 'manage', boolean>> = {}): MyAccess => ({
  level: 'write', via: 'share', owner: OWNER,
  toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: false, ...t },
})
const EDITOR = write()
const CO_OWNER = write({ manage: true })
const RED_TEAM_CO_OWNER = write({ manage: true, exploit: true })
const READ: MyAccess = { level: 'read', via: 'share', owner: OWNER, toggles: { rawData: false } }
const OWNS: MyAccess = { level: 'owner', via: 'owner', owner: OWNER, toggles: { rawData: true } }

const STORED = {
  naabuRateLimit: 100,
  agentRequireToolConfirmation: true,
  agentGuardrailEnabled: true,
  targetIps: ['10.0.0.1', '10.0.0.2'],
  roeTimeWindowEnabled: false,
  roeTimeWindowDays: ['mon'],
}

const judge = (changes: Record<string, unknown>, access: MyAccess | null | undefined, current: Record<string, unknown> = STORED) =>
  fieldChangeRefusal(STORED, current, changes, access)

afterEach(() => {
  vi.doUnmock('@/lib/prisma')
  vi.resetModules()
})

describe('fieldChangeRefusal', () => {
  test('owner unchanged, and no myAccess (sharing off) unchanged: nothing is refused', () => {
    for (const access of [OWNS, null, undefined]) {
      expect(judge({ agentRequireToolConfirmation: false, targetIps: ['8.8.8.8'], httpxCustomHeaders: ['X: y'] }, access)).toBeNull()
    }
  })

  test('an editor changes an ordinary setting and tightens a gate', () => {
    expect(judge({ naabuRateLimit: 50 }, EDITOR)).toBeNull()
    expect(fieldChangeRefusal({ ...STORED, agentRequireToolConfirmation: false }, STORED, { agentRequireToolConfirmation: true }, EDITOR)).toBeNull()
  })

  test('an editor cannot loosen the dangerous-tool confirmation: the key, the need, the reason and the access are named', () => {
    const refusal = judge({ agentRequireToolConfirmation: false }, EDITOR)
    expect(refusal).toMatchObject({ key: 'agentRequireToolConfirmation', needs: 'manage+exploit' })
    expect(refusal!.text).toMatch(/^agentRequireToolConfirmation needs Manage and Exploitation & shells \(loosens a safety gate: .+\)\. /)
    expect(refusal!.text).toContain(`Read + Write access without Manage, shared by ${SHARED_BY}.`)
  })

  test('the scope: an editor cannot even narrow it; a co-owner narrows, widening needs the owner', () => {
    expect(judge({ targetIps: ['10.0.0.1'] }, EDITOR)).toMatchObject({ key: 'targetIps', needs: 'manage' })
    expect(judge({ targetIps: ['10.0.0.1'] }, CO_OWNER)).toBeNull()
    const widen = judge({ targetIps: ['10.0.0.1', '10.0.0.2', '10.0.0.3'] }, CO_OWNER)
    expect(widen).toMatchObject({ key: 'targetIps', needs: 'owner' })
    expect(widen!.text).toContain("targetIps needs the project's owner (widens the scope: adds 10.0.0.3)")
    expect(widen!.text).toContain(`Read + Write access, shared by ${SHARED_BY}; only the owner can do this.`)
  })

  test("the owner's secrets are the owner's alone, at any write level", () => {
    for (const access of [EDITOR, CO_OWNER, RED_TEAM_CO_OWNER]) {
      expect(judge({ httpxCustomHeaders: ['X-Test: 1'] }, access)).toMatchObject({ key: 'httpxCustomHeaders', needs: 'owner' })
    }
  })

  test('a co-owner loosens a plain gate; an exploit gate also needs Exploitation & shells', () => {
    expect(judge({ agentGuardrailEnabled: false }, CO_OWNER)).toBeNull()
    expect(judge({ agentRequireToolConfirmation: false }, CO_OWNER)).toMatchObject({ needs: 'manage+exploit' })
    expect(judge({ agentRequireToolConfirmation: false }, CO_OWNER)!.text).toContain('Read + Write access without Exploitation & shells')
    expect(judge({ agentRequireToolConfirmation: false }, RED_TEAM_CO_OWNER)).toBeNull()
  })

  test('a value equal to the stored one is no change, and the first refused change is the one named', () => {
    expect(judge({ agentRequireToolConfirmation: true, targetIps: ['10.0.0.1', '10.0.0.2'] }, EDITOR)).toBeNull()
    expect(judge({ naabuRateLimit: 10, targetIps: ['10.0.0.1'], agentRequireToolConfirmation: false }, EDITOR)?.key).toBe('targetIps')
  })

  test('the rules read the stored row as the PUT does: a day added while the window is on is the owner\'s', () => {
    expect(judge({ roeTimeWindowDays: ['mon', 'sun'] }, CO_OWNER)).toBeNull()
    const on = { ...STORED, roeTimeWindowEnabled: true }
    expect(fieldChangeRefusal(on, on, { roeTimeWindowDays: ['mon', 'sun'] }, CO_OWNER))
      .toMatchObject({ key: 'roeTimeWindowDays', needs: 'owner' })
  })

  test('a read share changes nothing', () => {
    expect(judge({ naabuRateLimit: 50 }, READ)).toMatchObject({ needs: 'write' })
  })

  test('the judgment reaches no module that reads the database (the form runs it in the browser)', async () => {
    vi.resetModules()
    const databaseLoaded = vi.fn()
    vi.doMock('@/lib/prisma', () => { databaseLoaded(); return { default: {}, prisma: {} } })
    const fresh = await import('./settingsFieldAccess')
    expect(fresh.fieldChangeRefusal(STORED, STORED, { agentRequireToolConfirmation: false }, EDITOR)?.key).toBe('agentRequireToolConfirmation')
    expect(databaseLoaded).not.toHaveBeenCalled()
    // The double does bite: the server module that reads the database loads it.
    await import('@/lib/authz/projectAccess')
    expect(databaseLoaded).toHaveBeenCalled()
  })

  test('projectAccess re-exports the one level table', async () => {
    const [projectAccess, levelTable] = await Promise.all([import('@/lib/authz/projectAccess'), import('@/lib/authz/levelTable')])
    expect(projectAccess.meetsLevel).toBe(levelTable.meetsLevel)
  })
})

describe('catalogPickRefusal', () => {
  test('the owner, no myAccess and Manage pick from the catalog', () => {
    for (const access of [OWNS, null, undefined, CO_OWNER, RED_TEAM_CO_OWNER]) expect(catalogPickRefusal(access)).toBeNull()
  })
  test('below Manage the reason names the access and Manage', () => {
    expect(catalogPickRefusal(EDITOR)).toBe(
      `Read + Write access without Manage, shared by ${SHARED_BY}: picking from the owner's models, Jev configurations, skills and MCP tools needs Manage`)
    expect(catalogPickRefusal(READ)).toMatch(/^Read access, shared by Alice .+needs Manage$/)
  })
})

describe('writeAccessSummary', () => {
  test('only a Read + Write share gets one', () => {
    for (const access of [OWNS, READ, null, undefined]) expect(writeAccessSummary(access)).toBeNull()
  })
  test('an editor is told what Write, Manage and the owner each change', () => {
    const text = writeAccessSummary(EDITOR)!
    expect(text).toMatch(/^Read \+ Write access, shared by Alice \(alice@e2e\.local\)\. You can change ordinary settings and tighten safety gates\./)
    expect(text).toContain('Loosening a safety gate needs Manage (the approval, tunnel and Kali gates also need Exploitation & shells)')
    expect(text).toContain("The owner's credentials, custom headers and RoE record are the owner's alone.")
  })
  test('a co-owner is told the exploit gates need Exploitation & shells only while the toggle is off', () => {
    expect(writeAccessSummary(CO_OWNER)).toMatch(/^Read \+ Write access with Manage, .+loosen safety gates \(the approval, tunnel and Kali gates also need Exploitation & shells\), narrow/)
    expect(writeAccessSummary(RED_TEAM_CO_OWNER)).toContain('loosen safety gates, narrow')
  })
})
