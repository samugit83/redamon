/**
 * SH-08, SH-28, OQ-23: project settings classed by risk. An editor (Write) may change ordinary
 * settings and tighten a safety gate; loosening a gate needs Manage, and Exploitation & shells
 * for the agent's approval, tunnel and Kali switches; narrowing scope needs Manage, widening it
 * the owner; the owner's secrets are the owner's. The owner passes every change.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { fieldKeys, fieldsWhere, loadRegistry } from '@/lib/reconSettings/registry'
import { directionOf } from '@/lib/roe/roeWidening'
import { RECON_PRESETS } from '@/lib/recon-presets'
import { effectiveToggles, type ProjectAccess } from './projectAccess'
import { EXPLOIT_GATES, OWN_DIRECTIONS, classifyChange, classifyField } from './settingsRisk'

// The level decision is the real meetsLevel table (write rows from step 5.2a): write reaches R, R*
// and W; W+S, W+A and W+X also need their toggle; M needs manage; O stays the owner's. These
// accesses carry the toggles a write share could hold once step 5.6 turns the run toggles on.

type Toggles = Partial<Record<'rawData' | 'runScans' | 'useAgent' | 'exploit' | 'manage', boolean>>

function access(level: string, toggles: Toggles = {}, via = 'share'): ProjectAccess {
  return { project: { id: 'P', userId: 'owner-1' }, level, toggles: { rawData: level !== 'read', ...toggles }, via } as unknown as ProjectAccess
}

const OWNER = access('owner', {}, 'owner')
const READ = access('read')
const EDITOR = access('write')
const CO_OWNER = access('write', { manage: true })
const RED_TEAM_CO_OWNER = access('write', { manage: true, exploit: true })
const RED_TEAMER = access('write', { exploit: true, runScans: true, useAgent: true })

/** A fresh project: every column at its registry default. */
function defaultsRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const row: Record<string, unknown> = {}
  for (const [key, f] of Object.entries(loadRegistry().fields)) row[key] = f.default ?? null
  return { ...row, ...overrides }
}

function verdictOf(before: Record<string, unknown>, after: Record<string, unknown>, who: ProjectAccess | null) {
  return classifyChange(defaultsRow(before), after, who)
}

describe('classifyChange: one case per class and direction', () => {
  test('ordinary: Write', () => {
    const change = { naabuRateLimit: 50 }
    expect(verdictOf({ naabuRateLimit: 100 }, change, EDITOR).ok).toBe(true)
    const refused = verdictOf({ naabuRateLimit: 100 }, change, READ)
    expect(refused.ok).toBe(false)
    expect(refused.refused).toEqual([expect.objectContaining({ key: 'naabuRateLimit', share: 'ordinary', needs: 'write' })])
  })

  test('a gate tightened: Write', () => {
    const v = verdictOf({ agentRequireToolConfirmation: false }, { agentRequireToolConfirmation: true }, EDITOR)
    expect(v.ok).toBe(true)
    expect(v.changes).toEqual([expect.objectContaining({ key: 'agentRequireToolConfirmation', share: 'gate', needs: 'write', reason: null })])
  })

  test('a gate loosened: Manage', () => {
    const before = { jsReconValidateKeys: false }
    const after = { jsReconValidateKeys: true }
    expect(verdictOf(before, after, EDITOR).refused).toEqual([
      expect.objectContaining({ key: 'jsReconValidateKeys', share: 'gate', needs: 'manage', reason: expect.stringMatching(/safety/) }),
    ])
    expect(verdictOf(before, after, CO_OWNER).ok).toBe(true)
  })

  test('scope narrowed: Manage', () => {
    const before = { subdomainList: ['a.example.test', 'b.example.test'] }
    const after = { subdomainList: ['a.example.test'] }
    expect(verdictOf(before, after, EDITOR).refused).toEqual([
      expect.objectContaining({ key: 'subdomainList', share: 'scope', needs: 'manage', reason: null }),
    ])
    expect(verdictOf(before, after, CO_OWNER).ok).toBe(true)
  })

  test('scope widened: the owner', () => {
    const before = { subdomainList: ['a.example.test'] }
    const after = { subdomainList: ['a.example.test', 'c.example.test'] }
    const v = verdictOf(before, after, RED_TEAM_CO_OWNER)
    expect(v.refused).toEqual([
      expect.objectContaining({ key: 'subdomainList', share: 'scope', needs: 'owner', reason: expect.stringContaining('c.example.test') }),
    ])
    expect(verdictOf(before, after, OWNER).ok).toBe(true)
  })

  test("the owner's secret: the owner", () => {
    const after = { cypherfixGithubToken: 'rbac-fake-share-secret-0001' }
    expect(verdictOf({}, after, RED_TEAM_CO_OWNER).refused).toEqual([
      expect.objectContaining({ key: 'cypherfixGithubToken', share: 'secret', needs: 'owner' }),
    ])
    expect(verdictOf({}, after, OWNER).ok).toBe(true)
  })

  test('a key the registry does not know needs the owner', () => {
    const v = verdictOf({}, { notAColumn: 1 }, RED_TEAM_CO_OWNER)
    expect(v.refused).toEqual([expect.objectContaining({ key: 'notAColumn', share: 'unknown', needs: 'owner' })])
  })
})

describe('the spec cases', () => {
  test('owner unchanged: every column changed at once passes', () => {
    const before = defaultsRow()
    const after = Object.fromEntries(fieldKeys().map(k => [k, `changed-${k}`]))
    const v = classifyChange(before, after, OWNER)
    expect(v.ok).toBe(true)
    expect(v.refused).toEqual([])
    expect(v.changes.map(c => c.key)).toEqual(fieldKeys())
  })

  test('an editor cannot loosen the dangerous-tool confirmation', () => {
    const v = verdictOf({ agentRequireToolConfirmation: true }, { agentRequireToolConfirmation: false }, EDITOR)
    expect(v.ok).toBe(false)
    expect(v.refused).toEqual([expect.objectContaining({ key: 'agentRequireToolConfirmation', needs: 'manage+exploit' })])
    // Exploitation & shells alone is not enough either: loosening a gate is a co-owner's call.
    expect(verdictOf({ agentRequireToolConfirmation: true }, { agentRequireToolConfirmation: false }, RED_TEAMER).ok).toBe(false)
  })

  test('a co-owner loosening an approval gate needs Exploitation', () => {
    for (const key of ['agentRequireApprovalForExploitation', 'agentRequireApprovalForPostExploitation', 'agentRequireToolConfirmation']) {
      const before = { [key]: true }
      const after = { [key]: false }
      expect(verdictOf(before, after, CO_OWNER).refused, key).toEqual([expect.objectContaining({ key, needs: 'manage+exploit' })])
      expect(verdictOf(before, after, RED_TEAM_CO_OWNER).ok, key).toBe(true)
    }
    // Opening the post-exploitation phase is the same call.
    expect(verdictOf({ agentActivatePostExplPhase: false }, { agentActivatePostExplPhase: true }, CO_OWNER).ok).toBe(false)
    expect(verdictOf({ agentActivatePostExplPhase: false }, { agentActivatePostExplPhase: true }, RED_TEAM_CO_OWNER).ok).toBe(true)
  })

  test('a co-owner as projectAccess answers today (Exploitation reads off until step 5.6) cannot loosen an approval gate', () => {
    const today = access('write', effectiveToggles({ manage: true, exploit: true, runScans: true, useAgent: true }))
    expect(verdictOf({ agentRequireToolConfirmation: true }, { agentRequireToolConfirmation: false }, today).refused)
      .toEqual([expect.objectContaining({ key: 'agentRequireToolConfirmation', needs: 'manage+exploit' })])
    expect(verdictOf({ agentGuardrailEnabled: true }, { agentGuardrailEnabled: false }, today).ok).toBe(true)
  })

  test('widening scope needs the owner', () => {
    const cases: Array<[string, unknown, unknown]> = [
      ['targetDomain', 'example.test', 'other.test'],
      ['targetIps', ['10.0.0.1'], ['10.0.0.1', '10.0.0.2']],
      ['domainBatchHosts', ['a.example.test'], ['*.example.test']],
      ['ipHostnameExclude', ['a.example.test'], []],
      ['ipHostnameMaxScanned', 100, 200],
      ['ipMode', false, true],
      ['githubTargetRepos', 'one', ''],
      ['supplyChainRepoUrl', 'https://git.example.test/a', 'https://git.example.test/b'],
      ['roeExcludedHosts', ['prod.example.test'], []],
      ['roeGlobalMaxRps', 10, 0],
      ['roeAllowDos', false, true],
      ['roeEngagementEndDate', '2026-12-01', '2027-01-01'],
    ]
    for (const [key, before, after] of cases) {
      const v = verdictOf({ [key]: before }, { [key]: after }, RED_TEAM_CO_OWNER)
      expect(v.refused, key).toEqual([expect.objectContaining({ key, share: 'scope', needs: 'owner' })])
      expect(verdictOf({ [key]: before }, { [key]: after }, OWNER).ok, key).toBe(true)
    }
  })

  test('the same fields narrowed are a co-owner call', () => {
    const cases: Array<[string, unknown, unknown]> = [
      ['targetIps', ['10.0.0.1', '10.0.0.2'], ['10.0.0.1']],
      ['ipHostnameExclude', [], ['a.example.test']],
      ['ipHostnameMaxScanned', 200, 100],
      ['githubTargetRepos', '', 'one'],
      ['roeExcludedHosts', [], ['prod.example.test']],
      ['roeGlobalMaxRps', 10, 5],
      ['roeAllowDos', true, false],
      ['roeEngagementEndDate', '2027-01-01', '2026-12-01'],
    ]
    for (const [key, before, after] of cases) {
      expect(verdictOf({ [key]: before }, { [key]: after }, CO_OWNER).ok, key).toBe(true)
      expect(verdictOf({ [key]: before }, { [key]: after }, EDITOR).refused, key).toEqual([
        expect.objectContaining({ key, needs: 'manage' }),
      ])
    }
  })

  test('a preset that loosens a gate is refused at W', () => {
    // Secret Hunter validates the keys it finds against their providers: a gate an owner who
    // turned it off has closed. The rest of the preset is an editor's to apply.
    const preset = RECON_PRESETS.find(p => p.id === 'secret-hunter')!
    expect(preset.parameters.jsReconValidateKeys).toBe(true)
    const v = verdictOf({ jsReconValidateKeys: false }, preset.parameters as Record<string, unknown>, EDITOR)
    expect(v.refused).toEqual([expect.objectContaining({ key: 'jsReconValidateKeys', share: 'gate', needs: 'manage' })])
    expect(verdictOf({ jsReconValidateKeys: false }, preset.parameters as Record<string, unknown>, CO_OWNER).ok).toBe(true)
  })

  test('every shipped preset is ordinary or a gate: no preset reaches scope or a secret', () => {
    for (const preset of RECON_PRESETS) {
      const v = classifyChange(defaultsRow(), preset.parameters as Record<string, unknown>, OWNER)
      const beyond = v.changes.filter(c => c.share !== 'ordinary' && c.share !== 'gate').map(c => c.key)
      expect(beyond, preset.id).toEqual([])
    }
  })
})

describe('the directions the generic rules get wrong or do not cover', () => {
  test('turning the target guardrail or the ownership proof off widens; on narrows', () => {
    for (const key of ['targetGuardrailEnabled', 'verifyDomainOwnership']) {
      expect(classifyField(key, true, false).needs, key).toBe('owner')
      expect(classifyField(key, false, true).needs, key).toBe('manage')
    }
  })

  test('the derived roeEnabled widens when it goes off, not on', () => {
    expect(classifyField('roeEnabled', true, false).needs).toBe('owner')
    expect(classifyField('roeEnabled', false, true).needs).toBe('manage')
  })

  test('the Kali allowlist: a first entry tightens, an added entry or an emptied list loosens', () => {
    expect(classifyField('agentKaliInstallAllowedPackages', '', 'nmap').needs).toBe('write')
    expect(classifyField('agentKaliInstallAllowedPackages', 'nmap, hydra', 'nmap').needs).toBe('write')
    expect(classifyField('agentKaliInstallAllowedPackages', 'nmap', 'nmap,hydra').needs).toBe('manage+exploit')
    expect(classifyField('agentKaliInstallAllowedPackages', 'nmap', '').needs).toBe('manage+exploit')
  })

  test('the Kali denylist: an entry removed loosens, one added tightens', () => {
    expect(classifyField('agentKaliInstallForbiddenPackages', 'hydra', 'hydra,john').needs).toBe('write')
    expect(classifyField('agentKaliInstallForbiddenPackages', 'hydra,john', 'john').needs).toBe('manage+exploit')
  })

  test('MCP Kali exec: on loosens (Manage + Exploitation), off tightens', () => {
    expect(classifyField('mcpKaliExecEnabled', false, true).needs).toBe('manage+exploit')
    expect(classifyField('mcpKaliExecEnabled', true, false).needs).toBe('write')
  })

  test('a window part edited while the window is off widens nothing', () => {
    const row = { roeTimeWindowEnabled: false, roeTimeWindowStartTime: '09:00' }
    expect(classifyField('roeTimeWindowStartTime', '09:00', '01:00', row, { ...row, roeTimeWindowStartTime: '01:00' }).needs).toBe('manage')
    const on = { roeTimeWindowEnabled: true, roeTimeWindowStartTime: '09:00' }
    expect(classifyField('roeTimeWindowStartTime', '09:00', '01:00', on, { ...on, roeTimeWindowStartTime: '01:00' }).needs).toBe('owner')
  })

  test('the derived batch groups never decide on their own', () => {
    expect(classifyField('domainBatchGroups', [], [{ rootDomain: 'x.test', prefixes: ['*'], hosts: [], wildcard: true }]).needs).toBe('manage')
  })

  test('a partial save judges the window against the row as it will be', () => {
    // Auto-save sends one field: the window turned on in the same row decides.
    const before = defaultsRow({ roeTimeWindowEnabled: true, roeTimeWindowStartTime: '09:00' })
    expect(classifyChange(before, { roeTimeWindowStartTime: '01:00' }, CO_OWNER).refused).toEqual([
      expect.objectContaining({ key: 'roeTimeWindowStartTime', needs: 'owner' }),
    ])
  })
})

describe('what is classified', () => {
  test('an unchanged value is not a change: a full-form save at W passes over gates and scope', () => {
    const row = defaultsRow({ targetDomain: 'example.test', agentRequireToolConfirmation: false })
    const v = classifyChange(row, { ...row, naabuRateLimit: 7 }, EDITOR)
    expect(v.ok).toBe(true)
    expect(v.changes.map(c => c.key)).toEqual(['naabuRateLimit'])
  })

  test('no access, or a read access, changes nothing', () => {
    for (const who of [null, undefined, READ]) {
      const v = classifyChange(defaultsRow({ agentRequireToolConfirmation: false }), { naabuRateLimit: 7, agentRequireToolConfirmation: true }, who)
      expect(v.ok).toBe(false)
      expect(v.refused.map(c => c.key)).toEqual(['agentRequireToolConfirmation', 'naabuRateLimit'])
    }
  })

  test('a kind of access meetsLevel has no row for is refused', () => {
    expect(classifyChange(defaultsRow(), { naabuRateLimit: 7 }, access('auditor')).ok).toBe(false)
  })

  test('several changes: every refusal is listed, in key order, beside the allowed ones', () => {
    const v = verdictOf(
      { subdomainList: ['a.example.test'], agentRequireToolConfirmation: true },
      { subdomainList: ['a.example.test', 'b.example.test'], agentRequireToolConfirmation: false, naabuRateLimit: 3 },
      CO_OWNER,
    )
    expect(v.changes.map(c => [c.key, c.ok])).toEqual([
      ['agentRequireToolConfirmation', false], ['naabuRateLimit', true], ['subdomainList', false],
    ])
    expect(v.refused.map(c => c.needs)).toEqual(['manage+exploit', 'owner'])
  })
})

describe('the tables cover the registry', () => {
  test('every gate and scope field has a judgment, so none slips through unjudged', () => {
    const unjudged = fieldsWhere(f => f.share === 'gate' || f.share === 'scope')
      .filter(f => !(f.key in OWN_DIRECTIONS) && f.roe_parse !== 'tighten_only' && directionOf(f.key) === undefined)
      .map(f => f.key)
    expect(unjudged).toEqual([])
  })

  test('every own direction and every exploit gate names a gate or scope field', () => {
    const classed = new Set(fieldsWhere(f => f.share === 'gate' || f.share === 'scope').map(f => f.key))
    expect(Object.keys(OWN_DIRECTIONS).filter(k => !classed.has(k))).toEqual([])
    const gates = new Set(fieldsWhere(f => f.share === 'gate').map(f => f.key))
    expect([...EXPLOIT_GATES].filter(k => !gates.has(k))).toEqual([])
  })

  test('the exploit gates are the agent approval, phase, tunnel and Kali switches', () => {
    expect([...EXPLOIT_GATES].sort()).toEqual([
      'agentActivatePostExplPhase', 'agentChiselTunnelEnabled', 'agentKaliInstallAllowedPackages',
      'agentKaliInstallEnabled', 'agentKaliInstallForbiddenPackages', 'agentNgrokTunnelEnabled',
      'agentRequireApprovalForExploitation', 'agentRequireApprovalForPostExploitation',
      'agentRequireToolConfirmation', 'mcpKaliExecEnabled',
    ])
  })

  test('classifying never throws on a value of the wrong shape', () => {
    for (const key of fieldKeys()) {
      for (const [b, a] of [[null, 'x'], [{ a: 1 }, 7], [['x'], true]] as Array<[unknown, unknown]>) {
        expect(() => classifyField(key, b, a), key).not.toThrow()
      }
    }
  })
})
