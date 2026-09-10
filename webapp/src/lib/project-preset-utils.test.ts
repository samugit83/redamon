/**
 * Unit tests for the User Project Preset utility functions.
 *
 * Tests verify:
 *   - the preset field set is the whole registry minus the excluded classes
 *   - extractPresetSettings captures EVERY preset field, and nothing else
 *   - applyPresetSettings replaces every preset field and nothing else
 *   - both preset paths in ProjectForm go through the one guarded function
 *
 * @vitest-environment node
 */
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'
import {
  engagementLimitFields,
  engagementRecordFields,
  field,
  fieldKeys,
  fieldsWhere,
} from './reconSettings/registry'
import {
  PRESET_EXCLUDED_FIELDS,
  PRESET_FIELD_KEYS,
  applyPresetSettings,
  appliedPresetName,
  extractPresetSettings,
  pickPresetFields,
  presetFingerprint,
  readLoadedPreset,
} from './project-preset-utils'

/** The half that is listed by name, because it has no registry classification. */
const UNCLASSIFIED = ['name', 'description', 'vhostSniCustomWordlist', 'supplyChainInputMode']

/**
 * Real settings columns that `/api/projects/defaults` does not return (measured
 * against a running stack). The create form only holds what /defaults returned,
 * so these are the columns a preset used to lose.
 */
const ABSENT_FROM_BACKEND_DEFAULTS = [
  'katanaScope', 'sqliLevel', 'sqliRisk', 'sqliTamperScripts', 'ssrfCloudProviders',
  'rceAggressivePayloads', 'pathTraversalRequestTimeout', 'trufflehogEnabled',
  'trufflehogConcurrency', 'cypherfixDefaultBranch', 'cypherfixRequireApproval',
  'supplyChainEcosystems', 'supplyChainOrgMaxRepos', 'triageReviewBudget',
  'agentGuardrailEnabled', 'agentLatsPhaseExploitation', 'mcpKaliExecEnabled',
]

// ============================================================
// PRESET_EXCLUDED_FIELDS / PRESET_FIELD_KEYS
// ============================================================

describe('PRESET_EXCLUDED_FIELDS', () => {
  test('is a Set', () => {
    expect(PRESET_EXCLUDED_FIELDS).toBeInstanceOf(Set)
  })

  test('is composed of registry QUERIES, not a snapshot of one', () => {
    // The guard used to be `key.startsWith('roe')`, a string match on a COLUMN
    // NAME. Renaming a column or reclassifying a field must move this set with
    // it, which is only true if it is derived rather than listed.
    const bookkeeping = fieldsWhere((f, key) =>
      (f.deny_reason === 'identity' || f.deny_reason === 'internal' || f.deny_reason === 'derived')
      && key !== 'reconPresetId'
    )
    const expected = new Set([
      ...UNCLASSIFIED,
      ...fieldsWhere(f => f.mcp === 'create_only').map(f => f.key),
      ...engagementLimitFields().map(f => f.key),
      ...engagementRecordFields().map(f => f.key),
      ...fieldsWhere(f => f.tool === 'engagement').map(f => f.key),
      ...fieldsWhere(f => f.deny_reason === 'upload-managed').map(f => f.key),
      ...fieldsWhere(f => f.read_deny_reason === 'credential').map(f => f.key),
      ...bookkeeping.map(f => f.key),
    ])
    expect([...PRESET_EXCLUDED_FIELDS].sort()).toEqual([...expected].sort())
  })

  test('the scope never travels: target, batch, ownership proof, guardrail', () => {
    for (const key of [
      'targetDomain', 'subdomainList', 'ipMode', 'targetIps',
      'domainBatchMode', 'domainBatchHosts', 'domainBatchGroups',
      'verifyDomainOwnership', 'ownershipToken', 'ownershipTxtPrefix', 'targetGuardrailEnabled',
    ]) {
      expect(PRESET_EXCLUDED_FIELDS.has(key), key).toBe(true)
    }
  })

  test("the other scanners' targets never travel", () => {
    for (const key of [
      'githubTargetOrg', 'githubTargetRepos', 'gvmScanTargets',
      'supplyChainRepoUrl', 'supplyChainRepoRef', 'supplyChainOrgName', 'supplyChainInputMode',
    ]) {
      expect(PRESET_EXCLUDED_FIELDS.has(key), key).toBe(true)
    }
  })

  test('every engagement limit and every record column is excluded', () => {
    // A user preset used to capture 37 engagement columns, including the rate
    // ceiling, the excluded-host list and seven PII fields. Loading it into
    // another project overwrote that project's scope controls with the first
    // one's and copied the client's contact details across.
    for (const f of [...engagementLimitFields(), ...engagementRecordFields()]) {
      expect(PRESET_EXCLUDED_FIELDS.has(f.key), f.key).toBe(true)
    }
    expect(PRESET_EXCLUDED_FIELDS.has('engagementKind')).toBe(true)
    expect(PRESET_EXCLUDED_FIELDS.has('engagementIdentityHeader')).toBe(true)
  })

  test('credentials are excluded, and so are the settings around them', () => {
    // A per-target credential applied to another project is sent to a target it
    // was never issued for.
    for (const key of ['cypherfixGithubToken', 'graphqlAuthValue', 'phishingSmtpConfig', 'ownershipToken']) {
      expect(PRESET_EXCLUDED_FIELDS.has(key), key).toBe(true)
    }
    // The header NAME and the secrets-extraction toggle are configuration.
    expect(PRESET_EXCLUDED_FIELDS.has('graphqlAuthHeader')).toBe(false)
    expect(PRESET_EXCLUDED_FIELDS.has('jsluiceExtractSecrets')).toBe(false)
  })

  test('the row bookkeeping is excluded', () => {
    // A preset carrying `id` made the receiving project's next save try to
    // rewrite its primary key.
    for (const key of [
      'id', 'userId', 'createdAt', 'updatedAt', 'createdById', 'updatedById',
      'activationState', 'activationStartedAt', 'activationVersionId', 'roeEnabled',
    ]) {
      expect(PRESET_EXCLUDED_FIELDS.has(key), key).toBe(true)
    }
  })

  test('uploaded files and per-project wordlists are excluded', () => {
    for (const key of ['roeDocumentData', 'roeDocumentName', 'jsReconUploadedFiles',
      'supplyChainSbomFile', 'vhostSniCustomWordlist']) {
      expect(PRESET_EXCLUDED_FIELDS.has(key), key).toBe(true)
    }
  })

  test('does NOT exclude recon, agent or reconPresetId settings', () => {
    for (const key of ['naabuEnabled', 'nucleiEnabled', 'katanaDepth', 'scanModules',
      'agentOpenaiModel', 'aiPipelineModel', 'agentMaxIterations', 'agentToolPhaseMap',
      'reconPresetId', 'mcpKaliExecEnabled', 'updateGraphDb']) {
      expect(PRESET_EXCLUDED_FIELDS.has(key), key).toBe(false)
    }
  })
})

describe('PRESET_FIELD_KEYS', () => {
  test('with the excluded set, partitions the whole registry exactly', () => {
    const all = fieldKeys()
    expect(PRESET_FIELD_KEYS.length + PRESET_EXCLUDED_FIELDS.size).toBe(all.length)
    for (const key of all) {
      expect(PRESET_FIELD_KEYS.includes(key) !== PRESET_EXCLUDED_FIELDS.has(key), key).toBe(true)
    }
  })

  test('holds only registry columns', () => {
    for (const key of PRESET_FIELD_KEYS) expect(field(key), key).toBeDefined()
  })

  test('includes the settings /defaults does not return', () => {
    for (const key of ABSENT_FROM_BACKEND_DEFAULTS) {
      expect(PRESET_FIELD_KEYS.includes(key), key).toBe(true)
    }
  })
})

// ============================================================
// extractPresetSettings
// ============================================================

describe('extractPresetSettings', () => {
  test('captures every preset field, even from an empty form', () => {
    const result = extractPresetSettings({})
    expect(Object.keys(result).sort()).toEqual([...PRESET_FIELD_KEYS].sort())
  })

  test('a key the form does not hold is captured at its Prisma default', () => {
    // The create form only holds what /defaults returned.
    const result = extractPresetSettings({ naabuEnabled: false })
    expect(result.naabuEnabled).toBe(false)
    expect(result.katanaScope).toBe('dn')
    expect(result.sqliLevel).toBe(1)
    expect(result.triageReviewBudget).toBe(150)
    expect(result.agentLport).toBeNull()
  })

  test('Json defaults are captured as values, not as the Prisma string', () => {
    const result = extractPresetSettings({})
    expect(typeof result.agentToolPhaseMap).toBe('object')
    expect(typeof result.attackSkillConfig).toBe('object')
  })

  test('strips all excluded fields', () => {
    const result = extractPresetSettings({
      name: 'Test Project',
      description: 'A description',
      targetDomain: 'example.com',
      subdomainList: ['sub1'],
      ipMode: false,
      targetIps: ['192.168.1.1'],
      roeDocumentData: Buffer.from('binary'),
      roeDocumentName: 'roe.pdf',
      jsReconUploadedFiles: ['file1.js'],
      roeGlobalMaxRps: 5,
      roeClientName: 'ACME',
      openapiSources: [{ url: 'https://docs.example.test/openapi.json', headers: ['Authorization: Bearer secret'] }],
      openapiDiscoveryHeaders: [{ origin: 'https://docs.example.test', headers: ['X-API-Key: secret'] }],
      naabuEnabled: true,
      nucleiEnabled: false,
      agentMaxIterations: 50,
    })
    for (const key of ['name', 'description', 'targetDomain', 'subdomainList', 'ipMode',
      'targetIps', 'roeDocumentData', 'roeDocumentName', 'jsReconUploadedFiles',
      'roeGlobalMaxRps', 'roeClientName', 'openapiSources', 'openapiDiscoveryHeaders']) {
      expect(result, key).not.toHaveProperty(key)
    }
    expect(result.naabuEnabled).toBe(true)
    expect(result.nucleiEnabled).toBe(false)
    expect(result.agentMaxIterations).toBe(50)
  })

  test('an edit-mode row: drops the row identity, relations and credentials', () => {
    // In edit mode the form holds the whole GET /api/projects/[id] response.
    const row = {
      id: 'proj-a',
      userId: 'user-1',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-02T00:00:00.000Z',
      user: { id: 'user-1', name: 'u', email: 'u@example.test' },
      authProfile: { id: 'ap-1', hasValue: true },
      cypherfixGithubToken: 'ghp_example',
      graphqlAuthValue: 'Bearer example',
      katanaDepth: 4,
    }
    const result = extractPresetSettings(row)
    for (const key of ['id', 'userId', 'createdAt', 'updatedAt', 'user', 'authProfile',
      'cypherfixGithubToken', 'graphqlAuthValue']) {
      expect(result, key).not.toHaveProperty(key)
    }
    expect(JSON.stringify(result)).not.toContain('ghp_example')
    expect(result.katanaDepth).toBe(4)
  })

  test('drops keys /defaults returns that are not Project columns', () => {
    const result = extractPresetSettings({ githubAccessToken: 'x', gvmReadyMaxRetries: 3 })
    expect(result).not.toHaveProperty('githubAccessToken')
    expect(result).not.toHaveProperty('gvmReadyMaxRetries')
  })

  test('preserves complex value types (arrays, objects, null)', () => {
    const result = extractPresetSettings({
      scanModules: ['port_scan', 'vuln_scan'],
      agentToolPhaseMap: { query_graph: ['informational'] },
      nucleiTemplates: [],
      agentLport: null,
      katanaTimeout: 3600,
      httpxProbeHash: 'sha256',
    })
    expect(result.scanModules).toEqual(['port_scan', 'vuln_scan'])
    expect(result.agentToolPhaseMap).toEqual({ query_graph: ['informational'] })
    expect(result.nucleiTemplates).toEqual([])
    expect(result.agentLport).toBeNull()
    expect(result.katanaTimeout).toBe(3600)
    expect(result.httpxProbeHash).toBe('sha256')
  })

  test('preserves false, zero and empty string (not replaced by defaults)', () => {
    const result = extractPresetSettings({
      naabuEnabled: false,
      updateGraphDb: false,
      ffufRate: 0,
      nucleiRetries: 0,
      agentInformationalSystemPrompt: '',
    })
    expect(result.naabuEnabled).toBe(false)
    expect(result.updateGraphDb).toBe(false)
    expect(result.ffufRate).toBe(0)
    expect(result.nucleiRetries).toBe(0)
    expect(result.agentInformationalSystemPrompt).toBe('')
  })

  test('keeps reconPresetId for the badge', () => {
    expect(extractPresetSettings({ reconPresetId: 'full-active-scan' }).reconPresetId).toBe('full-active-scan')
  })

  test('does not mutate its input, and is JSON-safe', () => {
    const formData: Record<string, unknown> = { name: 'Test', naabuEnabled: true }
    const original = { ...formData }
    const result = extractPresetSettings(formData)
    expect(formData).toEqual(original)
    expect(JSON.parse(JSON.stringify(result))).toEqual(result)
  })
})

// ============================================================
// applyPresetSettings
// ============================================================

describe('applyPresetSettings', () => {
  const current = {
    name: 'Receiving project',
    targetDomain: 'other.example.com',
    roeGlobalMaxRps: 3,
    cypherfixGithubToken: 'ghp_receiving',
    agentOpenaiModel: 'my-configured-model',
    aiPipelineModel: 'my-pipeline-model',
    naabuEnabled: false,
    katanaDepth: 9,
    sqliLevel: 5,
  }

  test('writes the preset value for every field it names', () => {
    const next = applyPresetSettings(current, { naabuEnabled: true, katanaDepth: 3 }, {})
    expect(next.naabuEnabled).toBe(true)
    expect(next.katanaDepth).toBe(3)
  })

  test('REPLACES the configuration: every unnamed preset field is reset', () => {
    // The previous value (katanaDepth 9, sqliLevel 5) must not survive.
    const next = applyPresetSettings(current, {}, { katanaDepth: 2 })
    expect(next.katanaDepth).toBe(2)          // backend default
    expect(next.sqliLevel).toBe(1)            // not in /defaults: Prisma default
    expect(next.agentLport).toBeNull()        // nullable, no default
    for (const key of PRESET_FIELD_KEYS) expect(next, key).toHaveProperty(key)
  })

  test('the backend default wins over the Prisma default', () => {
    const next = applyPresetSettings({}, {}, { fireteamTimeoutSec: 7200 })
    expect(next.fireteamTimeoutSec).toBe(7200)
    expect(applyPresetSettings({}, {}, {}).fireteamTimeoutSec).toBe(3600)
  })

  test('never touches an excluded field, even when a stale preset carries it', () => {
    // Presets saved before the exclusions existed carry all of these.
    const stale = {
      id: 'proj-a',
      userId: 'user-a',
      targetDomain: 'source.example.com',
      roeGlobalMaxRps: 99,
      cypherfixGithubToken: 'ghp_source',
      name: 'Source project',
      naabuEnabled: true,
    }
    const next = applyPresetSettings(current, stale, {})
    expect(next).not.toHaveProperty('id')
    expect(next).not.toHaveProperty('userId')
    expect(next.targetDomain).toBe('other.example.com')
    expect(next.roeGlobalMaxRps).toBe(3)
    expect(next.cypherfixGithubToken).toBe('ghp_receiving')
    expect(next.name).toBe('Receiving project')
    expect(next.naabuEnabled).toBe(true)
  })

  test('never writes a key that is not a Project column', () => {
    // PUT passes the body to Prisma, which rejects an unknown argument.
    const next = applyPresetSettings(current, { user: { id: 'x' }, takeoverCnameValidationEnabled: true },
      { takeoverCnameValidationEnabled: true, githubAccessToken: 'x' })
    expect(next).not.toHaveProperty('user')
    expect(next).not.toHaveProperty('takeoverCnameValidationEnabled')
    expect(next).not.toHaveProperty('githubAccessToken')
  })

  test('applies fields the current form does not hold yet (the create form)', () => {
    const next = applyPresetSettings({ naabuEnabled: true }, { sqliLevel: 3, trufflehogEnabled: true }, {})
    expect(next.sqliLevel).toBe(3)
    expect(next.trufflehogEnabled).toBe(true)
  })

  test('keeps the LLM models when the preset does not name them', () => {
    // Built-in and AI-generated presets never do, and the backend default is a
    // hardcoded model the user may have no provider for.
    const next = applyPresetSettings(current, { naabuEnabled: true },
      { agentOpenaiModel: 'claude-opus-4-6', aiPipelineModel: 'claude-opus-4-6' })
    expect(next.agentOpenaiModel).toBe('my-configured-model')
    expect(next.aiPipelineModel).toBe('my-pipeline-model')
  })

  test('applies the LLM models when the preset names them', () => {
    const next = applyPresetSettings(current, { agentOpenaiModel: 'saved-model' }, {})
    expect(next.agentOpenaiModel).toBe('saved-model')
  })

  test('reconPresetId follows the preset, and resets when it has none', () => {
    const withBadge = { ...current, reconPresetId: 'stealth-recon' }
    expect(applyPresetSettings(withBadge, { reconPresetId: 'full-active-scan' }, {}).reconPresetId)
      .toBe('full-active-scan')
    expect(applyPresetSettings(withBadge, {}, {}).reconPresetId).toBeNull()
  })

  test('does not mutate its inputs', () => {
    const cur = { ...current }
    const preset = { naabuEnabled: true }
    applyPresetSettings(cur, preset, {})
    expect(cur).toEqual(current)
    expect(preset).toEqual({ naabuEnabled: true })
  })

  test('roundtrip: project B ends up with ALL of project A\'s settings, and keeps its own scope', () => {
    const projectA: Record<string, unknown> = {
      ...extractPresetSettings({}),
      id: 'proj-a',
      targetDomain: 'a.example.com',
      naabuEnabled: false,
      katanaDepth: 5,
      sqliLevel: 4,
      trufflehogEnabled: true,
      agentOpenaiModel: 'model-a',
      roeGlobalMaxRps: 50,
    }
    const projectB: Record<string, unknown> = {
      id: 'proj-b',
      targetDomain: 'b.example.com',
      katanaDepth: 1,
      roeGlobalMaxRps: 3,
    }
    const saved = JSON.parse(JSON.stringify(extractPresetSettings(projectA)))
    const next = applyPresetSettings(projectB, saved, {})

    for (const key of PRESET_FIELD_KEYS) expect(next[key], key).toEqual(projectA[key])
    expect(next.id).toBe('proj-b')
    expect(next.targetDomain).toBe('b.example.com')
    expect(next.roeGlobalMaxRps).toBe(3)
  })
})

describe('pickPresetFields', () => {
  test('keeps only the preset fields: the body a preset load saves', () => {
    const picked = pickPresetFields({
      id: 'proj-b', name: 'B', targetDomain: 'b.example.com', roeGlobalMaxRps: 3,
      naabuEnabled: true, katanaDepth: 2, user: { id: 'x' },
    })
    expect(picked).toEqual({ naabuEnabled: true, katanaDepth: 2 })
  })
})

// ============================================================
// The "Preset applied" badge: loadedPreset + fingerprint
// ============================================================

describe('presetFingerprint / appliedPresetName', () => {
  const loaded = (settings: Record<string, unknown>, name = 'Stealth') => {
    const next = applyPresetSettings({ name: 'P', targetDomain: 'a.example.com' }, settings, {})
    return { ...next, loadedPreset: { name, fingerprint: presetFingerprint(next) } }
  }

  test('the marker is never part of a preset itself', () => {
    expect(PRESET_EXCLUDED_FIELDS.has('loadedPreset')).toBe(true)
    expect(extractPresetSettings({ loadedPreset: { name: 'x', fingerprint: 'y' } })).not.toHaveProperty('loadedPreset')
  })

  test('shows the name while the settings are exactly what the preset produced', () => {
    expect(appliedPresetName(loaded({ naabuEnabled: false }))).toBe('Stealth')
  })

  test('disappears once ANY preset field changes', () => {
    const project = loaded({ naabuEnabled: false })
    expect(appliedPresetName({ ...project, naabuEnabled: true })).toBeNull()
    expect(appliedPresetName({ ...project, katanaDepth: 7 })).toBeNull()
    expect(appliedPresetName({ ...project, agentToolPhaseMap: {} })).toBeNull()
  })

  test('stays when only the target, the name or the RoE change', () => {
    // Those are not preset settings, so the project still runs the preset.
    const project = loaded({ naabuEnabled: false })
    expect(appliedPresetName({ ...project, targetDomain: 'b.example.com', name: 'Q', roeGlobalMaxRps: 5 }))
      .toBe('Stealth')
  })

  test('comes back if the settings are changed back to the preset', () => {
    const project = loaded({ katanaDepth: 3 })
    const edited = { ...project, katanaDepth: 4 }
    expect(appliedPresetName(edited)).toBeNull()
    expect(appliedPresetName({ ...edited, katanaDepth: 3 })).toBe('Stealth')
  })

  test('survives the database round trip: jsonb reorders object keys', () => {
    const project = loaded({ agentToolPhaseMap: { b: ['x'], a: ['y'] } })
    const reordered = { ...project, agentToolPhaseMap: { a: ['y'], b: ['x'] } }
    expect(appliedPresetName(JSON.parse(JSON.stringify(reordered)))).toBe('Stealth')
  })

  test('a field the data does not hold counts as its default', () => {
    expect(presetFingerprint({})).toBe(presetFingerprint(extractPresetSettings({})))
  })

  test('no marker, or a malformed one, shows nothing', () => {
    const project = loaded({})
    expect(appliedPresetName({ ...project, loadedPreset: null })).toBeNull()
    expect(appliedPresetName({ ...project, loadedPreset: { name: 'x' } })).toBeNull()
    expect(readLoadedPreset('Stealth')).toBeNull()
    expect(readLoadedPreset({ name: 'a', fingerprint: 'b' })).toEqual({ name: 'a', fingerprint: 'b' })
  })
})

/**
 * Domain batch F3: a preset must not carry one project's target scope into
 * another. Saving a preset from a batch project used to store its hostname list,
 * and applying it flipped an unrelated project into batch mode pointed at scope
 * its owner never entered.
 */
describe('domain batch scope never travels through a preset', () => {
  const batchProjectForm = {
    naabuTopPorts: '1000',
    nucleiSeverity: ['high'],
    targetDomain: 'single.example.com',
    subdomainList: ['www.'],
    ipMode: false,
    targetIps: ['10.0.0.1'],
    domainBatchMode: true,
    domainBatchHosts: ['secret-a.client.com', 'secret-b.client.com'],
    domainBatchGroups: [{ rootDomain: 'client.com', prefixes: ['secret-a.', 'secret-b.'], hosts: [] }],
  }

  test('the stored preset contains no batch field and none of the hostnames', () => {
    const settings = extractPresetSettings(batchProjectForm)
    expect(settings).not.toHaveProperty('domainBatchMode')
    expect(settings).not.toHaveProperty('domainBatchHosts')
    expect(settings).not.toHaveProperty('domainBatchGroups')
    const serialized = JSON.stringify(settings)
    expect(serialized).not.toContain('secret-a.client.com')
    expect(serialized).not.toContain('client.com')
  })

  test('the preset still carries the recon config it is for', () => {
    const settings = extractPresetSettings(batchProjectForm)
    expect(settings.naabuTopPorts).toBe('1000')
    expect(settings.nucleiSeverity).toEqual(['high'])
  })

  test('applying such a preset cannot overwrite the receiving project scope', () => {
    const receiving = {
      targetDomain: 'other.example.com',
      domainBatchMode: false,
      domainBatchHosts: [] as string[],
      naabuTopPorts: '100',
    }
    // Even a preset that DID capture the batch (saved before F3) cannot apply it.
    const next = applyPresetSettings(receiving, batchProjectForm, {})
    expect(next.domainBatchMode).toBe(false)
    expect(next.domainBatchHosts).toEqual([])
    expect(next.targetDomain).toBe('other.example.com')
    expect(next.naabuTopPorts).toBe('1000')
  })
})


// --- Both preset paths, one guarded function -----------------------------------

/**
 * Asserted at the source, not by rendering the form: rendering `ProjectForm`
 * needs the whole provider tree, and what went wrong here was structural. There
 * used to be one handler per preset kind, and only one of them was guarded.
 */
describe('ProjectForm: both preset kinds go through loadPreset', () => {
  const form = readFileSync(
    fileURLToPath(new URL('../components/projects/ProjectForm/ProjectForm.tsx', import.meta.url)),
    'utf8'
  )
  const loadPreset = form.slice(form.indexOf('const loadPreset = async'))

  test('the built-in list, the preset modal\'s user list and the drawer all call it', () => {
    expect(form).toMatch(/onSelect=\{\(preset\) => loadPreset\(\{ kind: 'builtin', preset \}\)\}/)
    expect(form.match(/loadPreset\(\{ kind: 'user', \.\.\.preset \}\)/g)).toHaveLength(2)
  })

  test('it confirms first, then applies through applyPresetSettings, then saves', () => {
    const confirmAt = loadPreset.indexOf('await ask(')
    const applyAt = loadPreset.indexOf('applyPresetSettings(')
    const setAt = loadPreset.indexOf('setFormData(next)')
    const saveAt = loadPreset.indexOf('presetSaveMutation.mutateAsync')
    expect(confirmAt).toBeGreaterThan(-1)
    expect(applyAt).toBeGreaterThan(confirmAt)
    expect(setAt).toBeGreaterThan(applyAt)
    expect(saveAt).toBeGreaterThan(setAt)
  })

  test('it saves only the preset fields, not the whole form', () => {
    expect(loadPreset).toMatch(/pickPresetFields\(next/)
    expect(loadPreset).toMatch(/mutateAsync\(\{ projectId, data: saved/)
  })

  test('it records the loaded preset, and saves that record with the settings', () => {
    const markAt = loadPreset.indexOf('fingerprint: presetFingerprint(next')
    expect(markAt).toBeGreaterThan(-1)
    expect(markAt).toBeLessThan(loadPreset.indexOf('setFormData(next)'))
    expect(loadPreset).toMatch(/const saved[^=]*= \{\s*\.\.\.pickPresetFields\(next[^}]*\),\s*loadedPreset,?\s*\}/)
  })

  test('in edit mode the badge reads the SAVED state, so an edit hides it only once saved', () => {
    expect(form).toMatch(/const presetBadgeSource = mode === 'edit' \? baseline : formData/)
    expect(form).toMatch(/appliedPresetName\(presetBadgeSource/)
  })

  test('no path is keyed on the `roe` name prefix', () => {
    // The columns keep their names while their classification changed, so a
    // prefix match survives a reclassification by accident. Comments are
    // stripped: a line explaining what the prefix loop WAS is not a guard.
    const code = form
      .split('\n')
      .filter(line => !/^\s*(\/\/|\*|\/\*)/.test(line))
      .join('\n')
    expect(code).not.toMatch(/startsWith\('roe'\)/)
  })
})
