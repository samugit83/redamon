/**
 * The share dialog's presets and toggles as data (steps 4.12, 5.14; SH-05, UI-07, HD-22, SH-29, ID-25;
 * feature document §6.1, §6.5): what each preset grants, which preset a share is, the body a grant
 * sends, when the Read + Write presets are offered (write sharing in force) and, within it, what the
 * person may grant (Root's policy, a co-owner's own toggles, the owner's consent), the warnings, and
 * which share control a project row offers.
 *
 * Run: npx vitest run --no-file-parallelism src/components/sharing/sharePresets.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import {
  COPY_WARNING,
  NOTE_MAX_CHARS,
  RAW_DATA_WARNING,
  SPEND_TOGGLE_IDS,
  READ_SHOWS_FINDINGS_WARNING,
  SANDBOX_NOTICE,
  SHARE_PRESETS,
  SHARE_TOGGLES,
  TARGET_CREDENTIALS_WARNING,
  WRITE_PRESETS_COMING,
  consentNeeded,
  copyWarningApplies,
  dateInputValue,
  endOfDayIso,
  presetById,
  presetOf,
  presetOffer,
  shareActions,
  shareTermsLabel,
  termsToBody,
  toggleOffer,
  writePresetsRefusal,
} from './sharePresets'
import type { MyAccess } from '@/lib/authz/projectAccess'

const NONE = { runScans: false, useAgent: false, exploit: false, manage: false }

describe('presets map to the right fields (§6.1)', () => {
  test('the seven presets, in the feature document\'s order', () => {
    expect(SHARE_PRESETS.map(p => p.id)).toEqual(['viewer', 'analyst', 'editor', 'operator', 'red_teamer', 'co_owner', 'custom'])
    expect(SHARE_PRESETS.map(p => p.label)).toEqual(['Viewer', 'Analyst', 'Editor', 'Operator', 'Red-teamer', 'Co-owner', 'Custom'])
  })

  test('Viewer is Read; Analyst is Read + Raw data & files', () => {
    expect(presetById('viewer').terms).toEqual({ access: 'read', rawData: false, ...NONE })
    expect(presetById('analyst').terms).toEqual({ access: 'read', rawData: true, ...NONE })
  })

  test('the write presets build on each other; Read + Write includes Raw data; Co-owner holds every toggle', () => {
    expect(presetById('editor').terms).toEqual({ access: 'write', rawData: true, ...NONE })
    expect(presetById('operator').terms).toEqual({ access: 'write', rawData: true, ...NONE, runScans: true, useAgent: true })
    expect(presetById('red_teamer').terms).toEqual({ access: 'write', rawData: true, ...NONE, runScans: true, useAgent: true, exploit: true })
    expect(presetById('co_owner').terms).toEqual({ access: 'write', rawData: true, runScans: true, useAgent: true, exploit: true, manage: true })
  })

  test('Custom has no fixed terms; only Viewer, Analyst and Custom are read presets', () => {
    expect(presetById('custom').terms).toBeNull()
    expect(SHARE_PRESETS.filter(p => p.level === 'read').map(p => p.id)).toEqual(['viewer', 'analyst', 'custom'])
    expect(SHARE_PRESETS.filter(p => p.level === 'write').map(p => p.id)).toEqual(['editor', 'operator', 'red_teamer', 'co_owner'])
  })

  test('which preset a share is: an exact match, else Custom; a row without write toggles reads them as off', () => {
    expect(presetOf({ access: 'read', rawData: false })).toBe('viewer')
    expect(presetOf({ access: 'read', rawData: true })).toBe('analyst')
    expect(presetOf({ access: 'write', rawData: true, runScans: true, useAgent: true })).toBe('operator')
    expect(presetOf({ access: 'write', rawData: false })).toBe('custom')
    expect(presetOf({ access: 'read', rawData: false, runScans: true })).toBe('custom')
  })

  test('a grant sends the level and Raw data; the write toggles only with a write level', () => {
    expect(termsToBody(presetById('viewer').terms!)).toEqual({ access: 'read', rawData: false })
    expect(termsToBody(presetById('analyst').terms!)).toEqual({ access: 'read', rawData: true })
    expect(termsToBody(presetById('operator').terms!)).toEqual({
      access: 'write', rawData: true, runScans: true, useAgent: true, exploit: false, manage: false,
    })
  })

  test('labels: the preset and what it grants', () => {
    expect(shareTermsLabel({ access: 'read', rawData: false })).toBe('Viewer (Read)')
    expect(shareTermsLabel({ access: 'read', rawData: true })).toBe('Analyst (Read + Raw data & files)')
    expect(shareTermsLabel({ access: 'write', rawData: false })).toBe('Custom (Read + Write)')
  })
})

describe('toggles and their warnings (HD-22, SH-29)', () => {
  test('Raw data & files applies to Read; the other four to Read + Write', () => {
    expect(SHARE_TOGGLES.map(t => [t.id, t.level])).toEqual([
      ['rawData', 'read'], ['runScans', 'write'], ['useAgent', 'write'], ['exploit', 'write'], ['manage', 'write'],
    ])
  })

  test('Use AI agent and Exploitation name the shared sandbox (the registry labels kali_exec sandboxShared)', () => {
    const notices = Object.fromEntries(SHARE_TOGGLES.map(t => [t.id, t.notices]))
    expect(notices.useAgent).toContain(SANDBOX_NOTICE)
    expect(notices.exploit).toContain(SANDBOX_NOTICE)
    expect(notices.rawData).toEqual([RAW_DATA_WARNING])
    expect(SANDBOX_NOTICE).toMatch(/sandbox shared by every project on this server/)
  })

  test('Run scans and Use AI agent carry the target credentials', () => {
    const notices = Object.fromEntries(SHARE_TOGGLES.map(t => [t.id, t.notices]))
    expect(notices.runScans).toContain(TARGET_CREDENTIALS_WARNING)
    expect(notices.useAgent).toContain(TARGET_CREDENTIALS_WARNING)
    expect(notices.manage).toEqual([])
  })

  test('the words', () => {
    expect(RAW_DATA_WARNING).toBe('Raw data includes captured traffic, workspace files and loot; grant it as you would hand over the files.')
    expect(TARGET_CREDENTIALS_WARNING).toMatch(/target credentials/)
    expect(READ_SHOWS_FINDINGS_WARNING).toMatch(/secrets/)
  })
})

describe('the Read + Write presets', () => {
  test('write switch off: disabled, "Coming when write sharing is on"', () => {
    expect(WRITE_PRESETS_COMING).toBe('Coming when write sharing is on')
    expect(writePresetsRefusal({ sharingWrite: false }, { enabled: true, maxLevel: 'read' })).toBe(WRITE_PRESETS_COMING)
    expect(writePresetsRefusal(null, null)).toBe(WRITE_PRESETS_COMING)
  })

  // By design (step 5.14, SH-05/UI-07): with write sharing in force the presets are offered (4.12 kept them disabled).
  test("write switch on: Root's policy at Read names why; at write they are offered", () => {
    expect(writePresetsRefusal({ sharingWrite: true }, { enabled: true, maxLevel: 'read' })).toBe('The instance sharing policy allows Read shares only')
    expect(writePresetsRefusal({ sharingWrite: true }, { enabled: true, maxLevel: 'write' })).toBeNull()
  })
})

describe('what the person may grant (step 5.14)', () => {
  const ok = { grantable: true as const }
  const grantable = (over: Record<string, unknown> = {}) => ({
    toggles: { runScans: ok, useAgent: ok, exploit: ok, manage: ok, ...over },
  }) as never

  test('presets: with write sharing in force and nothing refused, every preset and toggle is offered', () => {
    for (const p of SHARE_PRESETS) expect([p.id, presetOffer(p, null, grantable())]).toEqual([p.id, { state: 'offered' }])
    expect(toggleOffer('exploit', null, grantable())).toEqual({ state: 'offered' })
    // No grantable answer yet (or an older server): offered, the route decides.
    expect(toggleOffer('exploit', null, null)).toEqual({ state: 'offered' })
  })

  test('write sharing not in force: every write preset and toggle disabled with that reason; the read presets offered', () => {
    expect(presetOffer(presetById('editor'), WRITE_PRESETS_COMING, null)).toEqual({ state: 'disabled', reason: WRITE_PRESETS_COMING })
    expect(toggleOffer('manage', WRITE_PRESETS_COMING, null)).toEqual({ state: 'disabled', reason: WRITE_PRESETS_COMING })
    expect(presetOffer(presetById('analyst'), WRITE_PRESETS_COMING, null)).toEqual({ state: 'offered' })
  })

  test("policy limits: Exploitation kept to admins disables it and every preset holding it, with Root's reason", () => {
    const g = grantable({ exploit: { grantable: false, code: 'exploit_admins_only', reason: 'Only administrators.' } })
    expect(toggleOffer('exploit', null, g)).toEqual({ state: 'disabled', reason: 'Only administrators.' })
    expect(presetOffer(presetById('red_teamer'), null, g)).toEqual({ state: 'disabled', reason: 'Only administrators.' })
    expect(presetOffer(presetById('co_owner'), null, g)).toEqual({ state: 'disabled', reason: 'Only administrators.' })
    expect(presetOffer(presetById('operator'), null, g)).toEqual({ state: 'offered' })
  })

  test('co-owner cap: what a co-owner does not hold is not shown, nor any preset holding it', () => {
    const g = grantable({
      useAgent: { grantable: false, code: 'not_held', reason: 'not held' },
      exploit: { grantable: false, code: 'not_held', reason: 'not held' },
    })
    expect(toggleOffer('useAgent', null, g)).toEqual({ state: 'hidden' })
    expect(toggleOffer('runScans', null, g)).toEqual({ state: 'offered' })
    expect(['editor', 'operator', 'red_teamer', 'co_owner'].map(id => presetOffer(presetById(id as never), null, g).state))
      .toEqual(['offered', 'hidden', 'hidden', 'hidden'])
  })

  test("consent prompt: needed for a spend toggle until the owner consented; Manage never needs it", () => {
    expect(SPEND_TOGGLE_IDS).toEqual(['runScans', 'useAgent', 'exploit'])
    const src = readFileSync(path.resolve(__dirname, '../../lib/authz/ownerConsent.ts'), 'utf8')
    expect(src).toContain("export const SPEND_TOGGLES = ['runScans', 'useAgent', 'exploit'] as const")
    expect(consentNeeded({ runScans: true }, { ownerConsent: false })).toBe(true)
    expect(consentNeeded({ exploit: true }, { ownerConsent: false })).toBe(true)
    expect(consentNeeded({ manage: true }, { ownerConsent: false })).toBe(false)
    expect(consentNeeded({ useAgent: true }, { ownerConsent: true })).toBe(false)
    expect(consentNeeded({ useAgent: true }, null)).toBe(false)
  })

  test('warnings shown: what a collaborator sees can be copied, with Raw data, Read + Write or the agent', () => {
    expect(COPY_WARNING).toMatch(/can copy what they see/)
    expect(copyWarningApplies(presetById('viewer').terms!)).toBe(false)
    expect(copyWarningApplies(presetById('analyst').terms!)).toBe(true)
    expect(copyWarningApplies(presetById('editor').terms!)).toBe(true)
  })

  test('a Custom Read + Write share is labelled with its toggles', () => {
    expect(shareTermsLabel({ access: 'write', rawData: true, manage: true })).toBe('Custom (Read + Write + Manage (co-owner))')
    expect(shareTermsLabel({ access: 'write', rawData: true, exploit: true })).toBe('Custom (Read + Write + Exploitation & shells)')
  })
})

describe('dates and limits', () => {
  test('a day ends at 23:59:59 in the browser\'s zone; an instant shows as its local day', () => {
    expect(new Date(endOfDayIso('2027-01-31')).getTime()).toBe(new Date(2027, 0, 31, 23, 59, 59).getTime())
    expect(dateInputValue(endOfDayIso('2027-01-31'))).toBe('2027-01-31')
    expect(dateInputValue(null)).toBe('')
    expect(dateInputValue('not a date')).toBe('')
  })

  test('the note limit is the route\'s', () => {
    const src = readFileSync(path.resolve(__dirname, '../../lib/authz/projectShares.ts'), 'utf8')
    expect(src).toContain(`export const NOTE_MAX_LENGTH = ${NOTE_MAX_CHARS}`)
  })
})

describe('the share control a project row or the header offers', () => {
  const access = (over: Partial<MyAccess>): MyAccess => ({
    level: 'read', toggles: { rawData: false }, via: 'share', owner: { name: 'Alice', email: 'alice@example.test' }, ...over,
  })

  test('sharing in force: Share on the person\'s own project, Leave on one shared with them', () => {
    expect(shareActions({ myAccess: access({ level: 'owner', via: 'owner' }) }, true)).toEqual({ share: true, leave: false })
    expect(shareActions({ myAccess: access({}) }, true)).toEqual({ share: false, leave: true })
    expect(shareActions({ myAccess: access({ toggles: { rawData: true } }) }, true)).toEqual({ share: false, leave: true })
  })

  test('a co-owner (Read + Write with Manage) also gets Share; an editor without Manage only Leave', () => {
    const write = { rawData: true, runScans: false, useAgent: false, exploit: false }
    expect(shareActions({ myAccess: access({ level: 'write', toggles: { ...write, manage: true } }) }, true)).toEqual({ share: true, leave: true })
    expect(shareActions({ myAccess: access({ level: 'write', toggles: { ...write, manage: false } }) }, true)).toEqual({ share: false, leave: true })
  })

  test('oversight and break-glass are not shares: nothing to share, nothing to leave', () => {
    expect(shareActions({ myAccess: access({ via: 'oversight' }) }, true)).toEqual({ share: false, leave: false })
    expect(shareActions({ myAccess: access({ via: 'break_glass', toggles: { rawData: true } }) }, true)).toEqual({ share: false, leave: false })
  })

  test('sharing not in force, or a row read without myAccess: neither (DV-30)', () => {
    expect(shareActions({ myAccess: access({ level: 'owner', via: 'owner' }) }, false)).toEqual({ share: false, leave: false })
    expect(shareActions({ myAccess: access({}) }, false)).toEqual({ share: false, leave: false })
    expect(shareActions({}, true)).toEqual({ share: false, leave: false })
    expect(shareActions({ myAccess: null }, true)).toEqual({ share: false, leave: false })
    expect(shareActions(null, true)).toEqual({ share: false, leave: false })
  })
})
