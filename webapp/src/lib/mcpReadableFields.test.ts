/**
 * The read-side classification for `Project`.
 *
 * The posture CHANGED with the recon settings registry, deliberately and in two
 * directions at once, so this file is worth reading rather than skimming.
 *
 * It used to be a positive set: a new column was unreadable until someone
 * classified it, and the whole Rules of Engagement block was withheld. That
 * second half does not survive contact with the goal. An agent holding an MCP
 * token has to stand up a project that provably cannot violate its scope, and
 * an agent that cannot see its own rate ceiling, its own excluded hosts or its
 * own forbidden tools cannot verify that it is inside them. Withholding the
 * ceiling does not make the ceiling safer; it makes it unverifiable.
 *
 * So the set inverts: `readable: false` is explicit per column in
 * `recon_settings/registry.yaml` and everything else is readable. The thing
 * that has to hold is that the NAMED set never shrinks by accident, which is
 * what the tests below are, and they name each withheld column rather than
 * relying on a pattern.
 *
 * What stays withheld is what an agent has no business with whatever its
 * permissions: a stored credential, third-party personal data, and the signed
 * engagement document itself.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { Prisma } from '@prisma/client'

import {
  MCP_READABLE_PROJECT_FIELDS,
  MCP_UNREADABLE_PROJECT_FIELDS,
  assertReadableSelect,
  isReadableProjectField,
} from './mcpReadableFields'
import { reconSettingsSelect } from './reconSettings/filter'
import { loadRegistry } from './reconSettings/registry'

const columns = Object.keys(Prisma.ProjectScalarFieldEnum)
const registry = loadRegistry()

describe('the readable set is a real, current subset of the model', () => {
  test('it invents no column Prisma does not have', () => {
    const known = new Set(columns)
    const ghosts = [...MCP_READABLE_PROJECT_FIELDS].filter(k => !known.has(k))
    expect(ghosts, 'stale entries for columns that no longer exist').toEqual([])
  })

  test('readable and unreadable together cover every column', () => {
    const missing = columns.filter(
      c => !MCP_READABLE_PROJECT_FIELDS.has(c) && !(c in MCP_UNREADABLE_PROJECT_FIELDS)
    )
    expect(missing).toEqual([])
  })

  test('no column is in both', () => {
    const both = Object.keys(MCP_UNREADABLE_PROJECT_FIELDS).filter(c =>
      MCP_READABLE_PROJECT_FIELDS.has(c)
    )
    expect(both).toEqual([])
  })

  test('every withheld column carries a reason', () => {
    const REASONS = new Set(['credential', 'third_party_pii', 'document_blob', 'other_user'])
    for (const [field, reason] of Object.entries(MCP_UNREADABLE_PROJECT_FIELDS)) {
      expect(REASONS.has(reason), `${field} has reason '${reason}'`).toBe(true)
    }
  })
})

describe('the fields that must never be returned', () => {
  // Named, not matched by pattern. A pattern is what lets a rename silently
  // widen the set; a name fails loudly instead.
  test.each([
    ['cypherfixGithubToken', 'a stored credential'],
    ['graphqlAuthValue', 'an engagement credential'],
    ['ownershipToken', 'the secret proving domain control'],
    ['phishingSmtpConfig', 'SMTP credentials'],
    ['roeClientName', 'third-party identity'],
    ['roeClientContactName', 'third-party personal data'],
    ['roeClientContactEmail', 'third-party personal data'],
    ['roeClientContactPhone', 'third-party personal data'],
    ['roeEmergencyContact', 'third-party personal data'],
    ['roeRawText', 'the engagement agreement verbatim'],
    ['roeParsedJson', 'the engagement agreement, structured'],
    ['roeDocumentData', 'a binary blob'],
    ['roeDocumentName', 'the uploaded document'],
    ['userId', "another account's identifier"],
  ])('%s is not readable (%s)', field => {
    if (!columns.includes(field)) return // a rename; the ghost test owns that
    expect(isReadableProjectField(field)).toBe(false)
  })

  test('no column holding a credential VALUE is readable', () => {
    // graphqlAuthHeader is the header NAME an operator chose and carries no
    // secret; graphqlAuthValue is the credential and is withheld above.
    const CREDENTIAL_VALUES = [
      'cypherfixGithubToken', 'graphqlAuthValue', 'ownershipToken', 'phishingSmtpConfig',
    ]
    expect(CREDENTIAL_VALUES.filter(isReadableProjectField)).toEqual([])
  })

  test('a credential-shaped column is either withheld or explained', () => {
    // The pattern still runs, but as a prompt rather than a rule: anything it
    // catches must be named here with why reading it is harmless.
    const EXPLAINED: Record<string, string> = {
      jsluiceExtractSecrets:
        'a boolean feature toggle: whether jsluice REPORTS secret-shaped strings ' +
        'it finds in the target\'s JavaScript. It holds no secret of ours.',
      graphqlAuthHeader:
        'the header NAME an operator chose to carry the credential, not the ' +
        'credential; the value is withheld.',
      pathTraversalValidateSecretsEnabled:
        'a boolean feature toggle: whether the agent checks a secret it found in ' +
        'an exposed file with its provider. It holds no secret of ours.',
      urlscanSecretsInUrls:
        'a boolean feature toggle: whether URLScan reports the secrets written in ' +
        'URLs public urlscan visits recorded (stored masked). It holds no secret of ours.',
    }
    const leaky = columns.filter(
      c => /Token|ApiKey|Secret|Password|Credential/i.test(c) && isReadableProjectField(c)
    )
    const unexplained = leaky.filter(c => !(c in EXPLAINED))
    expect(unexplained, 'a credential-shaped column is readable with no reason given').toEqual([])
  })
})

describe('an agent can verify the engagement it is bound by', () => {
  // The direction the posture moved, asserted so nobody quietly moves it back.
  // A ceiling an agent cannot see is a ceiling it cannot check itself against.
  test.each([
    'roeEnabled',
    'roeGlobalMaxRps',
    'roeExcludedHosts',
    'roeForbiddenTools',
    'roeForbiddenCategories',
    'roeMaxSeverityPhase',
    'roeAllowDos',
    'roeAllowDataExfiltration',
    'roeTimeWindowEnabled',
    'roeEngagementStartDate',
    'roeEngagementEndDate',
  ])('%s is readable', field => {
    expect(isReadableProjectField(field)).toBe(true)
  })

  test('the scope it is pointed at is readable', () => {
    for (const field of ['targetDomain', 'targetIps', 'ipMode', 'domainBatchMode']) {
      expect(isReadableProjectField(field), field).toBe(true)
    }
  })

  test('most of the model is now readable, which is the point', () => {
    const readable = columns.filter(isReadableProjectField).length
    expect(readable).toBeGreaterThan(columns.length * 0.9)
    // But never all of it: the withheld set is not allowed to empty out.
    expect(readable).toBeLessThan(columns.length)
  })

  test('the withheld set is not allowed to shrink silently', () => {
    // A floor, so removing a name from the registry fails here rather than in
    // an incident. Raise it deliberately, never lower it by accident.
    expect(Object.keys(MCP_UNREADABLE_PROJECT_FIELDS).length).toBeGreaterThanOrEqual(14)
  })
})

describe('the registry is the single source for this', () => {
  test('the withheld set is exactly the registry query', () => {
    const fromRegistry = Object.entries(registry.fields)
      .filter(([, f]) => f.readable === false)
      .map(([k]) => k)
      .sort()
    expect(Object.keys(MCP_UNREADABLE_PROJECT_FIELDS).sort()).toEqual(fromRegistry)
  })

  test('there is no second hand-written table', async () => {
    // The old READ_ONLY_PROJECT_FIELDS map is gone; if it comes back, the two
    // will drift the way every pair of hand-aligned lists in this codebase has.
    const mod = (await import('./mcpReadableFields')) as Record<string, unknown>
    expect(mod.READ_ONLY_PROJECT_FIELDS).toBeUndefined()
  })
})

describe('the selects the read tools actually use stay inside the boundary', () => {
  test('the recon settings select is entirely readable', () => {
    expect(() => assertReadableSelect(reconSettingsSelect(), 'get_recon_settings')).not.toThrow()
  })

  test('the list_projects select is entirely readable', () => {
    const select = {
      id: true, name: true, targetDomain: true, targetIps: true,
      ipMode: true, domainBatchMode: true, updatedAt: true,
    }
    expect(() => assertReadableSelect(select, 'list_projects')).not.toThrow()
  })

  test('a select reaching past the boundary is refused, naming the field', () => {
    expect(() => assertReadableSelect({ id: true, roeRawText: true }, 'some_tool'))
      .toThrow(/roeRawText/)
    expect(() => assertReadableSelect({ roeClientContactPhone: true }, 'some_tool'))
      .toThrow(/roeClientContactPhone/)
  })
})
