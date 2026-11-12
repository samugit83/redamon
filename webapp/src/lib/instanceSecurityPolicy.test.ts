/**
 * The instance security policy fields (step 2.6, ID-03 powers, ID-25): what a PUT of
 * /api/admin/instance-settings may set and how each value is checked. The password minimum
 * never goes below 12 (HD-12), lifetimes are whole numbers inside sane bounds (the defaults are
 * PLACEHOLDER(OQ-38)), and the public base URL is an http(s) address with no credentials,
 * query or fragment, stored without a trailing slash. Only the fields a body names are read.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/instanceSecurityPolicy.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'
import {
  SECURITY_POLICY_FIELDS, changedSecurityPolicyFields, parseSecurityPolicyPatch, securityPolicyView,
} from './instanceSecurityPolicy'

const STORED = {
  passwordMinLength: 12, passwordAskChangeIfShort: false, memberSessionTtlHours: 168, adminSessionTtlHours: 12,
  adminIdleMinutes: 60, inviteTtlHours: 168, resetTtlHours: 4, publicBaseUrl: null,
  impersonationMaxMinutes: 720, impersonationReasonRequired: false, impersonationNotifyTarget: true,
}

describe('the fields', () => {
  test('password policy, session and link lifetimes, impersonation settings and the public base URL', () => {
    expect([...SECURITY_POLICY_FIELDS].sort()).toEqual(Object.keys(STORED).sort())
  })

  test('each is a column of InstanceSettings in the schema', () => {
    const schema = readFileSync(path.resolve(__dirname, '../../prisma/schema.prisma'), 'utf8')
    const model = schema.slice(schema.indexOf('model InstanceSettings'))
    const body = model.slice(0, model.indexOf('\n}'))
    for (const f of SECURITY_POLICY_FIELDS) expect(body).toMatch(new RegExp(`\\n\\s+${f}\\s`))
  })

  test('the view lists every field as stored', () => {
    expect(securityPolicyView({ ...STORED, tunnelsEnabled: true })).toEqual(STORED)
  })
})

describe('parsing a body', () => {
  test('only the fields the body names; nothing named, nothing read', () => {
    expect(parseSecurityPolicyPatch({ tunnelsEnabled: true })).toEqual({ patch: {} })
    expect(parseSecurityPolicyPatch({ passwordMinLength: 14, adminIdleMinutes: 30 }))
      .toEqual({ patch: { passwordMinLength: 14, adminIdleMinutes: 30 } })
  })

  test.each([
    ['passwordMinLength', 11], ['passwordMinLength', 73], ['passwordMinLength', 12.5], ['passwordMinLength', '14'],
    ['memberSessionTtlHours', 0], ['memberSessionTtlHours', 8761], ['adminSessionTtlHours', 169],
    ['adminIdleMinutes', 4], ['adminIdleMinutes', 1441], ['inviteTtlHours', 721], ['resetTtlHours', 0],
    ['impersonationMaxMinutes', 1441], ['impersonationMaxMinutes', 1440], ['impersonationMaxMinutes', 721],
    ['impersonationMaxMinutes', 4], ['passwordAskChangeIfShort', 'yes'], ['impersonationNotifyTarget', 1],
    ['impersonationReasonRequired', null],
  ])('%s = %j is refused, naming the field', (field, value) => {
    const out = parseSecurityPolicyPatch({ [field]: value })
    expect(out).toMatchObject({ error: { field } })
  })

  test('the password minimum never goes below 12', () => {
    expect(parseSecurityPolicyPatch({ passwordMinLength: 12 })).toEqual({ patch: { passwordMinLength: 12 } })
    expect(parseSecurityPolicyPatch({ passwordMinLength: 11 })).toMatchObject({ error: { field: 'passwordMinLength', message: expect.stringMatching(/12/) } })
  })

  test('the impersonation limit stops at 720 minutes (§12 OQ-32, today\'s 12 h reach); Root may lower it', () => {
    for (const v of [720, 60, 5]) {
      expect(parseSecurityPolicyPatch({ impersonationMaxMinutes: v })).toEqual({ patch: { impersonationMaxMinutes: v } })
    }
    for (const v of [721, 1440]) {
      expect(parseSecurityPolicyPatch({ impersonationMaxMinutes: v }))
        .toEqual({ error: { field: 'impersonationMaxMinutes', message: 'impersonationMaxMinutes must be a whole number from 5 to 720' } })
    }
  })

  test.each([
    ['https://redamon.example.test', 'https://redamon.example.test'],
    ['https://redamon.example.test/', 'https://redamon.example.test'],
    ['  http://10.0.0.5:3000//  ', 'http://10.0.0.5:3000'],
    ['https://example.test/redamon/', 'https://example.test/redamon'],
    ['', null],
    [null, null],
  ])('publicBaseUrl %j is stored as %j', (value, stored) => {
    expect(parseSecurityPolicyPatch({ publicBaseUrl: value })).toEqual({ patch: { publicBaseUrl: stored } })
  })

  test.each([
    'ftp://example.test', 'javascript:alert(1)', 'https://user:pw@example.test', 'https://example.test/?next=x',
    'https://example.test/#x', 'not a url', 42, `https://example.test/${'a'.repeat(2050)}`,
  ])('publicBaseUrl %j is refused', (value) => {
    expect(parseSecurityPolicyPatch({ publicBaseUrl: value })).toMatchObject({ error: { field: 'publicBaseUrl' } })
  })
})

describe('what changed', () => {
  test('only the values that differ from the stored ones', () => {
    expect(changedSecurityPolicyFields(STORED, { passwordMinLength: 12, adminIdleMinutes: 30, publicBaseUrl: null }))
      .toEqual(['adminIdleMinutes'])
    expect(changedSecurityPolicyFields({ ...STORED, publicBaseUrl: 'https://a.test' }, { publicBaseUrl: 'https://a.test' })).toEqual([])
    expect(changedSecurityPolicyFields(STORED, { impersonationNotifyTarget: false })).toEqual(['impersonationNotifyTarget'])
  })
})
