/**
 * One password policy for the UI, the API and the host commands (HD-12, ID-20). The host
 * scripts cannot import TypeScript: the standalone image copies `scripts/` as plain .mjs
 * (webapp/Dockerfile), and redamon.sh and the single-host deploy.sh are bash. So the fixed
 * part (the floor, the byte bound, the deny list) lives in one JSON file both sides read,
 * the scripts apply it through scripts/lib/passwordRules.mjs, and the two shells keep their
 * own floor and byte-bound variables. This test fails the moment a copy drifts: a floor written twice, a
 * script that checks the password its own way, or the two implementations of the rules
 * answering differently.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'
import {
  MIN_PASSWORD_LENGTH, MAX_PASSWORD_BYTES, DENY_LIST, BASE_PASSWORD_POLICY,
  effectiveMinLength, validateNewPassword, type PasswordPolicy,
} from './passwordPolicy'
import {
  PASSWORD_POLICY_FILE, BASE_PASSWORD_POLICY as SCRIPT_BASE_POLICY,
  effectiveMinLength as scriptEffectiveMinLength, checkNewPassword,
} from '../../../scripts/lib/passwordRules.mjs'

const webappFile = (rel: string) => readFileSync(path.resolve(__dirname, '../../..', rel), 'utf8')
const repoFile = (rel: string) => readFileSync(path.resolve(__dirname, '../../../..', rel), 'utf8')
const policyJson = JSON.parse(webappFile('scripts/lib/password-policy.json'))

function onlyNumber(source: string, pattern: RegExp, where: string): number {
  const hits = [...source.matchAll(pattern)]
  expect(hits, `${where}: exactly one definition of ${pattern.source}`).toHaveLength(1)
  return Number(hits[0][1])
}

describe('the password floor has one value everywhere', () => {
  test('the JSON file holds the floor, the byte bound and the deny list the TypeScript policy uses', () => {
    expect(policyJson.floor).toBe(MIN_PASSWORD_LENGTH)
    expect(policyJson.maxBytes).toBe(MAX_PASSWORD_BYTES)
    expect(policyJson.denyList).toEqual([...DENY_LIST])
    expect(PASSWORD_POLICY_FILE).toEqual(policyJson)
    // passwordPolicy.ts writes no number of its own: it reads the file.
    const ts = webappFile('src/lib/authz/passwordPolicy.ts')
    expect(ts).toContain("scripts/lib/password-policy.json'")
    expect(ts).not.toMatch(/MIN_PASSWORD_LENGTH\s*=\s*\d/)
  })

  test.each(['scripts/create-admin.mjs', 'scripts/reset-password.mjs'])(
    '%s applies the shared rules and the instance minimum, and writes no floor of its own',
    (rel) => {
      const src = webappFile(rel)
      expect(src).toContain("from './lib/passwordRules.mjs'")
      expect(src).toMatch(/checkNewPassword\(password\)/)
      expect(src).toMatch(/passwordPolicyFromDatabase\(prisma, \{ identity: identitySwitchOn\(\) \}\)/)
      expect(src).not.toMatch(/MIN_PASSWORD_LENGTH\s*=\s*\d/)
      expect(src).not.toMatch(/\.length\s*<\s*\d/)
    },
  )

  test('scripts/lib/passwordRules.mjs reads the JSON file and writes no number of its own', () => {
    const src = webappFile('scripts/lib/passwordRules.mjs')
    expect(src).toContain("new URL('./password-policy.json', import.meta.url)")
    expect(src).not.toMatch(/(floor|minLength|maxBytes|MIN_PASSWORD_LENGTH)\s*[:=]\s*\d/)
  })

  test.each(['redamon.sh', 'tooling/deploy/single-host/deploy.sh'])(
    '%s MIN_ADMIN_PASSWORD_LEN and MAX_ADMIN_PASSWORD_BYTES',
    (rel) => {
      const src = repoFile(rel)
      expect(onlyNumber(src, /^MIN_ADMIN_PASSWORD_LEN=(\d+)$/gm, rel)).toBe(policyJson.floor)
      expect(onlyNumber(src, /^MAX_ADMIN_PASSWORD_BYTES=(\d+)$/gm, rel)).toBe(policyJson.maxBytes)
      // The checks compare against the variables, never a second literal.
      expect(src).toMatch(/-ge \$\{?MIN_ADMIN_PASSWORD_LEN\}?/)
      expect(src).toMatch(/-le \$\{?MAX_ADMIN_PASSWORD_BYTES\}?/)
    },
  )
})

describe('the scripts and the TypeScript policy agree', () => {
  const POLICIES: PasswordPolicy[] = [
    BASE_PASSWORD_POLICY,
    { minLength: 12, rules: true },
    { minLength: 16, rules: true },
    { minLength: 16, rules: false },
  ]
  const PASSWORDS = [
    '', 'a'.repeat(11), 'a'.repeat(12), 'abcdefghijk', 'quiet-orchid-77', 'quiet-orchid-771',
    'password1234', 'PASSWORD1234', 'Correct-orchid-paddle', 'x'.repeat(14), '🔑'.repeat(11), '🔑'.repeat(12),
    'é'.repeat(36), 'é'.repeat(37), 'a'.repeat(72), 'a'.repeat(73), 'rbac-member-long@e2e.local',
    'RBAC-MEMBER-LONG', 'rbac-member-long!', ...DENY_LIST.slice(0, 20),
  ]
  const EMAILS = [undefined, 'Rbac-Member-Long@e2e.local', 'nobody@e2e.local']

  test('the base policy is the same object on both sides', () => {
    expect(SCRIPT_BASE_POLICY).toEqual(BASE_PASSWORD_POLICY)
  })

  test.each([8, 11, 12, 16, 72, 90, null, undefined, '16', 12.5])('effectiveMinLength(%s)', (stored) => {
    expect(scriptEffectiveMinLength(stored)).toBe(effectiveMinLength(stored))
  })

  test('every password, policy and email gets the same answer, message included', () => {
    for (const policy of POLICIES) {
      for (const email of EMAILS) {
        for (const pw of PASSWORDS) {
          expect(checkNewPassword(pw, policy, { email }), `${JSON.stringify(policy)} ${email} ${pw}`)
            .toEqual(validateNewPassword(pw, policy, { email }))
        }
      }
    }
  })
})
