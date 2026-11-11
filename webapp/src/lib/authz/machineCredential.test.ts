/**
 * The webapp's half of the machine credentials (T15, step 1.16): it mints the job
 * credential a scan container presents with the scanner key, and verifies it on the
 * scanner routes. The tokens must be byte-identical to the agent's
 * (agentic/machine_credential.py) and the orchestrator's verifier, so the shared
 * vectors pin every byte: the Python tests verify the same tokens this file mints.
 *
 * @vitest-environment node
 */
import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'vitest'
import { setNowForTests } from '@/lib/authz/clock'
import {
  CredentialRefused,
  JOB_CREDENTIAL_LABEL,
  JOB_CREDENTIAL_TTL_SECONDS,
  RUN_CREDENTIAL_LABEL,
  deriveKey,
  masterKeyIsWeak,
  mintJobCredential,
  mintMachineCredential,
  verifyJobCredential,
  verifyMachineCredential,
  type MachineClaims,
} from './machineCredential'

interface Vector { name: string; label: 'job' | 'run'; claims: MachineClaims; token: string }
const VECTORS = JSON.parse(readFileSync(
  path.resolve(__dirname, '../../../../tests/fixtures/machine_credential/vectors.json'), 'utf8',
)) as { master: string; job_key_hex: string; run_key_hex: string; vectors: Vector[] }

const labelOf = (v: Vector) => (v.label === 'job' ? JOB_CREDENTIAL_LABEL : RUN_CREDENTIAL_LABEL)
const keyOf = (v: Vector) => deriveKey(VECTORS.master, labelOf(v))
const NOW = 1_800_000_000
const MASTER = 'machine-credential-test-master-key'

function refusal(fn: () => unknown): string {
  try {
    fn()
  } catch (err) {
    if (err instanceof CredentialRefused) return err.code
    throw err
  }
  throw new Error('expected a CredentialRefused')
}

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64url')

describe('format shared with the Python verifiers', () => {
  test('the derived keys are hmac(INTERNAL_API_KEY, label)', () => {
    expect(deriveKey(VECTORS.master, JOB_CREDENTIAL_LABEL).toString('hex')).toBe(VECTORS.job_key_hex)
    expect(deriveKey(VECTORS.master, RUN_CREDENTIAL_LABEL).toString('hex')).toBe(VECTORS.run_key_hex)
  })

  test.each(VECTORS.vectors.map(v => [v.name, v] as const))(
    'TypeScript mints the Python token byte for byte: %s', (_name, v) => {
      expect(mintMachineCredential(v.claims, keyOf(v))).toBe(v.token)
    },
  )

  test.each(VECTORS.vectors.map(v => [v.name, v] as const))(
    'a Python token verifies here: %s', (_name, v) => {
      expect(verifyMachineCredential(v.token, keyOf(v), v.claims.aud, NOW)).toEqual(v.claims)
    },
  )

  test('only the known claims are signed, in sorted order', () => {
    const key = deriveKey(MASTER, JOB_CREDENTIAL_LABEL)
    const token = mintMachineCredential(
      { pid: 'p', aud: 'scan', exp: NOW + 60, ten: 't', job: 'j', extra: 'dropped' } as unknown as MachineClaims,
      key,
    )
    const body = Buffer.from(token.split('.')[0], 'base64url').toString('utf8')
    expect(body).toBe('{"aud":"scan","exp":1800000060,"job":"j","pid":"p","ten":"t"}')
  })
})

describe('verify refuses', () => {
  const key = deriveKey(MASTER, JOB_CREDENTIAL_LABEL)
  const claims: MachineClaims = { aud: 'scan', ten: 'u1', pid: 'p1', job: 'j1', exp: NOW + 60 }
  const good = () => mintMachineCredential(claims, key)

  test('an expired token', () => {
    expect(refusal(() => verifyMachineCredential(good(), key, 'scan', NOW + 60))).toBe('expired')
    expect(verifyMachineCredential(good(), key, 'scan', NOW + 59).ten).toBe('u1')
  })

  test('another audience', () => {
    expect(refusal(() => verifyMachineCredential(good(), key, 'graph', NOW))).toBe('wrong_audience')
  })

  test('a token signed under another master key or label', () => {
    expect(refusal(() => verifyMachineCredential(good(), deriveKey('other-master', JOB_CREDENTIAL_LABEL), 'scan', NOW)))
      .toBe('bad_signature')
    expect(refusal(() => verifyMachineCredential(good(), deriveKey(MASTER, RUN_CREDENTIAL_LABEL), 'scan', NOW)))
      .toBe('bad_signature')
  })

  test('a tampered body or signature', () => {
    const [body, sig] = good().split('.')
    const forged = b64(Buffer.from(body, 'base64url').toString('utf8').replace('"u1"', '"u2"'))
    expect(refusal(() => verifyMachineCredential(`${forged}.${sig}`, key, 'scan', NOW))).toBe('bad_signature')
    const flipped = sig.slice(0, -1) + (sig.endsWith('A') ? 'B' : 'A')
    expect(refusal(() => verifyMachineCredential(`${body}.${flipped}`, key, 'scan', NOW))).toBe('bad_signature')
  })

  test('malformed shapes', () => {
    for (const bad of ['', 'nodot', 'a.b.c', '.', `${good()}x!`, 'x'.repeat(5000) + '.y', '@@@.###']) {
      expect(refusal(() => verifyMachineCredential(bad, key, 'scan', NOW))).toMatch(/^(malformed|bad_signature)$/)
    }
    expect(refusal(() => verifyMachineCredential(undefined as unknown as string, key, 'scan', NOW))).toBe('malformed')
  })

  test('signed claims the signer would have dropped, or a non-integer expiry', () => {
    const sign = (raw: string) => `${b64(raw)}.${createHmac('sha256', key).update(raw, 'utf8').digest('base64url')}`
    const extra = sign('{"aud":"scan","exp":1800000060,"job":"j","pid":"p","role":"admin","ten":"t"}')
    expect(refusal(() => verifyMachineCredential(extra, key, 'scan', NOW))).toBe('malformed')
    const floatExp = sign('{"aud":"scan","exp":1800000060.0,"job":"j","pid":"p","ten":"t"}')
    expect(refusal(() => verifyMachineCredential(floatExp, key, 'scan', NOW))).toBe('malformed')
    const stringExp = sign('{"aud":"scan","exp":"1800000060","job":"j","pid":"p","ten":"t"}')
    expect(refusal(() => verifyMachineCredential(stringExp, key, 'scan', NOW))).toBe('malformed')
    const unsorted = sign('{"exp":1800000060,"aud":"scan","job":"j","pid":"p","ten":"t"}')
    expect(refusal(() => verifyMachineCredential(unsorted, key, 'scan', NOW))).toBe('malformed')
  })

  test('a token without its tenant or project', () => {
    const noTenant = mintMachineCredential({ aud: 'scan', ten: '', pid: 'p1', job: 'j', exp: NOW + 60 }, key)
    expect(refusal(() => verifyMachineCredential(noTenant, key, 'scan', NOW))).toBe('missing_claims')
  })

  test('an empty key', () => {
    expect(refusal(() => verifyMachineCredential(good(), Buffer.alloc(0), 'scan', NOW))).toBe('weak_master_key')
    expect(() => mintMachineCredential(claims, Buffer.alloc(0))).toThrow()
  })
})

describe('job credentials', () => {
  const saved = process.env.INTERNAL_API_KEY
  beforeEach(() => {
    process.env.INTERNAL_API_KEY = MASTER
    setNowForTests(() => new Date(NOW * 1000))
  })
  afterEach(() => {
    if (saved === undefined) delete process.env.INTERNAL_API_KEY
    else process.env.INTERNAL_API_KEY = saved
    setNowForTests(null)
  })

  test('a job credential names the scan audience, the tenant, the project and a job, for 7 days', () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    const claims = verifyJobCredential(token)
    expect(claims).toMatchObject({ aud: 'scan', ten: 'owner-1', pid: 'proj-1', exp: NOW + JOB_CREDENTIAL_TTL_SECONDS })
    expect(JOB_CREDENTIAL_TTL_SECONDS).toBe(7 * 24 * 60 * 60)
    expect(claims.job).toMatch(/^[0-9a-f-]{36}$/)
    expect(claims.run).toBeUndefined()
    expect(verifyJobCredential(mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })).job).not.toBe(claims.job)
  })

  test('it expires after its lifetime, on the injected clock', () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    setNowForTests(() => new Date((NOW + JOB_CREDENTIAL_TTL_SECONDS) * 1000))
    expect(refusal(() => verifyJobCredential(token))).toBe('expired')
  })

  test('a run credential is not a job credential, and the other way round', () => {
    const run = mintMachineCredential(
      { aud: 'scan', ten: 'u', pid: 'p', run: 'r', exp: NOW + 60 }, deriveKey(MASTER, RUN_CREDENTIAL_LABEL),
    )
    expect(refusal(() => verifyJobCredential(run))).toBe('bad_signature')
    const runShaped = mintMachineCredential(
      { aud: 'scan', ten: 'u', pid: 'p', run: 'r', exp: NOW + 60 }, deriveKey(MASTER, JOB_CREDENTIAL_LABEL),
    )
    expect(refusal(() => verifyJobCredential(runShaped))).toBe('missing_claims')
    const both = mintMachineCredential(
      { aud: 'scan', ten: 'u', pid: 'p', run: 'r', job: 'j', exp: NOW + 60 }, deriveKey(MASTER, JOB_CREDENTIAL_LABEL),
    )
    expect(refusal(() => verifyJobCredential(both))).toBe('missing_claims')
  })

  test('a weak or default master key refuses to mint and to verify', () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    for (const weak of ['', 'changeme', undefined]) {
      if (weak === undefined) delete process.env.INTERNAL_API_KEY
      else process.env.INTERNAL_API_KEY = weak
      expect(masterKeyIsWeak()).toBe(true)
      expect(refusal(() => mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' }))).toBe('weak_master_key')
      expect(refusal(() => verifyJobCredential(token))).toBe('weak_master_key')
    }
  })

  test('a credential with no tenant or project is never minted', () => {
    expect(() => mintJobCredential({ tenant: '', projectId: 'proj-1' })).toThrow()
    expect(() => mintJobCredential({ tenant: 'owner-1', projectId: '' })).toThrow()
  })
})
