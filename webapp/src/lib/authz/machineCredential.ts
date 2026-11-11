/**
 * Machine credentials (T15): short-lived HMAC tokens bound to a tenant, a project and
 * a run or a job. The webapp mints the job credential (`aud: 'scan'`) a scan container
 * presents beside the scanner key, and verifies it on the routes a scan calls back.
 *
 * The format is the agent's (agentic/machine_credential.py) and the orchestrator's
 * (recon_orchestrator/job_credential.py), byte for byte: b64url(canonical JSON) "."
 * b64url(HMAC-SHA256), under the key hmac(INTERNAL_API_KEY, label). Canonical JSON is
 * Python's `json.dumps(sort_keys=True, separators=(",", ":"))`, ensure_ascii included,
 * over the known claims only; tests/fixtures/machine_credential/vectors.json holds all
 * three to the same tokens. A weak or default INTERNAL_API_KEY mints and verifies
 * nothing.
 *
 * Signed, not encrypted: whoever holds a token reads its claims. Its expiry bounds the
 * use of one copied out of a scan container.
 */
import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { now } from '@/lib/authz/clock'

export const RUN_CREDENTIAL_LABEL = 'redamon-run-credential-v1'
export const JOB_CREDENTIAL_LABEL = 'redamon-job-credential-v1'
/** The header a scan container sends its job credential in. */
export const JOB_CREDENTIAL_HEADER = 'x-redamon-job'
export const JOB_AUDIENCE = 'scan'
/** A scan can run for days (a large GVM sweep, a domain batch); the credential outlives it. */
export const JOB_CREDENTIAL_TTL_SECONDS = 7 * 24 * 60 * 60

const CLAIM_NAMES = ['aud', 'ten', 'pid', 'run', 'job', 'exp'] as const
const MAX_TOKEN_LENGTH = 4096
const B64URL = /^[A-Za-z0-9_-]+$/

export interface MachineClaims {
  aud: string
  ten: string
  pid: string
  run?: string
  job?: string
  exp: number
}

export type CredentialRefusalCode =
  | 'malformed' | 'bad_signature' | 'wrong_audience' | 'expired' | 'missing_claims' | 'weak_master_key'

/** A credential that must not be honoured; `code` says why (logged, sent to the caller). */
export class CredentialRefused extends Error {
  constructor(readonly code: CredentialRefusalCode) {
    super(code)
    this.name = 'CredentialRefused'
  }
}

export function deriveKey(master: string, label: string): Buffer {
  return createHmac('sha256', master).update(label, 'utf8').digest()
}

/** Python's ensure_ascii: every code unit outside printable ASCII becomes \uXXXX. */
function asciiOnly(json: string): string {
  return json.replace(/[\u007f-￿]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
}

function canonical(claims: Record<string, unknown>): string {
  const kept = CLAIM_NAMES
    .filter(k => claims[k] !== undefined && claims[k] !== null)
    .sort()
    .map(k => `${JSON.stringify(k)}:${JSON.stringify(claims[k])}`)
  return asciiOnly(`{${kept.join(',')}}`)
}

function sign(raw: string, key: Buffer): Buffer {
  return createHmac('sha256', key).update(raw, 'utf8').digest()
}

/** Sign `claims` (only the known ones are kept) with an already-derived key. */
export function mintMachineCredential(claims: MachineClaims, key: Buffer): string {
  if (!key.length) throw new Error('empty signing key')
  const raw = canonical(claims as unknown as Record<string, unknown>)
  return `${Buffer.from(raw, 'utf8').toString('base64url')}.${sign(raw, key).toString('base64url')}`
}

/** The claims of a valid, unexpired token for `aud`; throws CredentialRefused. */
export function verifyMachineCredential(token: unknown, key: Buffer, aud: string, nowSeconds: number): MachineClaims {
  if (!key.length) throw new CredentialRefused('weak_master_key')
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) throw new CredentialRefused('malformed')
  const parts = token.split('.')
  if (parts.length !== 2 || !B64URL.test(parts[0]) || !B64URL.test(parts[1])) {
    throw new CredentialRefused('malformed')
  }
  const rawBytes = Buffer.from(parts[0], 'base64url')
  const given = Buffer.from(parts[1], 'base64url')
  const raw = rawBytes.toString('utf8')
  if (!raw || !given.length || !Buffer.from(raw, 'utf8').equals(rawBytes)) throw new CredentialRefused('malformed')
  const expected = sign(raw, key)
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    throw new CredentialRefused('bad_signature')
  }
  let claims: unknown
  try {
    claims = JSON.parse(raw)
  } catch {
    throw new CredentialRefused('malformed')
  }
  // Re-canonicalising refuses a body carrying claims the signer would have dropped.
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)
    || canonical(claims as Record<string, unknown>) !== raw) {
    throw new CredentialRefused('malformed')
  }
  const c = claims as Record<string, unknown>
  if (c.aud !== aud) throw new CredentialRefused('wrong_audience')
  if (typeof c.exp !== 'number' || !Number.isInteger(c.exp)) throw new CredentialRefused('malformed')
  if (c.exp <= nowSeconds) throw new CredentialRefused('expired')
  for (const name of ['ten', 'pid'] as const) {
    if (typeof c[name] !== 'string' || !c[name]) throw new CredentialRefused('missing_claims')
  }
  return c as unknown as MachineClaims
}

/** True when INTERNAL_API_KEY is absent or still the compose default. */
export function masterKeyIsWeak(): boolean {
  const master = process.env.INTERNAL_API_KEY
  return !master || master === 'changeme'
}

function jobKey(): Buffer {
  if (masterKeyIsWeak()) throw new CredentialRefused('weak_master_key')
  return deriveKey(process.env.INTERNAL_API_KEY as string, JOB_CREDENTIAL_LABEL)
}

const nowSeconds = () => Math.floor(now().getTime() / 1000)

/** A job credential for one scan start of `projectId`, owned by `tenant`. */
export function mintJobCredential(opts: { tenant: string; projectId: string; ttlSeconds?: number }): string {
  const key = jobKey()
  if (!opts.tenant || !opts.projectId) throw new Error('a job credential needs its tenant and project')
  return mintMachineCredential({
    aud: JOB_AUDIENCE,
    ten: opts.tenant,
    pid: opts.projectId,
    job: randomUUID(),
    exp: nowSeconds() + (opts.ttlSeconds ?? JOB_CREDENTIAL_TTL_SECONDS),
  }, key)
}

export function verifyJobCredential(token: unknown): MachineClaims {
  const claims = verifyMachineCredential(token, jobKey(), JOB_AUDIENCE, nowSeconds())
  if (typeof claims.job !== 'string' || !claims.job || 'run' in claims) throw new CredentialRefused('missing_claims')
  return claims
}
