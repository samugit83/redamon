/**
 * The navigator credential (plan §7.6): CREDENTIAL_BYTES random bytes, b64url, generated when a run
 * completes its reservation (runRegistry.complete) and resolved here when the agent calls a tool
 * back with it in the `X-Redamon-Navigator` header.
 *
 * It carries no claims: the run entry holds the person, actor, project, tenant and login, so every
 * id a tool call acts on comes from the registry, never from the request. It is not a signed
 * machine credential on purpose: the registry is the authority anyway (a signed token would still
 * be checked against a live run), and that format is shared byte for byte with the agent and the
 * orchestrator (tests/fixtures/machine_credential/vectors.json), which this must not change.
 *
 * It lives as long as its run: it stops resolving the moment the run ends, is aborted or expires.
 * A missing, malformed, unknown, ended or expired token answers the same refusal, logged with a code
 * and never with the token.
 */
import { timingSafeEqual } from 'node:crypto'
import { CREDENTIAL_BYTES, NAVIGATOR_CREDENTIAL_HEADER } from './constants'
import { hashCredential } from './credentialHash'
import { navigatorRuns, type NavigatorRun } from './runRegistry'

/** b64url of CREDENTIAL_BYTES bytes, no padding. */
const TOKEN_RE = new RegExp(`^[A-Za-z0-9_-]{${Math.ceil((CREDENTIAL_BYTES * 4) / 3)}}$`)

export type CredentialRefusal = 'missing' | 'malformed' | 'unknown'

export type ResolvedCredential = { run: NavigatorRun } | { refused: CredentialRefusal }

export function resolveCredentialValue(value: string | null | undefined): ResolvedCredential {
  if (!value) return refuse('missing')
  if (!TOKEN_RE.test(value)) return refuse('malformed')
  const hash = hashCredential(value)
  const run = navigatorRuns().byCredentialHash(hash)
  if (!run || !run.credentialHash) return refuse('unknown')
  const a = Buffer.from(hash, 'hex')
  const b = Buffer.from(run.credentialHash, 'hex')
  if (a.length !== b.length || !timingSafeEqual(a, b)) return refuse('unknown')
  return { run }
}

export function resolveCredential(request: Request): ResolvedCredential {
  return resolveCredentialValue(request.headers.get(NAVIGATOR_CREDENTIAL_HEADER))
}

function refuse(code: CredentialRefusal): ResolvedCredential {
  console.warn(`[navigator] credential refused code=${code}`)
  return { refused: code }
}
