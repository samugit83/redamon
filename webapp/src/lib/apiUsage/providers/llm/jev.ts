/**
 * TypeSafe AI (Jev). TypeSafe has no balance endpoint: credit only shows as a
 * 402 on a billed call. So the probe first lists models (free; proves the key),
 * then asks one Noul question (about 300 input tokens, $0.042 per million) to
 * prove the account can still pay. A 402 from either call is "quota used up".
 *
 * Error bodies are `{"detail": {"error_type", "message"}}`, which the shared
 * `messageOf` does not read.
 */
import { isPlainObject, str } from '../../parse'
import { errorResult, kindForStatus, shapeError, validResult } from '../../results'
import type { ErrorKind, ProbeContext, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'
import { JEV_MODEL } from '@/lib/llmProviderKinds'
import { LLM_PROBE, bearer } from './common'

const ORIGIN = 'https://api.typesafe.ai'

const DEFAULT_TEXT: Partial<Record<ErrorKind, string>> = {
  invalid_key: 'TypeSafe rejected the key',
  quota_exhausted: 'The TypeSafe account has no credit left',
}

export function modelsRequest(key: string): ProbeRequest {
  return { method: 'GET', url: `${ORIGIN}/v1/models`, headers: bearer(key) }
}

export function pingRequest(key: string): ProbeRequest {
  return {
    method: 'POST',
    url: `${ORIGIN}/v1/systemone`,
    headers: { ...bearer(key), 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: JEV_MODEL,
      state: 'ping',
      questions: { ping: { type: 'noul', instructions: 'Is this a ping?' } },
    }),
  }
}

function detail(res: ProbeResponse): { code?: string; message?: string } {
  const b = res.json
  const d = isPlainObject(b) && isPlainObject(b.detail) ? b.detail : {}
  return { code: str(d.error_type), message: str(d.message) }
}

function failure(res: ProbeResponse): ProbeResult {
  // 403 is TypeSafe's answer to a missing Authorization header: a key problem.
  const kind: ErrorKind = res.status === 402 ? 'quota_exhausted'
    : res.status === 401 || res.status === 403 ? 'invalid_key'
    : kindForStatus(res.status)
  const { code, message } = detail(res)
  return errorResult(kind, message || DEFAULT_TEXT[kind] || 'TypeSafe answered with an error', {
    httpStatus: res.status, providerCode: code,
  })
}

export function parseModels(res: ProbeResponse): ProbeResult | undefined {
  if (res.status < 200 || res.status >= 300) return failure(res)
  const b = res.json
  if (!isPlainObject(b) || !Array.isArray(b.models)) return shapeError(res)
  return undefined
}

export function parsePing(res: ProbeResponse): ProbeResult {
  if (res.status < 200 || res.status >= 300) return failure(res)
  const b = res.json
  const answer = isPlainObject(b) && isPlainObject(b.answers) ? b.answers.ping : undefined
  if (!isPlainObject(answer) || typeof answer.noul !== 'number') return shapeError(res)
  return validResult({ notes: ['The account answered a billed call, so it has credit'] })
}

async function run(ctx: ProbeContext): Promise<ProbeResult> {
  const listFailure = parseModels(await ctx.http(modelsRequest(ctx.key)))
  if (listFailure) return listFailure
  return parsePing(await ctx.http(pingRequest(ctx.key)))
}

export const jevProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-jev',
  service: 'jev',
  label: 'TypeSafe AI (Jev)',
  kind: 'validity',
  costNote: 'Spends about 300 input tokens (about $0.00001) per check: TypeSafe has no free balance endpoint, so only a billed call shows an empty account',
  docsUrl: 'https://docs.typesafe.ai/api',
  dashboardUrl: 'https://console.typesafe.ai/keys',
  verifiedOn: '2026-10-01',
  endpoint: 'GET api.typesafe.ai/v1/models, then POST /v1/systemone',
  run,
}
