/** Free TypeSafe key listing; never infer paid Jev capability or remaining credit. */
import { isPlainObject, str } from '../../parse'
import { errorResult, kindForStatus, shapeError, validResult } from '../../results'
import type { ErrorKind, ProbeContext, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'
import { LLM_PROBE, bearer } from './common'

const ORIGIN = 'https://api.typesafe.ai'

const DEFAULT_TEXT: Partial<Record<ErrorKind, string>> = {
  invalid_key: 'TypeSafe rejected the key',
  quota_exhausted: 'The TypeSafe account has no credit left',
}

export function modelsRequest(key: string): ProbeRequest {
  return { method: 'GET', url: `${ORIGIN}/v1/models`, headers: bearer(key) }
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
  const { code } = detail(res)
  return errorResult(kind, DEFAULT_TEXT[kind] || 'TypeSafe answered with an error', {
    httpStatus: res.status, providerCode: code,
  })
}

export function parseModels(res: ProbeResponse): ProbeResult | undefined {
  if (res.status < 200 || res.status >= 300) return failure(res)
  const b = res.json
  if (!isPlainObject(b) || !Array.isArray(b.models)) return shapeError(res)
  return undefined
}

async function run(ctx: ProbeContext): Promise<ProbeResult> {
  const listFailure = parseModels(await ctx.http(modelsRequest(ctx.key)))
  return listFailure ?? validResult({ notes: ['Key accepted for model listing only; Jev decision access and remaining credit are not checked'] })
}

export const jevProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-jev',
  service: 'jev',
  label: 'TypeSafe AI (Jev)',
  kind: 'validity',
  costNote: 'Free: lists models only; does not check Jev decision access or remaining credit',
  docsUrl: 'https://docs.typesafe.ai/api',
  dashboardUrl: 'https://console.typesafe.ai/keys',
  verifiedOn: '2026-10-01',
  endpoint: 'GET api.typesafe.ai/v1/models',
  run,
}
