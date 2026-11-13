import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import type { Session } from '@/lib/session'
import { BUILTIN_SETS, builtinSet } from '@/lib/authz/builtinSets'
import { lockPermissions, personAuditEntry } from '@/lib/authz/permissionAdmin'
import { isMaskedSecret, llmProviderSecretReentry, secretReentryResponse } from '@/lib/authz/secretEndpointRebind'
import { assertSafeLlmBaseUrl, BaseUrlValidationError } from '@/lib/llm-url-guard'
import { NON_CHAT_PROVIDER_TYPES } from '@/lib/llmProviderKinds'
import { maskProvider, restoreMaskedHeaders } from '@/lib/llmProviderMask'
import { isReasoningEffort } from '@/lib/llmReasoning'
import { INSTANCE_PROVIDER_KINDS, isInstanceProviderKind, type InstanceLlmProviderRecord } from './rows'
import {
  createInstanceProvider, deleteInstanceProvider, readByoLlmForbidden, readInstanceProvider, readInstanceProviders,
  readProviderAssignments, updateInstanceProvider, writeByoLlmForbidden, type InstanceProviderData,
} from './store'

/**
 * Managing instance LLM providers (step 6.11, GV-15): the confirmed Root adds, changes and deletes
 * them, assigns each to permission sets and sets `byoLlmForbidden`. The routes check the switch, the
 * session, Root (with its password for a write) and the origin first; this module validates and
 * writes.
 *
 * A provider's secrets (`apiKey`, the three AWS fields, every Extra Headers value) never leave the
 * webapp to a browser: the console reads them masked, a masked value sent back keeps the stored one,
 * and a new endpoint or kind needs them typed again (HD-24, secretEndpointRebind.ts). They are never
 * logged and never in an audit row: `before` / `after` carry the name, the kind, the model, the sets
 * and whether a secret or the endpoint changed, never a value of either.
 *
 * Each write commits with its audit row (fail closed) under the permissions lock, the one deleteSet
 * takes, so an assignment cannot name a set being deleted. An assignment names a member set or an
 * admin profile, built-in or stored.
 */
export const MAX_PROVIDER_SETS = 50
const MAX_NAME = 100
const MAX_SET_ID = 128
const SECRET_FIELDS = ['apiKey', 'awsAccessKeyId', 'awsSecretKey', 'awsBearerToken'] as const

const refuse = (status: number, code: string, error: string, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ error, code, ...extra }, { status, headers: { 'Cache-Control': 'no-store' } })
const ok = (body: unknown, status = 200) => NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } })

export interface SelectableSet {
  id: string
  name: string
  kind: 'member' | 'admin'
  builtin: boolean
}

export interface AdminView {
  providers: Array<Record<string, unknown> & { setIds: string[] }>
  sets: SelectableSet[]
  byoLlmForbidden: boolean
  kinds: readonly string[]
}

function masked(p: InstanceLlmProviderRecord, setIds: string[]): Record<string, unknown> & { setIds: string[] } {
  return { ...maskProvider(p as unknown as Record<string, unknown>), setIds }
}

/** GET: every provider masked with its sets, the sets an assignment may name, and the policy. */
export async function adminView(): Promise<AdminView> {
  const [providers, assignments, byoLlmForbidden, stored] = await Promise.all([
    readInstanceProviders(),
    readProviderAssignments(),
    readByoLlmForbidden(),
    prisma.permissionSet.findMany({ select: { id: true, name: true, kind: true } }),
  ])
  const setsOf = (id: string) => assignments.filter((a) => a.providerId === id).map((a) => a.setId).sort()
  return {
    providers: providers.map((p) => masked(p, setsOf(p.id))),
    sets: [
      ...BUILTIN_SETS.map((s) => ({ id: s.id, name: s.name, kind: s.kind, builtin: true })),
      ...stored
        .filter((r): r is typeof r & { kind: 'member' | 'admin' } => r.kind === 'member' || r.kind === 'admin')
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((r) => ({ id: r.id, name: r.name, kind: r.kind, builtin: false })),
    ],
    byoLlmForbidden,
    kinds: INSTANCE_PROVIDER_KINDS,
  }
}

function parseSetIds(value: unknown): string[] | NextResponse {
  if (value === undefined) return []
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string' || v.length === 0 || v.length > MAX_SET_ID)) {
    return refuse(400, 'invalid_set_ids', 'setIds must be a list of permission set ids.')
  }
  const ids = [...new Set(value as string[])].sort()
  if (ids.length > MAX_PROVIDER_SETS) return refuse(400, 'invalid_set_ids', `A provider can be assigned to at most ${MAX_PROVIDER_SETS} sets.`)
  return ids
}

const str = (v: unknown, fallback: string): string => (typeof v === 'string' ? v : fallback)

/**
 * The stored data a create (no `existing`) or an update would write, or the 400. A masked secret or
 * header value keeps the stored one; the Jev kinds and any kind the agent cannot build are refused.
 */
async function parseProvider(body: Record<string, unknown>, existing: InstanceLlmProviderRecord | null): Promise<InstanceProviderData | NextResponse> {
  const providerType = body.providerType === undefined && existing ? existing.providerType : body.providerType
  if (typeof providerType === 'string' && NON_CHAT_PROVIDER_TYPES.has(providerType)) {
    return refuse(400, 'non_chat_provider', 'An instance provider must be a chat model provider; a Jev provider cannot be one.')
  }
  if (!isInstanceProviderKind(providerType)) {
    return refuse(400, 'invalid_provider_type', `providerType must be one of: ${INSTANCE_PROVIDER_KINDS.join(', ')}.`)
  }
  const name = body.name === undefined && existing ? existing.name : body.name
  if (typeof name !== 'string' || !name.trim() || name.trim().length > MAX_NAME) {
    return refuse(400, 'invalid_name', `name is required (at most ${MAX_NAME} characters).`)
  }
  for (const f of ['baseUrl', 'modelIdentifier', 'awsRegion', 'reasoningEffort', ...SECRET_FIELDS] as const) {
    if (body[f] !== undefined && typeof body[f] !== 'string') return refuse(400, 'invalid_field', `${f} must be a string.`)
  }
  for (const f of ['timeout', 'maxTokens'] as const) {
    if (body[f] !== undefined && !(Number.isInteger(body[f]) && (body[f] as number) > 0)) return refuse(400, 'invalid_field', `${f} must be a positive whole number.`)
  }
  if (body.temperature !== undefined && !(typeof body.temperature === 'number' && body.temperature >= 0 && body.temperature <= 2)) {
    return refuse(400, 'invalid_field', 'temperature must be a number from 0 to 2.')
  }
  for (const f of ['sslVerify', 'reasoningEnabled'] as const) {
    if (body[f] !== undefined && typeof body[f] !== 'boolean') return refuse(400, 'invalid_field', `${f} must be a boolean.`)
  }
  if (body.reasoningEffort !== undefined && !isReasoningEffort(body.reasoningEffort)) {
    return refuse(400, 'invalid_field', 'reasoningEffort must be one of: low, medium, high, max.')
  }
  if (body.defaultHeaders !== undefined && (body.defaultHeaders === null || typeof body.defaultHeaders !== 'object' || Array.isArray(body.defaultHeaders)
    || Object.values(body.defaultHeaders as Record<string, unknown>).some((v) => typeof v !== 'string'))) {
    return refuse(400, 'invalid_field', 'defaultHeaders must be a map of header names to text values.')
  }

  const secret = (f: typeof SECRET_FIELDS[number]): string => {
    const sent = body[f]
    if (sent === undefined || isMaskedSecret(sent)) return existing ? existing[f] : ''
    return (sent as string).trim()
  }
  const compatible = providerType === 'openai_compatible'
  const data: InstanceProviderData = {
    providerType,
    name: name.trim(),
    apiKey: secret('apiKey'),
    baseUrl: compatible ? str(body.baseUrl, existing?.baseUrl ?? '').trim() : '',
    modelIdentifier: compatible ? str(body.modelIdentifier, existing?.modelIdentifier ?? '').trim() : '',
    defaultHeaders: body.defaultHeaders === undefined
      ? (existing?.defaultHeaders ?? {})
      : restoreMaskedHeaders(body.defaultHeaders, existing?.defaultHeaders ?? {}),
    timeout: (body.timeout as number | undefined) ?? existing?.timeout ?? 120,
    temperature: (body.temperature as number | undefined) ?? existing?.temperature ?? 0,
    maxTokens: (body.maxTokens as number | undefined) ?? existing?.maxTokens ?? 16384,
    sslVerify: (body.sslVerify as boolean | undefined) ?? existing?.sslVerify ?? true,
    reasoningEnabled: compatible ? ((body.reasoningEnabled as boolean | undefined) ?? existing?.reasoningEnabled ?? false) : false,
    reasoningEffort: compatible ? ((body.reasoningEffort as string | undefined) ?? existing?.reasoningEffort ?? 'high') : 'high',
    awsRegion: providerType === 'bedrock' ? str(body.awsRegion, existing?.awsRegion ?? 'us-east-1').trim() || 'us-east-1' : 'us-east-1',
    awsAccessKeyId: providerType === 'bedrock' ? secret('awsAccessKeyId') : '',
    awsSecretKey: providerType === 'bedrock' ? secret('awsSecretKey') : '',
    awsBearerToken: providerType === 'bedrock' ? secret('awsBearerToken') : '',
  }
  if (compatible && (!data.baseUrl || !data.modelIdentifier)) {
    return refuse(400, 'invalid_field', 'baseUrl and modelIdentifier are required for an OpenAI-compatible provider.')
  }
  if (providerType === 'bedrock' ? !(data.awsBearerToken || (data.awsAccessKeyId && data.awsSecretKey)) : !compatible && !data.apiKey) {
    return refuse(400, 'key_required', providerType === 'bedrock'
      ? 'A Bedrock provider needs a long-term API key, or an access key id with its secret.'
      : 'An API key is required.')
  }
  if (compatible) {
    try {
      await assertSafeLlmBaseUrl(data.baseUrl, { sslVerify: data.sslVerify })
    } catch (err) {
      if (err instanceof BaseUrlValidationError) return refuse(400, 'invalid_base_url', err.message)
      throw err
    }
  }
  return data
}

/** What an audit row says of a provider: never a secret, never the endpoint (it can hold credentials). */
function auditFacts(p: Pick<InstanceProviderData, 'name' | 'providerType' | 'modelIdentifier'>, setIds: readonly string[]) {
  return { name: p.name, providerType: p.providerType, modelIdentifier: p.modelIdentifier, setIds: [...setIds] }
}

const secretsChanged = (a: InstanceProviderData, b: InstanceProviderData): boolean =>
  SECRET_FIELDS.some((f) => a[f] !== b[f]) || JSON.stringify(a.defaultHeaders ?? {}) !== JSON.stringify(b.defaultHeaders ?? {})

type SetCheck = { unknown: string[] }

async function unknownSets(tx: Parameters<typeof lockPermissions>[0], ids: readonly string[]): Promise<SetCheck> {
  const stored = ids.filter((id) => !id.startsWith('builtin:'))
  const found = stored.length === 0 ? [] : (await tx.permissionSet.findMany({ where: { id: { in: stored } }, select: { id: true } })).map((r) => r.id)
  return { unknown: ids.filter((id) => (id.startsWith('builtin:') ? !builtinSet(id) : !found.includes(id))) }
}

const unknownSetRefusal = (setIds: string[]) =>
  refuse(400, 'unknown_set', 'A provider can be assigned only to permission sets that exist.', { setIds })

/** POST: a new provider and its sets. */
export async function createProvider(request: NextRequest, session: Session, body: Record<string, unknown>): Promise<NextResponse> {
  const setIds = parseSetIds(body.setIds)
  if (setIds instanceof NextResponse) return setIds
  const data = await parseProvider(body, null)
  if (data instanceof NextResponse) return data
  const outcome = await auditedTransaction(prisma, async (tx) => {
    await lockPermissions(tx)
    const check = await unknownSets(tx, setIds)
    if (check.unknown.length > 0) return check
    const provider = await createInstanceProvider(tx, { data, setIds, actorId: session.userId })
    await writeAuditTx(tx, await personAuditEntry(request, session, {
      action: 'instance.llm_provider_created', targetType: 'instance_llm_provider', targetId: provider.id,
      permission: 'instance:settings', after: auditFacts(data, setIds),
    }))
    return provider
  })
  if ('unknown' in outcome) return unknownSetRefusal(outcome.unknown)
  console.log(`[rbac] instance llm provider created id=${outcome.id} by=${session.userId} sets=${setIds.length}`)
  return ok(masked(outcome, setIds), 201)
}

/** PUT: the provider's settings and its sets (exactly `setIds` when sent, else unchanged). */
export async function updateProvider(request: NextRequest, session: Session, id: string, body: Record<string, unknown>): Promise<NextResponse> {
  const existing = await readInstanceProvider(id)
  if (!existing) return refuse(404, 'not_found', 'No such instance provider.')
  const setIds = body.setIds === undefined ? null : parseSetIds(body.setIds)
  if (setIds instanceof NextResponse) return setIds
  const reentry = llmProviderSecretReentry(existing, body)
  if (reentry) return secretReentryResponse(reentry)
  const data = await parseProvider(body, existing)
  if (data instanceof NextResponse) return data
  const outcome = await auditedTransaction(prisma, async (tx) => {
    await lockPermissions(tx)
    const before = (await readProviderAssignments([id])).map((a) => a.setId).sort()
    const next = setIds ?? before
    const check = await unknownSets(tx, next)
    if (check.unknown.length > 0) return check
    const { provider } = await updateInstanceProvider(tx, id, { data, setIds: next, actorId: session.userId })
    const { id: _id, createdAt: _c, updatedAt: _u, createdById: _cb, updatedById: _ub, ...stored } = existing
    await writeAuditTx(tx, await personAuditEntry(request, session, {
      action: 'instance.llm_provider_updated', targetType: 'instance_llm_provider', targetId: id,
      permission: 'instance:settings',
      before: auditFacts(existing, before),
      after: { ...auditFacts(data, next), secretsChanged: secretsChanged(stored, data), endpointChanged: stored.baseUrl !== data.baseUrl },
    }))
    return { provider, setIds: next }
  })
  if ('unknown' in outcome) return unknownSetRefusal(outcome.unknown)
  console.log(`[rbac] instance llm provider updated id=${id} by=${session.userId} sets=${outcome.setIds.length}`)
  return ok(masked(outcome.provider, outcome.setIds))
}

/** DELETE: the provider and its assignments; projects on its models then fail closed in the agent. */
export async function deleteProvider(request: NextRequest, session: Session, id: string): Promise<NextResponse> {
  const existing = await readInstanceProvider(id)
  if (!existing) return refuse(404, 'not_found', 'No such instance provider.')
  const setIds = await auditedTransaction(prisma, async (tx) => {
    await lockPermissions(tx)
    const before = (await deleteInstanceProvider(tx, id)).sort()
    await writeAuditTx(tx, await personAuditEntry(request, session, {
      action: 'instance.llm_provider_deleted', targetType: 'instance_llm_provider', targetId: id,
      permission: 'instance:settings', before: auditFacts(existing, before),
    }))
    return before
  })
  console.log(`[rbac] instance llm provider deleted id=${id} by=${session.userId} sets=${setIds.length}`)
  return ok({ deleted: id })
}

/** PUT policy `{byoLlmForbidden}`. */
export async function changePolicy(request: NextRequest, session: Session, body: Record<string, unknown>): Promise<NextResponse> {
  if (typeof body.byoLlmForbidden !== 'boolean') return refuse(400, 'invalid_field', 'byoLlmForbidden must be a boolean.')
  const next = body.byoLlmForbidden
  const before = await readByoLlmForbidden()
  if (before === next) return ok({ byoLlmForbidden: next })
  await auditedTransaction(prisma, async (tx) => {
    await writeByoLlmForbidden(tx, next)
    await writeAuditTx(tx, await personAuditEntry(request, session, {
      action: 'instance.llm_policy_changed', targetType: 'instance_settings', targetId: null,
      permission: 'instance:settings', before: { byoLlmForbidden: before }, after: { byoLlmForbidden: next },
    }))
  })
  console.log(`[rbac] instance llm policy changed byoLlmForbidden=${next} by=${session.userId}`)
  return ok({ byoLlmForbidden: next })
}
