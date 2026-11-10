/**
 * The recon settings registry, on the TypeScript side.
 *
 * `registry.json` beside this file is a build artifact of
 * `recon_settings/registry.yaml`; it is the same bytes the recon pipeline
 * reads, and `recon_settings/build.py --check` fails the gate if either copy is
 * stale. Edit the YAML, never either JSON.
 *
 * This module is the query layer every derived list goes through. Nothing else
 * should reach into the JSON directly: a consumer that writes its own filter is
 * a second definition of a list the registry already answers, which is the
 * drift this whole directory removes.
 *
 * Prisma stays the source of truth for existence, type and `@default()`, so the
 * helpers below read those from the DMMF rather than from the registry. That
 * independence is what makes the alignment tests mean something: if they read
 * the registry's joined copy the comparison would be a tautology.
 */
import { Prisma } from '@prisma/client'

import registryJson from './registry.json'

export type McpDisposition = 'settable' | 'create_only' | 'never'
export type Traffic = 'none' | 'passive' | 'active'
export type Phase =
  | 'domain_discovery'
  | 'port_scan'
  | 'http_probe'
  | 'resource_enum'
  | 'vuln_scan'
  | 'js_recon'
  | 'standalone'
export type Unit =
  | 'rps' | 'seconds' | 'minutes' | 'milliseconds' | 'threads' | 'count'
  | 'bytes' | 'depth' | 'percent' | 'ratio' | 'port' | 'none'
export type Validator =
  | 'http_header' | 'project_file' | 'project_file_name'
  | 'status_codes' | 'severity' | 'scan_modules' | 'hostname' | 'hostname_list' | 'roe_exclusion' | 'url'
  | 'url_path_list' | 'port_spec' | 'free_text' | 'identifier' | 'json_object' | 'attack_skill_config'
  | 'github_name' | 'github_repo_list' | 'provider_reference'
export type DenyReason =
  | 'identity' | 'internal' | 'escalation' | 'secret' | 'upload-managed'
  | 'engagement-record' | 'not-tuning' | 'derived'
export type ReadDenyReason = 'credential' | 'third_party_pii' | 'document_blob' | 'other_user'

/** The coarse shape a value is validated against, joined from Prisma. */
export type FieldType =
  | 'boolean' | 'int' | 'float' | 'string' | 'string-list' | 'number-list'
  | 'json' | 'datetime'

export interface RegistryField {
  tool: string
  runtime_key: string | null
  unit: Unit
  phase: Phase
  traffic: Traffic
  roe_capped: boolean
  mcp: McpDisposition
  /**
   * A create_only target list that `update_project_scope` may change on an
   * existing project, under the project:rescope permission. Absent means no.
   */
  rescope?: boolean
  /**
   * What a parsed Rules of Engagement document may do with this field, beyond
   * the `mcp` disposition: `deny` (never, and absent from the parse catalogue),
   * `tighten_only` (only `roe_safe_value`), or `allow`. Absent means allow.
   */
  roe_parse?: 'allow' | 'deny' | 'tighten_only'
  roe_safe_value?: unknown
  meaning: string
  bounds?: { min: number; max: number }
  values?: string[]
  validator?: Validator
  zero_means?: 'unlimited' | 'disabled' | 'auto' | 'literal'
  fallback?: 'missing' | 'falsy'
  coerce?: 'int' | 'strip' | 'strip_list'
  deny_reason?: DenyReason
  written_by?: string
  /** Absent means readable. Only an explicit false withholds a column. */
  readable?: boolean
  /**
   * What stealth mode does to this field. `set` forces a value; `ceiling`
   * lowers it to at most N and leaves an already-quieter value alone.
   */
  stealth?: { set?: unknown; ceiling?: number }
  read_deny_reason?: ReadDenyReason
  group?: string
  /**
   * The ProjectForm section that renders this field, joined from its tool at
   * build time unless the field names its own. Null means "no input anywhere",
   * which the parity test reads to tell a deliberate omission from a forgotten
   * one.
   */
  form_section: string | null
  // joined from Prisma at build time
  type: FieldType
  prisma_type: string
  optional: boolean
  default: unknown
  has_default: boolean
}

export interface RegistryTool {
  title: string
  phase: Phase
  traffic: Traffic
  vendor?: string | null
  image?: string | null
  enabled_key?: string | null
  module?: string | null
  isolated_fn?: string | null
  graph_writer?: string | null
  partial_recon_module?: string | null
  form_section?: string | null
  produces?: string[]
  description?: string
  footguns?: string[]
}

export interface RuntimeOnlyKey {
  source: 'internal' | 'env' | 'user_account' | 'project_relation'
  tool?: string
  unit: Unit
  roe_capped: boolean
  zero_means?: 'unlimited' | 'disabled' | 'auto' | 'literal'
  secret?: boolean
  meaning: string
}

export interface Registry {
  version: number
  fields: Record<string, RegistryField>
  tools: Record<string, RegistryTool>
  runtime_only: Record<string, RuntimeOnlyKey>
}

const REGISTRY = registryJson as unknown as Registry

export function loadRegistry(): Registry {
  return REGISTRY
}

/** Every Project scalar column Prisma knows about. */
export function prismaColumns(): string[] {
  return Object.keys(Prisma.ProjectScalarFieldEnum)
}

/**
 * column -> its `@default()` value, read from the DMMF.
 *
 * A function default (`cuid()`, `now()`, `autoincrement()`) has no value, so it
 * maps to `undefined`: the column exists and has a default, but not one this
 * layer can compare against a bound.
 */
export function prismaDefaults(): Record<string, unknown> {
  const model = Prisma.dmmf.datamodel.models.find(m => m.name === 'Project')
  if (!model) throw new Error('Prisma DMMF has no Project model')
  const out: Record<string, unknown> = {}
  for (const f of model.fields) {
    if (f.kind !== 'scalar' || !f.hasDefaultValue) continue
    const d = f.default
    if (d !== null && typeof d === 'object' && 'name' in d) continue // cuid(), now(), ...
    out[f.name] = d
  }
  return out
}

/** column -> its Prisma scalar type, list-ness included, read from the DMMF. */
export function prismaTypes(): Record<string, { type: string; isList: boolean }> {
  const model = Prisma.dmmf.datamodel.models.find(m => m.name === 'Project')
  if (!model) throw new Error('Prisma DMMF has no Project model')
  const out: Record<string, { type: string; isList: boolean }> = {}
  for (const f of model.fields) {
    if (f.kind !== 'scalar') continue
    out[f.name] = { type: f.type, isList: f.isList }
  }
  return out
}

export interface NamedField extends RegistryField {
  key: string
}

/** The query helper every derived list goes through. */
export function fieldsWhere(pred: (f: RegistryField, key: string) => boolean): NamedField[] {
  const out: NamedField[] = []
  for (const key of Object.keys(REGISTRY.fields).sort()) {
    const f = REGISTRY.fields[key]
    if (pred(f, key)) out.push({ key, ...f })
  }
  return out
}

export function field(key: string): RegistryField | undefined {
  return Object.prototype.hasOwnProperty.call(REGISTRY.fields, key)
    ? REGISTRY.fields[key]
    : undefined
}

export function fieldKeys(): string[] {
  return Object.keys(REGISTRY.fields).sort()
}

export function toolIds(): string[] {
  return Object.keys(REGISTRY.tools).sort()
}

export function tool(id: string): RegistryTool | undefined {
  return Object.prototype.hasOwnProperty.call(REGISTRY.tools, id)
    ? REGISTRY.tools[id]
    : undefined
}

// --- the derived lists ------------------------------------------------------------
// Each of these replaced a hand-maintained copy. They live here so there is one
// query per list rather than one per consumer.

/** Fields a token may write through `update_recon_settings`. */
export function settableFields(): NamedField[] {
  return fieldsWhere(f => f.mcp === 'settable')
}

/** Fields `create_project` may set and update_recon_settings may never change. */
export function createOnlyFields(): NamedField[] {
  return fieldsWhere(f => f.mcp === 'create_only')
}

/**
 * The create-only target lists `update_project_scope` may change: the ones the
 * project form already lets a person edit after creation. Every other
 * create-only field stays fixed whatever the token holds.
 */
export function rescopableFields(): NamedField[] {
  return fieldsWhere(f => f.mcp === 'create_only' && f.rescope === true)
}

/**
 * The engagement's enforced limits: a rate ceiling, an exclusion list, a time
 * window, the agent's denylists.
 *
 * Ordinary settable fields, reachable from the form and from MCP alike. They are
 * grouped because several controls key on the CLASS rather than on the field:
 * a preset must never carry them, `/defaults` must never emit them, and the
 * derivation reads three of them. Keyed on the registry group rather than on the
 * `roe` name prefix, because the columns keep those names while their meaning
 * changed, so a prefix match survives that change by accident.
 */
export function engagementLimitFields(): NamedField[] {
  return fieldsWhere(f => f.group === 'engagement_limits')
}

/** The engagement contract: who the client is, what the document said. UI-only. */
export function engagementRecordFields(): NamedField[] {
  return fieldsWhere(f => f.deny_reason === 'engagement-record')
}

/** Columns that are not pipeline parameters at all. */
export function neverFields(): NamedField[] {
  return fieldsWhere(f => f.mcp === 'never')
}

/**
 * Columns an MCP tool may RETURN.
 *
 * The read boundary is not the write boundary, and conflating them is how an
 * external agent ends up holding a client's phone number. `targetDomain` is
 * write-once and freely readable, because reading it is how a caller confirms
 * which engagement it is looking at. The Rules of Engagement go the other way:
 * an agent may know its rate ceiling and its exclusions, and has no business
 * with the client's emergency contact or the scanned signed document.
 *
 * Positive by construction: `readable: false` is explicit in the registry and
 * everything else is readable, so a NEW column is readable the day it is added.
 * That is the opposite of the write side's default on purpose - a column nobody
 * classified is far more likely to be ordinary tuning than a credential, and
 * the credentials are named.
 */
export function mcpReadableFields(): NamedField[] {
  return fieldsWhere(f => f.readable !== false)
}

/** Columns withheld from every MCP read, with the reason. */
export function readDeniedFields(): NamedField[] {
  return fieldsWhere(f => f.readable === false)
}

/**
 * Every runtime key the engagement rate ceiling applies to, columns and
 * runtime-only keys together.
 *
 * This is the list `RATE_LIMIT_KEYS` used to hardcode. Being IN it is not the
 * same as being capped, which is why the runtime test asserts the resolved
 * value rather than membership.
 */
export function roeCappedRuntimeKeys(): string[] {
  const fromFields = fieldsWhere(f => f.roe_capped)
    .map(f => f.runtime_key)
    .filter((k): k is string => Boolean(k))
  const fromRuntime = Object.entries(REGISTRY.runtime_only)
    .filter(([, r]) => r.roe_capped)
    .map(([k]) => k)
  return [...new Set([...fromFields, ...fromRuntime])].sort()
}

/** Concurrency knobs the memory governor scales by ratio. */
export function governorRatioKeys(): string[] {
  return fieldsWhere(f => f.unit === 'threads' && f.runtime_key !== null)
    .map(f => f.runtime_key as string)
    .sort()
}

/** In-memory accumulators the memory governor budgets in bytes. */
export function governorBudgetKeys(): string[] {
  return fieldsWhere(f => (f.unit === 'count' || f.unit === 'bytes') && f.runtime_key !== null)
    .map(f => f.runtime_key as string)
    .sort()
}

/**
 * Which scan kind a registry tool belongs to, for the queued-job fingerprint.
 *
 * A kind that is not here is a pipeline kind, covered by its phase instead. Only
 * the standalone scanners need naming, because `phase: standalone` is where
 * everything that is not a pipeline phase ends up.
 */
const KIND_TOOLS: Record<string, readonly string[]> = {
  gvm: ['gvm'],
  github_hunt: ['github'],
  trufflehog: ['trufflehog'],
  supply_chain: ['supply_chain', 'supply_chain_recon'],
  supply_chain_repo: ['supply_chain', 'supply_chain_recon'],
  ai_attack: ['ai_surface_recon'],
}

const PIPELINE_KINDS = new Set(['full_recon', 'partial_recon'])

/**
 * Tools filed under `standalone` because their form lives with the other
 * scanners, that nevertheless RUN inside the full recon pipeline. Supply-chain
 * recon runs after JS recon, gated by its own flag rather than by scanModules,
 * so a change to it must re-confirm a queued full recon like any phase would.
 */
const IN_PIPELINE_TOOLS: ReadonlySet<string> = new Set(['supply_chain_recon'])

/**
 * Fields whose change between enqueue and dispatch must re-confirm a queued job.
 *
 * Anything that steers WHERE or HOW HARD a job scans: every field of the job's
 * own tools that sends traffic, plus every engagement limit and the scope
 * columns, which steer every kind.
 *
 * The hand-written list this replaced named six fields for `full_recon` and no
 * `roe*` field at all. Queued work outlives the token that created it, so with
 * most of the model mutable that is the path where a scope-compliant
 * configuration becomes a non-compliant run with nothing failing: enqueue under
 * a 3 rps ceiling, raise the ceiling, dispatch.
 */
export function fingerprintFields(kind: string): string[] {
  // The engagement agreement and the project's OWN targeting steer every kind,
  // whatever it scans. The other create_only columns point a specific scanner at
  // a specific third party (githubTargetOrg, gvmScanTargets, supplyChainRepoUrl),
  // so they belong to that scanner's tool and are picked up per kind below
  // rather than made to re-confirm every unrelated job.
  const always = (f: RegistryField) =>
    f.group === 'engagement_limits' || (f.mcp === 'create_only' && f.tool === 'targeting')

  if (PIPELINE_KINDS.has(kind)) {
    return fieldsWhere(
      f => always(f) || f.tool === 'pipeline'
        || (f.traffic !== 'none' && (f.phase !== 'standalone' || IN_PIPELINE_TOOLS.has(f.tool)))
    ).map(f => f.key)
  }

  const tools = KIND_TOOLS[kind]
  if (!tools) return []
  const owned = new Set(tools)
  return fieldsWhere(f => always(f) || (owned.has(f.tool) && f.traffic !== 'none')).map(f => f.key)
}

/** Every scan kind the fingerprint knows how to derive a field set for. */
export function fingerprintKinds(): string[] {
  return [...PIPELINE_KINDS, ...Object.keys(KIND_TOOLS)].sort()
}
