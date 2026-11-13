/**
 * The project owner's catalogs, as a collaborator's project form reads them (step 5.7, SH-26):
 * which LLM providers and Jev configurations the owner has (id, name, type, whether a key is
 * stored), the owner's attack skills (id, name, quarantined), tradecraft resources (id, name,
 * enabled), MCP servers (id, name, enabled, tool names, default phases) and which API keys are set.
 *
 * Names and presence only, never a value. Every list is rebuilt field by field from an explicit
 * select, so a column added to one of these rows later stays out of the answer until it is named
 * here: API keys, tokens, passwords, base URLs, headers, endpoints, stdio commands and environments,
 * skill text and tradecraft URLs never leave this module. GET /api/projects/[id]/owner-catalog
 * serves it, with the caller's access to the project decided first.
 */
import { NextResponse } from 'next/server'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { isChatProvider, isJevProvider } from '@/lib/llmProviderKinds'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'
import { PHASES } from '@/lib/mcp/schema'

/**
 * The owner's API keys (UserSettings), named by presence. The secrets the settings route masks
 * (its SECRET_FIELDS), less the instance tunnel credentials (`ngrokAuthtoken`, `chiselAuth`), which
 * no project setting reads; ownerCatalog.test.ts keeps the two lists equal.
 */
export const OWNER_KEY_FIELDS = [
  'githubAccessToken',
  'supplyChainGithubToken',
  'githubEnterpriseToken',
  'tavilyApiKey',
  'shodanApiKey',
  'serpApiKey',
  'nvdApiKey',
  'vulnersApiKey',
  'urlscanApiKey',
  'censysApiToken',
  'censysOrgId',
  'fofaApiKey',
  'otxApiKey',
  'netlasApiKey',
  'virusTotalApiKey',
  'zoomEyeApiKey',
  'criminalIpApiKey',
  'securitytrailsApiKey',
  'viewdnsApiKey',
  'quakeApiKey',
  'hunterApiKey',
  'publicWwwApiKey',
  'hunterHowApiKey',
  'googleApiKey',
  'googleApiCx',
  'onypheApiKey',
  'driftnetApiKey',
  'wpscanApiToken',
  'pdcpApiKey',
  'trufflehogGithubToken',
  'trufflehogGitlabToken',
  'trufflehogDockerToken',
  'trufflehogHuggingfaceToken',
  'trufflehogAwsAccessKeyId',
  'trufflehogAwsSecretKey',
  'trufflehogAwsSessionToken',
  'trufflehogGcpServiceAccount',
  'trufflehogPostmanToken',
  'trufflehogJenkinsUsername',
  'trufflehogJenkinsPassword',
  'trufflehogElasticUsername',
  'trufflehogElasticPassword',
  'trufflehogElasticApiKey',
  'trufflehogElasticServiceToken',
  'trufflehogCircleciToken',
  'trufflehogTravisciToken',
  'trufflehogGitUsername',
  'trufflehogGitToken',
] as const

export type OwnerKeyField = typeof OWNER_KEY_FIELDS[number]

export interface CatalogProvider {
  id: string
  name: string
  type: string
  /** A credential is stored (an API key, or Bedrock's bearer token or IAM pair); never which. */
  hasKey: boolean
}

export interface CatalogAttackSkill {
  id: string
  name: string
  /** A quarantined skill cannot be turned on (userSkills.ts). */
  quarantined: boolean
}

export interface CatalogTradecraftResource {
  id: string
  name: string
  enabled: boolean
}

/** Field names as GET /api/users/[id]/mcp spells them, so the tool matrix reads either answer. */
export interface CatalogMcpServer {
  id: string
  name: string
  enabled: boolean
  /** Empty: the matrix falls back to every phase, as for a stored server without the field. */
  default_phases: string[]
  tools: Array<{ name: string; default_phases: string[] }>
}

export interface OwnerCatalog {
  /** Chat providers: the model pickers' sources. */
  providers: CatalogProvider[]
  /** Jev configurations (non-chat), the project's `jevProviderId` picks one. */
  jevProviders: CatalogProvider[]
  attackSkills: CatalogAttackSkill[]
  tradecraftResources: CatalogTradecraftResource[]
  mcpServers: CatalogMcpServer[]
  keys: Record<OwnerKeyField, boolean>
}

const present = (v: unknown): boolean => typeof v === 'string' && v.trim() !== ''

// The key columns are read only to answer presence; the endpoint, header and model columns never.
const PROVIDER_SELECT = {
  id: true, name: true, providerType: true, apiKey: true, awsAccessKeyId: true, awsSecretKey: true, awsBearerToken: true,
} as const satisfies Prisma.UserLlmProviderSelect

const SETTINGS_SELECT: Prisma.UserSettingsSelect = {
  ...Object.fromEntries(OWNER_KEY_FIELDS.map((f) => [f, true])),
  mcpServers: true,
}

export function providerHasKey(row: { apiKey: string; awsAccessKeyId: string; awsSecretKey: string; awsBearerToken: string }): boolean {
  return present(row.apiKey) || present(row.awsBearerToken) || (present(row.awsAccessKeyId) && present(row.awsSecretKey))
}

const KNOWN_PHASES: ReadonlySet<string> = new Set(PHASES)

function phases(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((p): p is string => typeof p === 'string' && KNOWN_PHASES.has(p)) : []
}

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)

/** The stored `mcpServers` JSON as the catalog shows it; anything that is not a server with an id is skipped. */
export function catalogMcpServers(raw: unknown): CatalogMcpServer[] {
  if (!Array.isArray(raw)) return []
  return raw.flatMap((srv): CatalogMcpServer[] => {
    if (!isRecord(srv) || typeof srv.id !== 'string' || !srv.id) return []
    const tools = Array.isArray(srv.tools) ? srv.tools : []
    return [{
      id: srv.id,
      name: typeof srv.name === 'string' && srv.name ? srv.name : srv.id,
      enabled: srv.enabled !== false,
      default_phases: phases(srv.default_phases),
      tools: tools.flatMap((t) => (isRecord(t) && typeof t.name === 'string' && t.name
        ? [{ name: t.name, default_phases: phases(t.default_phases) }]
        : [])),
    }]
  })
}

/** The owner's catalogs (see the module comment). */
export async function ownerCatalog(ownerId: string): Promise<OwnerCatalog> {
  const [providerRows, skills, resources, settings] = await Promise.all([
    prisma.userLlmProvider.findMany({ where: { userId: ownerId }, select: PROVIDER_SELECT, orderBy: { createdAt: 'asc' } }),
    prisma.userAttackSkill.findMany({
      where: { userId: ownerId }, select: { id: true, name: true, quarantinedAt: true }, orderBy: { createdAt: 'desc' },
    }),
    prisma.userTradecraftResource.findMany({
      where: { userId: ownerId }, select: { id: true, name: true, enabled: true }, orderBy: { createdAt: 'asc' },
    }),
    prisma.userSettings.findUnique({ where: { userId: ownerId }, select: SETTINGS_SELECT }) as Promise<Record<string, unknown> | null>,
  ])
  const provider = (row: typeof providerRows[number]): CatalogProvider =>
    ({ id: row.id, name: row.name, type: row.providerType, hasKey: providerHasKey(row) })
  return {
    providers: providerRows.filter(isChatProvider).map(provider),
    jevProviders: providerRows.filter(isJevProvider).map(provider),
    attackSkills: skills.map((s) => ({ id: s.id, name: s.name, quarantined: s.quarantinedAt !== null })),
    tradecraftResources: resources.map((r) => ({ id: r.id, name: r.name, enabled: r.enabled })),
    mcpServers: catalogMcpServers(settings?.mcpServers),
    keys: Object.fromEntries(OWNER_KEY_FIELDS.map((f) => [f, present(settings?.[f])])) as Record<OwnerKeyField, boolean>,
  }
}

export interface CatalogModelOption {
  id: string
  name: string
  context_length: number | null
  description: string
}

const MODELS_FAILED = "Could not list the project owner's models"
// As /api/models: the agent asks every provider at once, each with its own 15-20 s budget.
const MODELS_TIMEOUT_MS = 60_000

function modelOptions(data: Record<string, unknown>): Record<string, CatalogModelOption[]> {
  const out: Record<string, CatalogModelOption[]> = {}
  for (const [group, models] of Object.entries(data)) {
    if (!Array.isArray(models)) continue
    out[group] = models.flatMap((m): CatalogModelOption[] => (isRecord(m) && typeof m.id === 'string' && m.id
      ? [{
          id: m.id,
          name: typeof m.name === 'string' ? m.name : m.id,
          context_length: typeof m.context_length === 'number' ? m.context_length : null,
          description: typeof m.description === 'string' ? m.description : '',
        }]
      : []))
  }
  return out
}

/**
 * The models of the owner's chat providers, grouped by provider as the model pickers read them: the
 * agent's /models over the owner's rows, as /api/models lists one's own. Jev rows are never sent (a
 * non-chat key lists no models). The rows travel whole to the agent only, as on /api/models; the
 * answer is rebuilt from the four fields a picker shows.
 */
export async function ownerModelOptions(
  ownerId: string,
): Promise<{ models: Record<string, CatalogModelOption[]> } | { failure: NextResponse }> {
  const rows = await prisma.userLlmProvider.findMany({ where: { userId: ownerId }, orderBy: { createdAt: 'asc' } })
  const providers = rows.filter(isChatProvider)
  let res: Response
  try {
    res = await agentFetch('/models', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ providers: providers.length > 0 ? providers : null }),
      cache: 'no-store',
    }, { timeoutMs: MODELS_TIMEOUT_MS })
  } catch (err) {
    if (err instanceof AgentUnreachableError) return { failure: upstreamFailureResponse('agent', err.cause_, MODELS_FAILED) }
    throw err
  }
  if (!res.ok) return { failure: await upstreamErrorResponse('agent', res, MODELS_FAILED, { status: 503 }) }
  const data: unknown = await res.json().catch(() => null)
  if (!isRecord(data)) {
    return { failure: NextResponse.json({ error: MODELS_FAILED, code: 'invalid_response' }, { status: 502 }) }
  }
  return { models: modelOptions(data) }
}
