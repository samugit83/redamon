/**
 * One Secret row of the JS Recon table, from the download route's record.
 */
import { isPublicClientKey } from './publicClientKeys'

/**
 * What the Red Zone calls a js_recon Secret that only TruffleHog found. A key
 * both engines found keeps js_recon's own row and says so in `alternate_names`.
 */
export const JS_RECON_TRUFFLEHOG_SOURCE = 'TruffleHog (JS Recon)'

/** The source module a person reads; `source` stays the stored value otherwise. */
export function secretSourceLabel(source: unknown, detectionMethod: unknown): string | null {
  if (source === 'js_recon' && detectionMethod === 'trufflehog') return JS_RECON_TRUFFLEHOG_SOURCE
  return typeof source === 'string' && source ? source : null
}

/** The JS Recon table's Detection cell; null for a node written before the property. */
export function detectionMethodLabel(method: unknown): string | null {
  if (method === 'trufflehog') return 'TruffleHog'
  if (method === 'regex') return 'Regex'
  return typeof method === 'string' && method ? method : null
}

/**
 * The merge records a TruffleHog match as `TruffleHog:<DetectorName>`, the form
 * Cypher and the Priority Board key on; a person reads `TruffleHog (Github)`.
 */
export function alternateNameLabel(name: string): string {
  const m = /^TruffleHog:(.+)$/.exec(name)
  return m ? `TruffleHog (${m[1]})` : name
}

/** A neo4j Integer arrives as {low, high}; absent stays null. */
function intOrNull(value: unknown): number | null {
  if (value && typeof value === 'object' && 'low' in value) return (value as { low: number }).low
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function stringListOrNull(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null
  return value.filter((v): v is string => typeof v === 'string' && v !== '')
}

export interface JsReconSecretRow {
  nodeId: unknown
  id: unknown
  name: unknown
  severity: unknown
  public_client_key: boolean
  redacted_value: unknown
  matched_text: unknown
  category: unknown
  source_url: unknown
  /** Null on a node written before JS Recon stored it. */
  line_number: number | null
  confidence: unknown
  detection_method: unknown
  /** Other rule or detector names that matched the same span; null on an older node. */
  alternate_names: string[] | null
  validation: Record<string, unknown>
  updatedAt: unknown
}

export function jsReconSecretFromRecord(get: (key: string) => unknown): JsReconSecretRow {
  // The node's validation_status is what every other reader (the Red Zone,
  // mute rules, the Priority Board) goes by, so it wins over the copy inside
  // the validator's details.
  const stored = get('validation_status')
  let validation: Record<string, unknown> = { status: stored || 'unvalidated' }
  const info = get('validation_info')
  if (typeof info === 'string' && info) {
    try {
      const parsed = JSON.parse(info)
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        validation = { ...parsed, status: stored || parsed.status || 'unvalidated' }
      }
    } catch { /* keep the stored status */ }
  }
  // A node written before `public_client_key` keeps its old severity until
  // JS Recon runs again; its pattern name still says public.
  const publicClientKey = isPublicClientKey(get('public_client_key'), get('name'))
  return {
    nodeId: get('nodeId') ?? null,
    id: get('id'),
    name: get('name'),
    severity: publicClientKey ? 'info' : get('severity'),
    public_client_key: publicClientKey,
    redacted_value: get('redacted_value'),
    matched_text: get('matched_text'),
    category: get('category'),
    source_url: get('source_url'),
    line_number: intOrNull(get('line_number')),
    confidence: get('confidence'),
    detection_method: get('detection_method'),
    alternate_names: stringListOrNull(get('alternate_names')),
    validation,
    updatedAt: get('updatedAt') ?? null,
  }
}
