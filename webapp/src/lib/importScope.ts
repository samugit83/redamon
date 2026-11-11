import { Prisma } from '@prisma/client'
import { describeInvalid, normalizeHost, splitWildcard, validateDomainBatch } from '@/lib/domainBatch'
import {
  IP_HOSTNAME_DEFAULTS, IP_HOSTNAME_FIELDS, type ScopeFields, ipHostnamePolicyChanged, resolveScopeGroups,
  scopeGuardrailNames,
} from '@/lib/scopeGroups'
import { firstHardBlocked } from '@/lib/hard-guardrail'

export interface ImportScopeResult {
  /** Set when the import must be refused, with the HTTP status to refuse it with. */
  error?: string
  status?: number
  warnings: string[]
}

/**
 * Normalise an imported bundle's scope columns IN PLACE, the way the create
 * routes do, and refuse a scope they would refuse.
 *
 * Import is a second creation path. Copying the bundle's columns verbatim let a
 * bundle carry a hand-written `domainBatchGroups` the host list never produced,
 * a project in IP mode and batch mode at once, or a government target, none of
 * which any create route accepts. So the groups are re-derived from the hosts,
 * the modes are exclusive, a non-batch row keeps no batch scope, and the hard
 * guardrail runs in every mode.
 *
 * A batch host the current rules refuse is dropped with a warning rather than
 * refusing the bundle, so an older export still imports; nothing surviving is a
 * refusal.
 */
export function normalizeImportedScope(fields: Record<string, unknown>): ImportScopeResult {
  const warnings: string[] = []
  const ipMode = fields.ipMode === true
  const batchMode = fields.domainBatchMode === true
  if (ipMode && batchMode) {
    return {
      error: 'This bundle sets both IP mode and Domain batch mode. A project has one targeting mode; it was not imported.',
      status: 400,
      warnings,
    }
  }

  if (batchMode) {
    const raw = Array.isArray(fields.domainBatchHosts)
      ? fields.domainBatchHosts.filter((h): h is string => typeof h === 'string')
      : []
    let batch = validateDomainBatch(raw)
    if (batch.invalid.length > 0) {
      const refused = new Set(batch.invalid.map(i => i.entry))
      warnings.push(`Dropped hostnames the current rules refuse. ${describeInvalid(batch.invalid)}`)
      batch = validateDomainBatch(raw.filter(h => !refused.has(h.trim())))
    }
    if (!batch.ok) {
      return { error: `The bundle's hostname list cannot be imported: ${batch.errors.join(' ')}`, status: 400, warnings }
    }
    fields.domainBatchHosts = batch.entries
    fields.domainBatchGroups = batch.legacy as unknown as Prisma.InputJsonValue
    fields.targetDomain = ''
  } else {
    fields.domainBatchGroups = Prisma.DbNull
    fields.domainBatchHosts = []
    if (!ipMode && typeof fields.targetDomain === 'string') {
      const targetDomain = splitWildcard(normalizeHost(fields.targetDomain)).rest
      fields.targetDomain = targetDomain
      const prefixes = Array.isArray(fields.subdomainList)
        ? fields.subdomainList.filter((x): x is string => typeof x === 'string')
        : []
      const { invalid } = resolveScopeGroups({ targetDomain, subdomainList: prefixes })
      const badPrefixes = invalid.filter(i => i.reason === 'invalid_prefix')
      if (invalid.length > badPrefixes.length) {
        return { error: `The bundle's target cannot be imported. ${describeInvalid(invalid)}`, status: 400, warnings }
      }
      if (badPrefixes.length > 0) {
        const refused = new Set(badPrefixes.map(i => i.entry))
        fields.subdomainList = prefixes.filter(x => !refused.has(x))
        warnings.push(`Dropped subdomain prefixes the current rules refuse. ${describeInvalid(badPrefixes)}`)
      }
    }
  }

  // The hostname policy applies only in IP mode. A bundle of another mode that
  // carries one (edited, or exported after a mode flip an older release did not
  // clean) imports without it: it scanned nothing there.
  if (!ipMode && IP_HOSTNAME_FIELDS.some(k => k in fields)
      && ipHostnamePolicyChanged(fields as ScopeFields, IP_HOSTNAME_DEFAULTS)) {
    for (const key of IP_HOSTNAME_FIELDS) {
      const value = IP_HOSTNAME_DEFAULTS[key]
      fields[key] = Array.isArray(value) ? [] : value
    }
    warnings.push('Dropped the hostname policy (Hostnames on target IPs): it applies only to IP-mode projects.')
  }

  const blocked = firstHardBlocked(scopeGuardrailNames({
    ipMode,
    domainBatchMode: batchMode,
    domainBatchHosts: fields.domainBatchHosts as string[],
    targetDomain: typeof fields.targetDomain === 'string' ? fields.targetDomain : '',
    subdomainList: Array.isArray(fields.subdomainList)
      ? fields.subdomainList.filter((s): s is string => typeof s === 'string')
      : [],
    ipHostnameInclude: Array.isArray(fields.ipHostnameInclude)
      ? fields.ipHostnameInclude.filter((s): s is string => typeof s === 'string')
      : [],
  }))
  if (blocked) {
    return { error: `Target permanently blocked: ${blocked.name}: ${blocked.reason}`, status: 403, warnings }
  }
  return { warnings }
}
