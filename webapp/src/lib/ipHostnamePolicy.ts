/**
 * Hostnames on target IPs: what a narrowing of the policy does to the names a
 * run already scanned (design §6.3, decision D-19).
 *
 * After a PUT /api/projects/[id] or an MCP update_project_scope that narrows the
 * policy commits, the route calls markOutOfPolicy and returns its answer as
 * `hostnamePolicyMarked`. A failure is a display problem only: every reader of
 * scanned names also re-applies the project's current policy
 * (admittedByCurrentPolicy, below), so a name the policy no longer admits is
 * never treated as a target whatever the graph says.
 */
import { getGraphSession } from '@/app/api/graph/neo4j'
import { matches, parseEntries } from '@/lib/ipHostnameFilter'
import { type IpHostnamePolicyFields, ipHostnameModeOf } from '@/lib/scopeGroups'

/** A project row, or a create/update body, as far as the policy goes. */
export type CurrentPolicyRow = IpHostnamePolicyFields & { ipMode?: boolean | null }

/**
 * The scanned names a reader may still call scanned (design §6.3): a name keeps
 * its scanned reason in the graph until the next full run, so after a
 * narrowing, a failed out_of_policy marker or a restored version only the
 * project's CURRENT policy says whether it is still a target. A filter that
 * cannot be read admits nothing, as in the rule.
 */
export function admittedByCurrentPolicy(
  names: readonly string[], row: CurrentPolicyRow | null | undefined,
): string[] {
  if (!row || row.ipMode !== true) return []
  const mode = ipHostnameModeOf(row.ipHostnameMode)
  if (mode === 'scan_all') return [...names]
  if (mode !== 'record_filter') return []
  const include = parseEntries(row.ipHostnameInclude ?? [])
  const exclude = parseEntries(row.ipHostnameExclude ?? [])
  if (include.invalid.length || exclude.invalid.length) return []
  return names.filter(name => matches(name, include.patterns, exclude.patterns).included)
}

// Both statements match only the selection's own names on the tenant key, and
// only those still marked scanned: a recorded name (an ExternalDomain) is
// never touched, nor one an earlier narrowing already marked.
const SCANNED_NAMES = `
MATCH (s:Subdomain {user_id: $uid, project_id: $pid, source: 'ip_hostname_selection'})
WHERE s.ip_hostname_reason = 'scanned'
RETURN s.name AS name`

const MARK = `
UNWIND $names AS name
MATCH (s:Subdomain {name: name, user_id: $uid, project_id: $pid, source: 'ip_hostname_selection'})
WHERE s.ip_hostname_reason = 'scanned'
SET s.ip_hostname_reason = 'out_of_policy', s.ip_hostname_evaluated_at = datetime()
RETURN count(s) AS n`

/**
 * Mark the project's scanned hostnames that `policy` no longer admits as
 * `ip_hostname_reason = 'out_of_policy'`; true when the graph agrees with the
 * policy afterwards. One read and one write in one transaction, so a name a
 * concurrent writer adds between them is never marked from a stale list. A
 * graph failure rejects; the callers report `hostnamePolicyMarked: false` and
 * keep the save.
 */
export async function markOutOfPolicy(
  projectId: string,
  userId: string,
  policy: CurrentPolicyRow,
): Promise<boolean> {
  const session = getGraphSession()
  try {
    return await session.executeWrite(async tx => {
      const params = { uid: userId, pid: projectId }
      const read = await tx.run(SCANNED_NAMES, params)
      const names = read.records.map(r => r.get('name')).filter((n): n is string => typeof n === 'string' && !!n)
      const keep = new Set(admittedByCurrentPolicy(names, policy))
      const drop = names.filter(n => !keep.has(n))
      if (drop.length) await tx.run(MARK, { names: drop, ...params })
      return true
    })
  } finally {
    await session.close()
  }
}
