/**
 * Hostnames on target IPs: what a narrowing of the policy does to the names a
 * run already scanned (design §6.3, decision D-19).
 *
 * After a PUT /api/projects/[id] or an MCP update_project_scope that narrows the
 * policy commits, the route calls markOutOfPolicy and returns its answer as
 * `hostnamePolicyMarked`. A failure is a display problem only: every reader of
 * scanned names also re-applies the project's current policy, so a name the
 * policy no longer admits is never treated as a target whatever the graph says.
 */
import type { IpHostnamePolicyFields } from '@/lib/scopeGroups'

/**
 * Mark the project's scanned hostnames that `policy` no longer admits as
 * `ip_hostname_reason = 'out_of_policy'`; true when the graph agrees with the
 * policy afterwards.
 *
 * Writes nothing and answers true: the only nodes it would mark are Subdomains
 * with `source: 'ip_hostname_selection'`, and the pipeline does not write any
 * yet (the selection step that creates them comes with the late-name scan), so
 * there is nothing a narrowing could leave behind. The tenant-keyed write lands
 * with that step, in this function, without changing its callers.
 */
export async function markOutOfPolicy(
  _projectId: string,
  _userId: string,
  _policy: IpHostnamePolicyFields,
): Promise<boolean> {
  return true
}
