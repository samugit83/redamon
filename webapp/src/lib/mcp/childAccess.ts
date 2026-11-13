/**
 * Ownership for the child rows MCP tools address by id.
 *
 * `assertMcpProjectAccess` proves the PARENT and nothing else: it takes a
 * projectId, checks `Project.userId`, and never sees a versionId, jobId, viewId
 * or remediationId. Every one of those is a bare cuid that `findUnique` will
 * happily resolve across tenants - and a `ScanVersion` is a gzipped dump of an
 * entire attack-surface graph.
 *
 * There was nothing to reuse. The existing checks either inline the pattern in
 * a route while calling the session-based `guardProject`, or take a browser
 * `EffectiveUser`; neither is reachable from a bearer token.
 *
 * So: one module, and no tool may reach a child row any other way. Each helper
 * proves the PARENT with `assertMcpProjectAccess` first, then re-resolves the
 * owning projectId FROM THE ROW. A row that is missing and a row belonging to
 * someone else take the same path to the same message, so neither id space can
 * be enumerated - see `childNotFound` for why that message names the child.
 *
 * A graph `nodeId` needs no helper here and deliberately has none: the triage
 * mixin's own WHERE carries `n.user_id` and `n.project_id` plus the
 * muteable-label expression, so a foreign id matches zero rows server-side.
 */
import prisma from '@/lib/prisma'
import { assertMcpProjectAccess, type McpProjectToken } from '@/lib/mcpAuth'
import type { ProjectLevel } from '@/lib/authz/permissions'
import { McpToolError } from '@/lib/mcp/errors'

/**
 * Who asks and at what level: the token (a bare user id is a token that never
 * opted in to shared projects) and the level of the tool behind the lookup,
 * which defaults to the owner's as `assertMcpProjectAccess` does.
 */
type Asker = McpProjectToken | string

/**
 * A child row that is either missing or another project's. The caller is not
 * told which, and that is the whole anti-enumeration property.
 *
 * It names the CHILD rather than reusing `McpAccessDenied`'s flat "Project not
 * found". Every caller of these helpers has already cleared
 * `assertMcpProjectAccess` one line above, so the project demonstrably exists
 * and is theirs; answering "Project not found" sent an agent off to retry with
 * a different projectId over a bad viewId, which is the retry loop this surface
 * is written to avoid.
 *
 * The distinction that must NOT leak is foreign-versus-missing, and this
 * preserves it exactly: both cases produce this identical message. The project
 * boundary itself is untouched - a foreign PROJECT still fails earlier, in
 * `assertMcpProjectAccess`, with the flat message.
 */
function childNotFound(kind: string): never {
  throw new McpToolError(`No such ${kind} in this project.`, 'not_found')
}

/** Fields every caller of `assertVersionInProject` gets. Never `snapshot`. */
export interface OwnedScanVersion {
  id: string
  seq: number
  label: string
  isCurrent: boolean
  pinned: boolean
  nodeCount: number | null
  linkCount: number | null
  createdAt: Date
  /** Derived from `octet_length`, so the bytes themselves are never loaded. */
  hasSnapshot: boolean
  snapshotBytes: number
}

/**
 * A version, proven to belong to a project this token owns.
 *
 * Raw SQL rather than Prisma because `octet_length(snapshot)` is the only way
 * to learn whether a version still has its bytes without fetching a gzipped
 * whole-graph dump out of Postgres to find out.
 */
export async function assertVersionInProject(
  token: Asker,
  projectId: string,
  versionId: string,
  needed: ProjectLevel = 'O'
): Promise<OwnedScanVersion> {
  await assertMcpProjectAccess(token, projectId, needed)

  const [row] = await prisma.$queryRaw<Array<{
    id: string
    project_id: string
    seq: number
    label: string
    is_current: boolean
    pinned: boolean
    node_count: number | null
    link_count: number | null
    created_at: Date
    snapshot_bytes: number | null
  }>>`
    SELECT id, project_id, seq, label, is_current, pinned, node_count, link_count,
           created_at, octet_length(snapshot) AS snapshot_bytes
    FROM scan_versions
    WHERE id = ${versionId}
  `
  // The project predicate is applied HERE rather than in the WHERE so that a
  // foreign row and a missing row take the same path to the same answer.
  if (!row || row.project_id !== projectId) childNotFound('scan version')

  const bytes = Number(row.snapshot_bytes ?? 0)
  return {
    id: row.id,
    seq: row.seq,
    label: row.label,
    isCurrent: row.is_current,
    pinned: row.pinned,
    nodeCount: row.node_count,
    linkCount: row.link_count,
    createdAt: row.created_at,
    hasSnapshot: bytes > 0,
    snapshotBytes: bytes,
  }
}

export interface OwnedJob {
  id: string
  projectId: string
  kind: string
  status: string
  runId: string
  enqueuedAt: Date
}

export async function assertJobInProject(
  token: Asker,
  projectId: string,
  jobId: string,
  needed: ProjectLevel = 'O'
): Promise<OwnedJob> {
  await assertMcpProjectAccess(token, projectId, needed)
  const row = await prisma.jobQueue.findUnique({
    where: { id: jobId },
    select: { id: true, projectId: true, kind: true, status: true, runId: true, enqueuedAt: true },
  })
  if (!row || row.projectId !== projectId) childNotFound('queued job')
  return row
}

export interface OwnedGraphView {
  id: string
  projectId: string
  name: string
  description: string
  cypherQuery: string
  /** The project's owner: the tenant the stored query runs under (on a shared project, not the token's user). */
  ownerId: string
}

/**
 * A saved view, proven owned.
 *
 * `cypherQuery` is loaded because the caller has to RUN it, and is never part
 * of any payload that leaves the process: handing raw Cypher to an external
 * model leaks the graph schema and gives it an injection carrier.
 */
export async function assertViewInProject(
  token: Asker,
  projectId: string,
  viewId: string,
  needed: ProjectLevel = 'O'
): Promise<OwnedGraphView> {
  const project = await assertMcpProjectAccess(token, projectId, needed)
  const row = await prisma.graphView.findUnique({
    where: { id: viewId },
    select: { id: true, projectId: true, name: true, description: true, cypherQuery: true },
  })
  if (!row || row.projectId !== projectId) childNotFound('saved view')
  return { ...row, ownerId: project.userId }
}

export interface OwnedRemediation {
  id: string
  projectId: string
  title: string
  status: string
}

export async function assertRemediationInProject(
  token: Asker,
  projectId: string,
  remediationId: string,
  needed: ProjectLevel = 'O'
): Promise<OwnedRemediation> {
  await assertMcpProjectAccess(token, projectId, needed)
  const row = await prisma.remediation.findUnique({
    where: { id: remediationId },
    select: { id: true, projectId: true, title: true, status: true },
  })
  if (!row || row.projectId !== projectId) childNotFound('remediation')
  return row
}
