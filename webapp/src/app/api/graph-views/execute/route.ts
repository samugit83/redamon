import { NextRequest, NextResponse } from 'next/server'
import { graphError } from '../../graph/graphErrors'
import { getGraphSession } from '../../graph/neo4j'
import { formatGraphRecords } from '../../graph/format'
import { injectProjectFilter, findUnscopedNodePattern, namesMutedLabel, hasVariableLengthPath, findDisallowedCall } from './injectProjectFilter'
import { requirePermission } from '@/lib/authz/guards'

/**
 * Execute a Cypher query (from a saved graph view) against Neo4j,
 * injecting project_id tenant filter, and return formatted graph data.
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { cypherQuery, projectId } = body

    if (!cypherQuery || !projectId) {
      return NextResponse.json(
        { error: 'cypherQuery and projectId are required' },
        { status: 400 }
      )
    }

    // Only the project's effective owner may run a (read-only) view query against
    // its subgraph.
    const auth = await requirePermission(request, 'graph:cypher', { projectId })
    if (auth instanceof NextResponse) return auth

    // Block write operations -- data filters are read-only
    const upper = cypherQuery.toUpperCase().replace(/\/\/[^\n]*/g, '')
    const WRITE_KEYWORDS = ['CREATE', 'MERGE', 'DELETE', 'DETACH', 'SET', 'REMOVE', 'DROP', 'CALL']
    const found = WRITE_KEYWORDS.find(kw => new RegExp(`\\b${kw}\\b`).test(upper))
    if (found) {
      return NextResponse.json(
        { error: `Write operations are not allowed in data filters (found: ${found})` },
        { status: 400 }
      )
    }

    // A saved view may not ask about suppressed findings. Checked BEFORE
    // injection, which adds a `!Muted` term of its own to every pattern.
    if (namesMutedLabel(cypherQuery)) {
      return NextResponse.json(
        { error: "The 'Muted' label is reserved: findings suppressed as noise are hidden from views and cannot be queried." },
        { status: 400 }
      )
    }

    // A namespaced function bypasses the CALL block above (apoc.* functions need
    // no CALL) and runs unscoped Cypher / fetches URLs from inside the DB.
    const badCall = findDisallowedCall(cypherQuery)
    if (badCall) {
      return NextResponse.json(
        { error: `The function or procedure '${badCall}' is not permitted in a view query.` },
        { status: 400 }
      )
    }

    // A variable-length or quantified path traverses nodes with no pattern of
    // their own, so they cannot be tenant-scoped and could surface another
    // project's nodes. Refuse rather than run one unscoped.
    if (hasVariableLengthPath(cypherQuery)) {
      return NextResponse.json(
        { error: 'Variable-length and quantified path patterns are not allowed: their intermediate nodes cannot be tenant-scoped.' },
        { status: 400 }
      )
    }

    // Inject project_id filter into every node pattern in the Cypher query.
    const filtered = injectProjectFilter(cypherQuery)

    // Fail closed: if any node pattern remains that could surface cross-tenant
    // nodes (a variable/label with no project_id predicate), refuse the query
    // rather than leak another tenant's subgraph.
    const unscoped = findUnscopedNodePattern(filtered)
    if (unscoped) {
      return NextResponse.json(
        { error: `Query contains a node pattern that cannot be tenant-scoped: (${unscoped})` },
        { status: 400 }
      )
    }

    const session = getGraphSession()
    try {
      const result = await session.run(filtered, { projectId })
      const { nodes, links } = formatGraphRecords(result.records)
      return NextResponse.json({ nodes, links, projectId })
    } finally {
      await session.close()
    }
  } catch (error) {
    // The Neo4j message quotes the query and the values it matched; its status
    // code (Neo.ClientError.Statement.SyntaxError) says what went wrong.
    return graphError(error, 'Query execution failed', 'Graph view execute error')
  }
}
