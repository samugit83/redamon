import { NextRequest, NextResponse } from 'next/server'
import { rowCap } from '../rowCap'
import { requirePermission } from '@/lib/authz/guards'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { DECLARED_ONLY } from '@/lib/declaredOnly'
import { internalError } from '@/lib/routeErrors'

function toNum(val: unknown): number | null {
  if (val == null) return null
  if (typeof val === 'object' && 'low' in (val as object)) return (val as { low: number }).low
  return typeof val === 'number' ? val : null
}

/**
 * "AI Surface" inventory view - every AI/LLM/MCP/vector-DB surface discovered,
 * across ALL modules (http_probe, port_scan, resource_enum, js_recon, and the
 * central ai_surface_recon). Returns one array per sub-sheet.
 */
export async function GET(request: NextRequest) {
  const pid = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'graph:read', { projectId: pid })
  if (auth instanceof NextResponse) return auth
  if (!pid) return NextResponse.json({ error: 'projectId is required' }, { status: 400 })

  const session = getGraphSession()
  try {
    // --- LLM / chat / framework endpoints ---
    const llm = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid})
       WHERE ep.ai_interface_type IS NOT NULL OR ep.is_ai_framework_detected = true
       RETURN toString(id(ep)) AS nodeId,
              ep.baseurl AS baseUrl, ep.path AS path, ep.method AS method,
              ep.ai_interface_type AS interfaceType,
              ep.ai_supports_streaming AS streaming,
              ep.ai_supports_tools AS tools,
              ep.ai_supports_vision AS vision,
              ep.ai_model_family_guess AS modelFamily,
              ep.ai_latency_p50_ms AS latencyMs,
              ep.is_ai_rag_ingest AS ragIngest,
              ep.ai_framework_name AS framework,
              ep.ai_frontend_product_guess AS frontend,
              ep.ai_tool_schema_ref AS schemaRef,
              ep.source AS source, ep.updated_at AS updatedAt,
              ${DECLARED_ONLY('ep')} AS declaredOnly
       ORDER BY ep.ai_interface_type, ep.baseurl, ep.path LIMIT ${rowCap()}`,
      { pid })

    // --- MCP servers ---
    const mcp = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid}) WHERE ep.ai_interface_type = 'mcp'
       RETURN toString(id(ep)) AS nodeId, ep.baseurl AS baseUrl, ep.path AS path,
              ep.ai_mcp_server_name AS serverName,
              ep.ai_mcp_server_version AS serverVersion,
              ep.ai_mcp_protocol_version AS protocolVersion,
              ep.ai_mcp_tool_count AS toolCount,
              ep.ai_mcp_resource_count AS resourceCount,
              ep.ai_mcp_prompt_count AS promptCount,
              ep.ai_mcp_caps AS capabilities,
              ep.ai_mcp_auth_required AS authRequired,
              ep.ai_mcp_tools_hash AS toolsHash, ep.updated_at AS updatedAt
       ORDER BY ep.baseurl LIMIT ${rowCap()}`,
      { pid })

    // --- AI technologies (category ai-*) ---
    const tech = await session.run(
      `MATCH (t:Technology {project_id: $pid}) WHERE t.category STARTS WITH 'ai-'
       OPTIONAL MATCH (x)-[r]->(t) WHERE type(r) IN ['USES_TECHNOLOGY','HAS_TECHNOLOGY']
       // Adding id(t) to the implicit grouping key cannot split a row: the
       // Technology MERGE key is (name, version) per project, already grouped on.
       RETURN toString(id(t)) AS nodeId,
              t.name AS name, t.category AS category, t.version AS version,
              [d IN collect(DISTINCT r.detected_by) WHERE d IS NOT NULL] AS detectedBy,
              count(DISTINCT x) AS attachedTo, t.updated_at AS updatedAt
       ORDER BY t.category, t.name LIMIT ${rowCap()}`,
      { pid })

    // --- Vector databases ---
    const vdb = await session.run(
      `MATCH (t:Technology {project_id: $pid, category: 'ai-vector-db'})
       OPTIONAL MATCH (p:Port)-[r:HAS_TECHNOLOGY]->(t)
       OPTIONAL MATCH (ip:IP)-[:HAS_PORT]->(p)
       RETURN toString(id(t)) AS nodeId, t.name AS name, ip.address AS host, p.number AS port,
              coalesce(r.detected_by, t.source) AS detectedBy, t.updated_at AS updatedAt
       ORDER BY t.name LIMIT ${rowCap()}`,
      { pid })

    // --- Model inventory (flatten ai_model_ids) ---
    const models = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid}) WHERE ep.ai_model_ids IS NOT NULL
       UNWIND ep.ai_model_ids AS modelId
       // A model is a list value, not a node, so the row points at the Endpoint
       // that reports it. The GET and POST Endpoints of one path (method is in
       // the Endpoint key) fold into one row here; min() makes the pick stable.
       WITH modelId, ep.ai_model_family_guess AS family,
            ep.baseurl AS baseUrl, ep.path AS sourceEndpoint,
            max(ep.updated_at) AS updatedAt,
            toString(min(id(ep))) AS nodeId
       RETURN nodeId, modelId, family, baseUrl, sourceEndpoint, updatedAt
       ORDER BY modelId LIMIT ${rowCap()}`,
      { pid })

    const sheets = {
      llmEndpoints: llm.records.map((r: { get: (key: string) => unknown }) => ({
        nodeId: (r.get('nodeId') as string | null) ?? null,
        baseUrl: r.get('baseUrl'), path: r.get('path'), method: r.get('method'),
        interfaceType: r.get('interfaceType'), streaming: r.get('streaming'),
        tools: r.get('tools'), vision: r.get('vision'), modelFamily: r.get('modelFamily'),
        latencyMs: toNum(r.get('latencyMs')), ragIngest: r.get('ragIngest'),
        framework: r.get('framework'), frontend: r.get('frontend'),
        schemaRef: r.get('schemaRef'), source: r.get('source'),
        declaredOnly: r.get('declaredOnly') === true,
        updatedAt: r.get('updatedAt') ?? null,
      })),
      mcpServers: mcp.records.map((r: { get: (key: string) => unknown }) => ({
        nodeId: (r.get('nodeId') as string | null) ?? null,
        baseUrl: r.get('baseUrl'), path: r.get('path'), serverName: r.get('serverName'),
        serverVersion: r.get('serverVersion'), protocolVersion: r.get('protocolVersion'),
        toolCount: toNum(r.get('toolCount')), resourceCount: toNum(r.get('resourceCount')),
        promptCount: toNum(r.get('promptCount')),
        capabilities: (r.get('capabilities') as string[]) || [],
        authRequired: r.get('authRequired'), toolsHash: r.get('toolsHash'),
        updatedAt: r.get('updatedAt') ?? null,
      })),
      technologies: tech.records.map((r: { get: (key: string) => unknown }) => ({
        nodeId: (r.get('nodeId') as string | null) ?? null,
        name: r.get('name'), category: r.get('category'), version: r.get('version'),
        detectedBy: (r.get('detectedBy') as string[]) || [], attachedTo: toNum(r.get('attachedTo')),
        updatedAt: r.get('updatedAt') ?? null,
      })),
      vectorDbs: vdb.records.map((r: { get: (key: string) => unknown }) => ({
        nodeId: (r.get('nodeId') as string | null) ?? null,
        name: r.get('name'), host: r.get('host'), port: toNum(r.get('port')),
        detectedBy: r.get('detectedBy'),
        updatedAt: r.get('updatedAt') ?? null,
      })),
      models: models.records.map((r: { get: (key: string) => unknown }) => ({
        nodeId: (r.get('nodeId') as string | null) ?? null,
        modelId: r.get('modelId'), family: r.get('family'),
        baseUrl: r.get('baseUrl'), sourceEndpoint: r.get('sourceEndpoint'),
        updatedAt: r.get('updatedAt') ?? null,
      })),
    }

    return NextResponse.json({
      sheets,
      meta: {
        llmEndpoints: sheets.llmEndpoints.length,
        mcpServers: sheets.mcpServers.length,
        technologies: sheets.technologies.length,
        vectorDbs: sheets.vectorDbs.length,
        models: sheets.models.length,
      },
    })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Red-zone aiSurface error' })
  } finally {
    await session.close()
  }
}
