import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { getGraphSession } from '@/app/api/graph/neo4j'
import {
  discoveryDomains,
  partialScopeFields,
  resolveProjectRoots,
  type GraphDomainRow,
} from '@/lib/partialReconScope'

interface RouteParams {
  params: Promise<{ projectId: string; toolId: string }>
}

interface Neo4jRecord {
  get(key: string): unknown
}

function num(record: Neo4jRecord | undefined, key: string): number {
  const value = record?.get(key) as { toNumber?: () => number } | number | undefined
  if (value && typeof value === 'object' && typeof value.toNumber === 'function') return value.toNumber()
  return typeof value === 'number' ? value : 0
}

function strings(record: Neo4jRecord | undefined, key: string): string[] {
  const value = record?.get(key)
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []
}

// Every Domain-anchored count starts here: the roots this run covers, never
// "whichever Domain node Neo4j returned first".
const DOMAINS = `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid}) WHERE d.name IN $domains`

const SUBDOMAIN_COUNT = `${DOMAINS}
  OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
  RETURN count(DISTINCT s) AS subdomainCount`

const SUBDOMAINS_AND_IPS = `${DOMAINS}
  OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
  OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
  WITH collect(DISTINCT s.name) AS subdomains,
       count(DISTINCT i) + count(DISTINCT di) AS ipCount
  RETURN subdomains, size(subdomains) AS subCount, ipCount`

// Same IP + Port shape as Nmap: tlsx grabs certs on already-open ports.
const PORTS = `${DOMAINS}
  OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)
  OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
  WITH collect(DISTINCT s.name) AS subdomains,
       count(DISTINCT i) + count(DISTINCT di) AS ipCount,
       count(DISTINCT p) + count(DISTINCT dp) AS portCount
  RETURN subdomains, size(subdomains) AS subCount, ipCount, portCount`

const SUBDOMAIN_LIST = `${DOMAINS}
  OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
  WITH collect(DISTINCT s.name) AS subdomains
  RETURN subdomains, size(subdomains) AS subCount`

// BaseURLs and Endpoints are project-wide: a BaseURL is not tied to a Domain
// node. The tools that read them skip a host under a Domain the run does not
// cover (a root dropped from the batch keeps its node until the next full
// recon, or one left unticked), so the counts skip it too.
const hostOfUrl = (url: string) => `split(split(split(${url}, '://')[1], '/')[0], ':')[0]`
const BASEURL_HOST = `toLower(coalesce(b.host, ${hostOfUrl('b.url')}))`

function notUnderOtherDomain(host: string): string {
  return `NOT EXISTS {
    MATCH (od:Domain {user_id: $uid, project_id: $pid})
    WHERE NOT od.name IN $domains
      AND (${host} = toLower(od.name) OR ${host} ENDS WITH '.' + toLower(od.name))
  }`
}

const SCOPED_BASEURLS = `OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
  WHERE ${notUnderOtherDomain(BASEURL_HOST)}`

const SCOPED_ENDPOINTS = `OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
  WHERE ${notUnderOtherDomain(`toLower(${hostOfUrl('e.baseurl')})`)}`

const BASEURLS = `${SCOPED_BASEURLS}
  RETURN collect(DISTINCT b.url) AS baseurls`

const BASEURLS_AND_ENDPOINTS = `${SCOPED_BASEURLS}
  WITH collect(DISTINCT b.url) AS baseurls
  ${SCOPED_ENDPOINTS}
  RETURN baseurls, count(DISTINCT e) AS endpointCount`

const baseurlFields = (r: Neo4jRecord | undefined) => {
  const baseurls = strings(r, 'baseurls')
  return { existing_baseurls: baseurls, existing_baseurls_count: baseurls.length }
}
const subdomainFields = (r: Neo4jRecord | undefined) => ({
  existing_subdomains: strings(r, 'subdomains'),
  existing_subdomains_count: num(r, 'subCount'),
})

interface ToolQuery {
  cypher: string
  respond: (record: Neo4jRecord | undefined) => Record<string, unknown>
}

const SUBDOMAINS_IPS_TOOL: ToolQuery = {
  cypher: SUBDOMAINS_AND_IPS,
  respond: r => ({ ...subdomainFields(r), existing_ips_count: num(r, 'ipCount') }),
}
const PORTS_TOOL: ToolQuery = {
  cypher: PORTS,
  respond: r => ({
    ...subdomainFields(r),
    existing_ips_count: num(r, 'ipCount'),
    existing_ports_count: num(r, 'portCount'),
  }),
}
const SUBDOMAIN_COUNT_TOOL: ToolQuery = {
  cypher: SUBDOMAIN_COUNT,
  respond: r => ({ existing_subdomains_count: num(r, 'subdomainCount') }),
}
const BASEURL_TOOL: ToolQuery = {
  cypher: BASEURLS,
  respond: r => ({ existing_subdomains_count: 0, ...baseurlFields(r) }),
}
// SupplyChainRecon consumes the same graph inputs as JsRecon (BaseURLs +
// Endpoints); it re-uses the JS-recon fetch to harvest packages.
const JS_TOOL: ToolQuery = {
  cypher: BASEURLS_AND_ENDPOINTS,
  respond: r => ({
    existing_subdomains_count: 0,
    ...baseurlFields(r),
    existing_endpoints_count: num(r, 'endpointCount'),
  }),
}

const TOOL_QUERIES: Record<string, ToolQuery> = {
  SubdomainDiscovery: SUBDOMAIN_COUNT_TOOL,
  Urlscan: SUBDOMAIN_COUNT_TOOL,
  Uncover: SUBDOMAIN_COUNT_TOOL,
  Naabu: SUBDOMAINS_IPS_TOOL,
  Masscan: SUBDOMAINS_IPS_TOOL,
  Shodan: SUBDOMAINS_IPS_TOOL,
  OsintEnrichment: SUBDOMAINS_IPS_TOOL,
  Nmap: PORTS_TOOL,
  Tlsx: PORTS_TOOL,
  Katana: BASEURL_TOOL,
  OpenAPI: BASEURL_TOOL,
  Hakrawler: BASEURL_TOOL,
  Jsluice: BASEURL_TOOL,
  Ffuf: BASEURL_TOOL,
  Kiterunner: BASEURL_TOOL,
  JsRecon: JS_TOOL,
  SupplyChainRecon: JS_TOOL,
  Gau: { cypher: SUBDOMAIN_LIST, respond: subdomainFields },
  ParamSpider: { cypher: SUBDOMAIN_LIST, respond: subdomainFields },
  ZapAjaxSpider: {
    cypher: `${SCOPED_BASEURLS}
      WITH collect(DISTINCT b.url) AS baseurls
      OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
      WHERE ${notUnderOtherDomain(BASEURL_HOST)}
      RETURN baseurls, count(DISTINCT e) AS endpointCount`,
    respond: r => ({
      ...baseurlFields(r),
      existing_endpoints_count: num(r, 'endpointCount'),
      existing_subdomains_count: 0,
    }),
  },
  Arjun: {
    cypher: `${SCOPED_BASEURLS}
      OPTIONAL MATCH (b)-[:HAS_ENDPOINT]->(e:Endpoint {user_id: $uid, project_id: $pid})
      WITH collect(DISTINCT b.url) AS baseurls, count(DISTINCT e) AS endpointCount
      RETURN baseurls, endpointCount`,
    respond: r => ({
      existing_subdomains_count: 0,
      ...baseurlFields(r),
      existing_endpoints_count: num(r, 'endpointCount'),
    }),
  },
  EndpointAiClassifier: {
    cypher: `OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
      WITH count(DISTINCT e) AS endpointCount
      OPTIONAL MATCH (p:Parameter {user_id: $uid, project_id: $pid})
      WITH endpointCount, count(DISTINCT p) AS parameterCount
      OPTIONAL MATCH (e2:Endpoint {user_id: $uid, project_id: $pid})
        WHERE e2.ai_interface_type IS NOT NULL AND e2.ai_interface_type <> 'non-llm'
      RETURN endpointCount, parameterCount, count(DISTINCT e2) AS alreadyClassifiedCount`,
    respond: r => ({
      existing_endpoints_count: num(r, 'endpointCount'),
      existing_parameters_count: num(r, 'parameterCount'),
      already_ai_classified_count: num(r, 'alreadyClassifiedCount'),
    }),
  },
  SecurityChecks: {
    cypher: `${DOMAINS}
      OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
      OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
      WITH collect(DISTINCT s.name) AS subdomains,
           count(DISTINCT i) + count(DISTINCT di) AS ipCount
      ${SCOPED_BASEURLS}
      WITH subdomains, ipCount, collect(DISTINCT b.url) AS baseurls
      RETURN subdomains, size(subdomains) AS subCount, ipCount, baseurls`,
    respond: r => ({
      ...subdomainFields(r),
      existing_ips_count: num(r, 'ipCount'),
      ...baseurlFields(r),
    }),
  },
  Httpx: {
    cypher: `${DOMAINS}
      OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
      WITH collect(DISTINCT s.name) AS subdomains
      OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid}) WHERE d.name IN $domains
      OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)
      OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
      OPTIONAL MATCH (p)-[:HAS_SERVICE]->(:Service)-[:SERVES_URL]->(bu:BaseURL)
      OPTIONAL MATCH (dp)-[:HAS_SERVICE]->(:Service)-[:SERVES_URL]->(dbu:BaseURL)
      WITH subdomains,
           count(DISTINCT i) + count(DISTINCT di) AS ipCount,
           count(DISTINCT p) + count(DISTINCT dp) AS portCount,
           count(DISTINCT bu) + count(DISTINCT dbu) AS baseurlCount
      RETURN subdomains, size(subdomains) AS subCount, ipCount, portCount, baseurlCount`,
    respond: r => ({
      ...subdomainFields(r),
      existing_ips_count: num(r, 'ipCount'),
      existing_ports_count: num(r, 'portCount'),
      existing_baseurls_count: num(r, 'baseurlCount'),
    }),
  },
  Nuclei: {
    cypher: `${DOMAINS}
      OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
      WITH count(DISTINCT s) AS subCount
      ${SCOPED_BASEURLS}
      WITH subCount, collect(DISTINCT b.url) AS baseurls
      ${SCOPED_ENDPOINTS}
      RETURN subCount, baseurls, count(DISTINCT e) AS endpointCount`,
    respond: r => ({
      existing_subdomains_count: num(r, 'subCount'),
      ...baseurlFields(r),
      existing_endpoints_count: num(r, 'endpointCount'),
    }),
  },
  GraphqlScan: {
    cypher: `${SCOPED_BASEURLS}
      WITH collect(DISTINCT b.url) AS baseurls
      ${SCOPED_ENDPOINTS}
      RETURN baseurls, count(DISTINCT e) AS endpointCount,
             count(DISTINCT CASE WHEN e.is_graphql = true THEN e END) AS graphqlEndpointCount`,
    respond: r => ({
      existing_subdomains_count: 0,
      ...baseurlFields(r),
      existing_endpoints_count: num(r, 'endpointCount'),
      existing_graphql_endpoints_count: num(r, 'graphqlEndpointCount'),
    }),
  },
  WebCachePoison: JS_TOOL,
  VhostSni: {
    cypher: `${DOMAINS}
      OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
      OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
      OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
      OPTIONAL MATCH (s)-[:HAS_BASE_URL|HAS_BASEURL]->(bu:BaseURL)
      WITH collect(DISTINCT s.name) AS subdomains,
           count(DISTINCT i) AS ipCount,
           count(DISTINCT p) AS portCount,
           count(DISTINCT bu) AS baseurlCount
      OPTIONAL MATCH (ed:ExternalDomain {user_id: $uid, project_id: $pid})
      RETURN subdomains, size(subdomains) AS subCount, ipCount, portCount, baseurlCount,
             count(DISTINCT ed) AS externalCount`,
    respond: r => ({
      ...subdomainFields(r),
      existing_ips_count: num(r, 'ipCount'),
      existing_ports_count: num(r, 'portCount'),
      existing_baseurls_count: num(r, 'baseurlCount'),
      existing_external_domains_count: num(r, 'externalCount'),
    }),
  },
  SubdomainTakeover: {
    cypher: `${DOMAINS}
      OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
      OPTIONAL MATCH (s)-[:HAS_BASE_URL|HAS_BASEURL]->(bu:BaseURL)
      WITH collect(DISTINCT s.name) AS subdomains, count(DISTINCT bu) AS baseurlCount
      RETURN subdomains, size(subdomains) AS subCount, baseurlCount`,
    respond: r => ({ ...subdomainFields(r), existing_baseurls_count: num(r, 'baseurlCount') }),
  },
  AiSurfaceRecon: {
    cypher: `${SCOPED_BASEURLS}
      WITH collect(DISTINCT b.url) AS baseurls
      ${SCOPED_ENDPOINTS}
      WITH baseurls,
           count(DISTINCT CASE WHEN (e.ai_interface_type IS NOT NULL AND e.ai_interface_type <> 'non-llm') OR e.is_ai_framework_detected = true THEN e END) AS aiEndpoints,
           count(DISTINCT CASE WHEN e.ai_interface_type = 'mcp' THEN e END) AS mcpEndpoints
      OPTIONAL MATCH (svc)-[:HAS_TECHNOLOGY|USES_TECHNOLOGY]->(t:Technology {category: 'ai-vector-db', user_id: $uid, project_id: $pid})
      RETURN baseurls, aiEndpoints, mcpEndpoints, count(DISTINCT svc) AS vectorDbServices`,
    respond: r => ({
      existing_subdomains_count: 0,
      ...baseurlFields(r),
      existing_ai_endpoints_count: num(r, 'aiEndpoints'),
      existing_mcp_endpoints_count: num(r, 'mcpEndpoints'),
      existing_vector_db_services_count: num(r, 'vectorDbServices'),
    }),
  },
  // Origin Discovery needs CDN-FRONTED hosts (from a prior HTTP probe), not just
  // any subdomain. frontedCount lets the modal block a run with nothing to
  // unmask (G7). Fronted = resolves to a CDN IP, or its BaseURL is CDN-flagged /
  // carries a favicon hash.
  OriginDiscovery: {
    cypher: `${DOMAINS}
      OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
      WITH collect(DISTINCT s.name) AS subdomains
      OPTIONAL MATCH (fd:Domain {user_id: $uid, project_id: $pid})-[:HAS_SUBDOMAIN]->(fs:Subdomain)
      WHERE fd.name IN $domains
        AND (EXISTS { (fs)-[:RESOLVES_TO]->(ci:IP) WHERE ci.is_cdn = true }
         OR EXISTS { (fs)-[:HAS_BASE_URL|HAS_BASEURL]->(:BaseURL)-[:HAS_ENDPOINT]->(ep:Endpoint)
                     WHERE ep.is_cdn = true OR ep.favicon_hash IS NOT NULL })
      RETURN subdomains, size(subdomains) AS subCount, count(DISTINCT fs) AS frontedCount`,
    respond: r => ({ ...subdomainFields(r), fronted_count: num(r, 'frontedCount') }),
  },
}

// One read of the project's Domain nodes: which roots exist, which have recon
// data, and which Domain nodes are left over from roots the project dropped.
const GRAPH_DOMAINS = `MATCH (d:Domain {user_id: $uid, project_id: $pid})
  RETURN d.name AS name,
         EXISTS { (d)-[:HAS_SUBDOMAIN]->(:Subdomain) } OR EXISTS { (d)-[:RESOLVES_TO]->(:IP) } AS hasData`

const ZERO_COUNTS = {
  existing_subdomains_count: 0,
  existing_ips_count: 0,
  existing_ports_count: 0,
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, toolId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: {
        userId: true, targetDomain: true, ipMode: true,
        domainBatchMode: true, domainBatchGroups: true,
      },
    })

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    const scope = resolveProjectRoots(project, projectId)
    const tool = TOOL_QUERIES[toolId]
    const withDiscovery = (fields: ReturnType<typeof partialScopeFields>) =>
      toolId === 'SubdomainDiscovery'
        ? { ...fields, discovery_domains: discoveryDomains(scope, fields.domains) }
        : fields

    if (tool) {
      try {
        const session = getGraphSession()
        try {
          const uid = project.userId
          const domainRows = await session.run(GRAPH_DOMAINS, { uid, pid: projectId })
          const graph: GraphDomainRow[] = domainRows.records
            .map((r: Neo4jRecord) => ({ name: String(r.get('name') ?? ''), hasData: r.get('hasData') === true }))
            .filter((row: GraphDomainRow) => row.name)
          const fields = partialScopeFields(scope, graph)

          const result = await session.run(tool.cypher, { uid, pid: projectId, domains: fields.domains })
          return NextResponse.json({
            ...withDiscovery(fields),
            ...tool.respond(result.records[0]),
            source: 'graph',
          })
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn(`Neo4j query failed for ${toolId} graph-inputs, falling back to settings:`, err)
      }
    }

    // Fallback: the project's own roots with zero counts. The orchestrator
    // re-derives the scope anyway, so offering the roots here is safe.
    return NextResponse.json({
      ...withDiscovery(partialScopeFields(scope, null)),
      ...ZERO_COUNTS,
      source: 'settings',
    })

  } catch (error) {
    console.error('Error getting graph inputs:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
