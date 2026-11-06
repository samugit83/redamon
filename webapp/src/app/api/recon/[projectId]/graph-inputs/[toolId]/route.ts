import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { getGraphSession } from '@/app/api/graph/neo4j'
import {
  discoveryDomains,
  graphHostInScopeCypher,
  graphScopeParams,
  partialScopeFields,
  resolveProjectRoots,
  type GraphDomainRow,
} from '@/lib/partialReconScope'
import { findLegacyDomains } from '@/lib/legacyGraph'
import { notQuarantined } from '@/lib/graph/requestTargets'
import { internalError, safeErrorCode } from '@/lib/routeErrors'

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

/**
 * The scope part of every count, in one of two forms:
 *
 * - by graph scope (domain projects with scope groups): Domain nodes are orgs,
 *   so a host is counted when the positive §4.6 test admits it for the run's
 *   scan roots (graphHostInScopeCypher: an EXACT group's listed hosts, a root
 *   with Root on, strict subdomains of an ENUMERATE root, the longest root
 *   deciding). A removed scan root's hosts fail it, though they still hang off
 *   a current org Domain until the next full recon (§4.11.7).
 * - by Domain name (IP mode, or a row whose groups cannot be derived): the
 *   run's roots are Domain names, as before the org model.
 *
 * `domains` binds `d` (the Domains whose own IPs count: only a root that is
 * itself in scope); `subPath(tail)` binds `s` (plus `tail`'s variables);
 * `hostOk(expr)` tests a lower-cased host expression.
 */
interface ScopeCypher {
  domains: string
  subPath: (tail: string) => string
  hostOk: (host: string) => string
}

const BY_GRAPH_SCOPE: ScopeCypher = {
  domains: `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid}) WHERE ${graphHostInScopeCypher('toLower(d.name)')}`,
  subPath: tail => `OPTIONAL MATCH (s:Subdomain {user_id: $uid, project_id: $pid})${tail}
    WHERE ${graphHostInScopeCypher('toLower(s.name)')}`,
  hostOk: host => graphHostInScopeCypher(host),
}

function notUnderOtherDomain(host: string): string {
  return `NOT EXISTS {
    MATCH (od:Domain {user_id: $uid, project_id: $pid})
    WHERE NOT od.name IN $domains
      AND (${host} = toLower(od.name) OR ${host} ENDS WITH '.' + toLower(od.name))
  }`
}

const BY_DOMAIN_NAME: ScopeCypher = {
  domains: `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid}) WHERE d.name IN $domains`,
  subPath: tail => `OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)${tail}`,
  hostOk: notUnderOtherDomain,
}

const SUBDOMAIN_COUNT = (q: ScopeCypher) => `${q.domains}
  ${q.subPath('')}
  RETURN count(DISTINCT s) AS subdomainCount`

const SUBDOMAINS_AND_IPS = (q: ScopeCypher) => `${q.domains}
  ${q.subPath('-[:RESOLVES_TO]->(i:IP)')}
  OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
  WITH collect(DISTINCT s.name) AS subdomains,
       count(DISTINCT i) + count(DISTINCT di) AS ipCount
  RETURN subdomains, size(subdomains) AS subCount, ipCount`

// Same IP + Port shape as Nmap: tlsx grabs certs on already-open ports.
const PORTS = (q: ScopeCypher) => `${q.domains}
  ${q.subPath('-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)')}
  OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
  WITH collect(DISTINCT s.name) AS subdomains,
       count(DISTINCT i) + count(DISTINCT di) AS ipCount,
       count(DISTINCT p) + count(DISTINCT dp) AS portCount
  RETURN subdomains, size(subdomains) AS subCount, ipCount, portCount`

const SUBDOMAIN_LIST = (q: ScopeCypher) => `${q.domains}
  ${q.subPath('')}
  WITH collect(DISTINCT s.name) AS subdomains
  RETURN subdomains, size(subdomains) AS subCount`

// BaseURLs and Endpoints are project-wide: a BaseURL is not tied to a Domain
// node. The tools that read them skip a host outside the run's scope, so the
// counts skip it too.
const hostOfUrl = (url: string) => `split(split(split(${url}, '://')[1], '/')[0], ':')[0]`
const BASEURL_HOST = `toLower(coalesce(b.host, ${hostOfUrl('b.url')}))`

const SCOPED_BASEURLS = (q: ScopeCypher) => `OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
  WHERE ${q.hostOk(BASEURL_HOST)}`

// The tools that read Endpoints never request a quarantined one.
const SCOPED_ENDPOINTS = (q: ScopeCypher) => `OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
  WHERE ${q.hostOk(`toLower(${hostOfUrl('e.baseurl')})`)} AND ${notQuarantined('e')}`

const BASEURLS = (q: ScopeCypher) => `${SCOPED_BASEURLS(q)}
  RETURN collect(DISTINCT b.url) AS baseurls`

const BASEURLS_AND_ENDPOINTS = (q: ScopeCypher) => `${SCOPED_BASEURLS(q)}
  WITH collect(DISTINCT b.url) AS baseurls
  ${SCOPED_ENDPOINTS(q)}
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
  cypher: (q: ScopeCypher) => string
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

// Per-source OpenAPI status, one string per configured document, written on
// the org Domain of the scan root that fetched it
// ("<scan root>|<id>|<url hash>|<code>|<time>"; older runs: no scan root).
// The parser (openapiSourceStatus.ts) accepts both.
const OPENAPI_SOURCE_STATUS = `MATCH (d:Domain {user_id: $uid, project_id: $pid})
  WHERE d.openapi_source_status IS NOT NULL
  UNWIND d.openapi_source_status AS s
  RETURN collect(DISTINCT s) AS status`

async function openApiSourceStatus(session: { run: (q: string, p: Record<string, unknown>) => Promise<{ records: Neo4jRecord[] }> },
  uid: string, pid: string): Promise<string[] | null> {
  try {
    const result = await session.run(OPENAPI_SOURCE_STATUS, { uid, pid })
    return strings(result.records[0], 'status')
  } catch (err) {
    // Cosmetic: the form shows the status as unknown.
    console.warn('OpenAPI source status read failed:', err)
    return null
  }
}

const TOOL_QUERIES: Record<string, ToolQuery> = {
  SubdomainDiscovery: SUBDOMAIN_COUNT_TOOL,
  Urlscan: SUBDOMAIN_COUNT_TOOL,
  Uncover: SUBDOMAIN_COUNT_TOOL,
  Naabu: SUBDOMAINS_IPS_TOOL,
  Masscan: SUBDOMAINS_IPS_TOOL,
  Shodan: SUBDOMAINS_IPS_TOOL,
  OsintEnrichment: SUBDOMAINS_IPS_TOOL,
  IpAttribution: SUBDOMAINS_IPS_TOOL,
  Nmap: PORTS_TOOL,
  Tlsx: PORTS_TOOL,
  Katana: BASEURL_TOOL,
  OpenAPI: BASEURL_TOOL,
  Hakrawler: BASEURL_TOOL,
  Jsluice: BASEURL_TOOL,
  Ffuf: BASEURL_TOOL,
  Kiterunner: BASEURL_TOOL,
  JsRecon: JS_TOOL,
  SerializedScan: JS_TOOL,
  SupplyChainRecon: JS_TOOL,
  Gau: { cypher: SUBDOMAIN_LIST, respond: subdomainFields },
  ParamSpider: { cypher: SUBDOMAIN_LIST, respond: subdomainFields },
  ZapAjaxSpider: {
    cypher: q => `${SCOPED_BASEURLS(q)}
      WITH collect(DISTINCT b.url) AS baseurls
      OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
      WHERE ${q.hostOk(BASEURL_HOST)} AND ${notQuarantined('e')}
      RETURN baseurls, count(DISTINCT e) AS endpointCount`,
    respond: r => ({
      ...baseurlFields(r),
      existing_endpoints_count: num(r, 'endpointCount'),
      existing_subdomains_count: 0,
    }),
  },
  Arjun: {
    cypher: q => `${SCOPED_BASEURLS(q)}
      OPTIONAL MATCH (b)-[:HAS_ENDPOINT]->(e:Endpoint {user_id: $uid, project_id: $pid})
        WHERE ${notQuarantined('e')}
      WITH collect(DISTINCT b.url) AS baseurls, count(DISTINCT e) AS endpointCount
      RETURN baseurls, endpointCount`,
    respond: r => ({
      existing_subdomains_count: 0,
      ...baseurlFields(r),
      existing_endpoints_count: num(r, 'endpointCount'),
    }),
  },
  EndpointAiClassifier: {
    cypher: () => `OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
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
    cypher: q => `${q.domains}
      ${q.subPath('-[:RESOLVES_TO]->(i:IP)')}
      OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
      WITH collect(DISTINCT s.name) AS subdomains,
           count(DISTINCT i) + count(DISTINCT di) AS ipCount
      ${SCOPED_BASEURLS(q)}
      WITH subdomains, ipCount, collect(DISTINCT b.url) AS baseurls
      RETURN subdomains, size(subdomains) AS subCount, ipCount, baseurls`,
    respond: r => ({
      ...subdomainFields(r),
      existing_ips_count: num(r, 'ipCount'),
      ...baseurlFields(r),
    }),
  },
  Httpx: {
    cypher: q => `${q.domains}
      ${q.subPath('')}
      WITH collect(DISTINCT s.name) AS subdomains
      ${q.domains}
      ${q.subPath('-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)')}
      OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
      OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(:Service)-[:SERVES_URL]->(bu:BaseURL)
      OPTIONAL MATCH (dp)-[:RUNS_SERVICE]->(:Service)-[:SERVES_URL]->(dbu:BaseURL)
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
    cypher: q => `${q.domains}
      ${q.subPath('')}
      WITH count(DISTINCT s) AS subCount
      ${SCOPED_BASEURLS(q)}
      WITH subCount, collect(DISTINCT b.url) AS baseurls
      ${SCOPED_ENDPOINTS(q)}
      RETURN subCount, baseurls, count(DISTINCT e) AS endpointCount`,
    respond: r => ({
      existing_subdomains_count: num(r, 'subCount'),
      ...baseurlFields(r),
      existing_endpoints_count: num(r, 'endpointCount'),
    }),
  },
  GraphqlScan: {
    cypher: q => `${SCOPED_BASEURLS(q)}
      WITH collect(DISTINCT b.url) AS baseurls
      ${SCOPED_ENDPOINTS(q)}
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
  RouteExposure: JS_TOOL,
  VhostSni: {
    cypher: q => `${q.domains}
      ${q.subPath('')}
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
    cypher: q => `${q.domains}
      ${q.subPath('')}
      OPTIONAL MATCH (s)-[:HAS_BASE_URL|HAS_BASEURL]->(bu:BaseURL)
      WITH collect(DISTINCT s.name) AS subdomains, count(DISTINCT bu) AS baseurlCount
      RETURN subdomains, size(subdomains) AS subCount, baseurlCount`,
    respond: r => ({ ...subdomainFields(r), existing_baseurls_count: num(r, 'baseurlCount') }),
  },
  AiSurfaceRecon: {
    cypher: q => `${SCOPED_BASEURLS(q)}
      WITH collect(DISTINCT b.url) AS baseurls
      ${SCOPED_ENDPOINTS(q)}
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
    cypher: q => `${q.domains}
      ${q.subPath('')}
      RETURN collect(DISTINCT s.name) AS subdomains, count(DISTINCT s) AS subCount,
             count(DISTINCT CASE WHEN EXISTS { (s)-[:RESOLVES_TO]->(ci:IP) WHERE ci.is_cdn = true }
               OR EXISTS { (s)-[:HAS_BASE_URL|HAS_BASEURL]->(:BaseURL)-[:HAS_ENDPOINT]->(ep:Endpoint)
                           WHERE ep.is_cdn = true OR ep.favicon_hash IS NOT NULL } THEN s END) AS frontedCount`,
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
        userId: true, targetDomain: true, ipMode: true, subdomainList: true,
        domainBatchMode: true, domainBatchHosts: true,
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

    let graphFailure: unknown = null
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

          // Domain projects test hosts against the scope groups; IP mode (and a
          // row whose groups cannot be derived) matches the Domain by name.
          const byScope = scope.groups.length > 0
          const result = await session.run(tool.cypher(byScope ? BY_GRAPH_SCOPE : BY_DOMAIN_NAME), {
            uid, pid: projectId, domains: fields.domains,
            ...(byScope ? graphScopeParams(scope, fields.domains) : {}),
          })
          // Old-model Domain nodes (§4.11.6): the modal shows a banner and
          // disables Run, as the partial route refuses the start.
          const legacy = await findLegacyDomains(session, uid, projectId, scope.groups)
          return NextResponse.json({
            ...withDiscovery(fields),
            ...tool.respond(result.records[0]),
            legacy_graph: legacy,
            ...(toolId === 'OpenAPI'
              ? { openapiSourceStatus: await openApiSourceStatus(session, uid, projectId) }
              : {}),
            source: 'graph',
          })
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn(`Neo4j query failed for ${toolId} graph-inputs, falling back to settings:`, err)
        graphFailure = err
      }
    }

    // Fallback: the project's own roots with zero counts. The orchestrator
    // re-derives the scope anyway, so offering the roots here is safe. When the
    // graph could not be read, the zeros are unknown, not "nothing found", and
    // the flag lets the modal say so instead of "run Naabu first".
    return NextResponse.json({
      ...withDiscovery(partialScopeFields(scope, null)),
      ...ZERO_COUNTS,
      source: 'settings',
      ...(graphFailure ? { degraded: 'graph_unavailable', code: safeErrorCode(graphFailure) } : {}),
    })

  } catch (error) {
    return internalError(error, 'Failed to get graph inputs', { log: 'Error getting graph inputs' })
  }
}
