import { NextRequest, NextResponse } from 'next/server'
import { rowCap } from '../rowCap'
import { requirePermission } from '@/lib/authz/guards'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'
import { reportCountable } from '@/lib/triage/reportable'
import { DECLARED_ONLY } from '@/lib/declaredOnly'
import { deriveWebInitGrade, WEB_INIT_HEADER_CHECKS } from '@/app/graph/components/RedZoneTables/webInitGrade'
import { internalError } from '@/lib/routeErrors'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

// Vulnerability.type strings emitted by recon/helpers/security_checks.py
// for web-layer initial-access (auth + cookie + header hygiene + rate limiting).
const WEB_AUTH_TYPES = [
  'login_no_https',
  'basic_auth_no_tls',
  'session_no_secure',
  'session_no_httponly',
  'cache_control_missing',
  'csp_unsafe_inline',
  'insecure_form_action',
  'no_rate_limiting',
  'tls_expiring_soon',
]

// Header-hygiene Vulnerability.type strings (from SECURITY_HEADERS dict in security_checks.py)
const HEADER_HYGIENE_TYPES = [
  'missing_referrer_policy',
  'missing_permissions_policy',
  'missing_coop',
  'missing_corp',
  'missing_coep',
]

// Live Page Content checks (item 5) that are a way in by themselves: a console
// open without login, an install page anyone can complete. urlscan's history
// types stay out: this tab is the live state.
const OPEN_DOOR_TYPES = ['open_console', 'unfinished_installer']

const AUTH_CATEGORIES = ['auth', 'login', 'admin', 'authentication']

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'graph:read', { projectId })
  if (auth instanceof NextResponse) return auth
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getGraphSession()
  try {
    // Row = one BaseURL that either
    //   (a) hosts an Endpoint classified as auth/login/admin, OR
    //   (b) has a web-auth / header-hygiene security_check Vulnerability
    // Aggregates per-BaseURL: endpoint breakdown + linked vuln tags + security-header presence.
    //
    // A BaseURL is a thin service node: httpx writes the status, Server banner
    // and response headers onto the Endpoint it probed (graph_db http_mixin), so
    // they are read from there, the root path first. The BaseURL-level reads stay
    // for a graph written before that split. Each OPTIONAL MATCH is aggregated
    // before the next one so the endpoint, vuln and header rows never multiply.
    //
    // An auth endpoint known only from an API specification is documented, not
    // observed: it is counted apart as "declared" unless a finding sits on it,
    // and a declaration alone never makes a row.
    const result = await session.run(
      `MATCH (bu:BaseURL {project_id: $pid})
       OPTIONAL MATCH (bu)-[:HAS_ENDPOINT]->(ep:Endpoint)
         WHERE (
           ep.category IN $authCategories OR
           ep.path =~ '(?i).*/(login|signin|sign-in|admin|auth|authenticate|oauth|sso)(/|$|\\\\?).*'
         )
         AND (NOT ${DECLARED_ONLY('ep')} OR (ep)-[:HAS_VULNERABILITY]->())
       WITH bu, collect(DISTINCT ep) AS authEps
       OPTIONAL MATCH (bu)-[:HAS_ENDPOINT]->(dep:Endpoint)
         WHERE (
           dep.category IN $authCategories OR
           dep.path =~ '(?i).*/(login|signin|sign-in|admin|auth|authenticate|oauth|sso)(/|$|\\\\?).*'
         )
         AND ${DECLARED_ONLY('dep')} AND NOT (dep)-[:HAS_VULNERABILITY]->()
       WITH bu, authEps, count(DISTINCT dep) AS declaredAuthCount
       OPTIONAL MATCH (bu)-[:HAS_VULNERABILITY]->(v:Vulnerability)
         WHERE (v.type IN $allTypes OR v.vulnerability_type IN $allTypes OR v.name IN $allTypes)
           AND ${notMuted('v')} AND ${reportCountable('v')}
       WITH bu, authEps, declaredAuthCount, collect(DISTINCT coalesce(v.type, v.vulnerability_type, v.name)) AS vulnTags
       WHERE size(authEps) > 0 OR size([x IN vulnTags WHERE x IS NOT NULL]) > 0
       OPTIONAL MATCH (bu)-[:HAS_ENDPOINT]->(anyEp:Endpoint)
       WITH bu, authEps, declaredAuthCount, vulnTags, count(DISTINCT anyEp) AS totalEndpointCount
       OPTIONAL MATCH (bu)-[:HAS_ENDPOINT*0..1]->()-[:HAS_HEADER]->(h:Header)
         WHERE h.is_security_header = true
       WITH bu, authEps, declaredAuthCount, vulnTags, totalEndpointCount, collect(DISTINCT h.name) AS secHeaders
       OPTIONAL MATCH (bu)-[:HAS_ENDPOINT]->(probe:Endpoint)
         WHERE probe.status_code IS NOT NULL
       WITH bu, authEps, declaredAuthCount, vulnTags, totalEndpointCount, secHeaders, probe
       ORDER BY CASE WHEN probe.path = '/' THEN 0
                     WHEN probe.server IS NOT NULL THEN 1 ELSE 2 END, probe.path
       WITH bu, authEps, declaredAuthCount, vulnTags, totalEndpointCount, secHeaders, head(collect(probe)) AS probe
       OPTIONAL MATCH (sd:Subdomain)-[:HAS_BASE_URL]->(bu)
       RETURN toString(id(bu))                       AS nodeId,
              bu.url                                 AS baseUrl,
              bu.scheme                              AS scheme,
              coalesce(bu.status_code, probe.status_code) AS statusCode,
              coalesce(bu.server, probe.server)      AS server,
              sd.name                                AS subdomain,
              [e IN authEps | e.path]                AS authEndpointPaths,
              [e IN authEps | e.method]              AS authEndpointMethods,
              [e IN authEps WHERE e.category IS NOT NULL | e.category] AS authCategories,
              totalEndpointCount,
              size(authEps)                          AS authEndpointCount,
              declaredAuthCount,
              [x IN vulnTags WHERE x IS NOT NULL]    AS vulnTags,
              [h IN secHeaders WHERE h IS NOT NULL]  AS securityHeadersPresent,
              bu.updated_at                          AS updatedAt
       ORDER BY size([x IN vulnTags WHERE x IS NOT NULL]) DESC, size(authEps) DESC
       LIMIT ${rowCap()}`,
      {
        pid: projectId,
        authCategories: AUTH_CATEGORIES,
        allTypes: [...WEB_AUTH_TYPES, ...HEADER_HYGIENE_TYPES, ...OPEN_DOOR_TYPES],
      }
    )

    const rows = result.records.map(r => {
      const headersPresent = ((r.get('securityHeadersPresent') as string[]) || []).filter(Boolean)
      const vulnTags = ((r.get('vulnTags') as string[]) || []).filter(Boolean)
      const authPaths = (r.get('authEndpointPaths') as string[]) || []
      const authMethods = (r.get('authEndpointMethods') as string[]) || []
      const authCategoriesList = (r.get('authCategories') as string[]) || []

      const { grade, headerGrid } = deriveWebInitGrade(headersPresent, vulnTags)

      return {
        nodeId: (r.get('nodeId') as string | null) ?? null,
        baseUrl: (r.get('baseUrl') as string) || '',
        scheme: r.get('scheme') as string | null,
        statusCode: r.get('statusCode') != null ? toNum(r.get('statusCode')) : null,
        server: r.get('server') as string | null,
        subdomain: r.get('subdomain') as string | null,
        authEndpointPaths: authPaths,
        authEndpointMethods: authMethods,
        authCategories: authCategoriesList,
        authEndpointCount: toNum(r.get('authEndpointCount')),
        declaredAuthCount: toNum(r.get('declaredAuthCount')),
        totalEndpointCount: toNum(r.get('totalEndpointCount')),
        vulnTags,
        headerGrid,
        grade,
        updatedAt: (r.get('updatedAt') ?? null) as unknown,
      }
    })

    return NextResponse.json({ rows, meta: { totalRows: rows.length } })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Red-zone webInitAccess error' })
  } finally {
    await session.close()
  }
}
