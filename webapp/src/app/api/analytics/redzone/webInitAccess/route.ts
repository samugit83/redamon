import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'
import { deriveWebInitGrade, WEB_INIT_HEADER_CHECKS } from '@/app/graph/components/RedZoneTables/webInitGrade'

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

const AUTH_CATEGORIES = ['auth', 'login', 'admin', 'authentication']

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getSession()
  try {
    // Row = one BaseURL that either
    //   (a) hosts an Endpoint classified as auth/login/admin, OR
    //   (b) has a web-auth / header-hygiene security_check Vulnerability
    // Aggregates per-BaseURL: endpoint breakdown + linked vuln tags + security-header presence.
    const result = await session.run(
      `MATCH (bu:BaseURL {project_id: $pid})
       OPTIONAL MATCH (bu)-[:HAS_ENDPOINT]->(ep:Endpoint)
         WHERE (
           ep.category IN $authCategories OR
           ep.path =~ '(?i).*/(login|signin|sign-in|admin|auth|authenticate|oauth|sso)(/|$|\\\\?).*'
         )
       OPTIONAL MATCH (bu)-[:HAS_ENDPOINT]->(anyEp:Endpoint)
       OPTIONAL MATCH (bu)-[:HAS_VULNERABILITY]->(v:Vulnerability)
         WHERE v.type IN $allTypes OR v.vulnerability_type IN $allTypes OR v.name IN $allTypes
       OPTIONAL MATCH (bu)-[:HAS_HEADER]->(h:Header)
         WHERE h.is_security_header = true
       OPTIONAL MATCH (sd:Subdomain)-[:HAS_BASE_URL]->(bu)
       WITH bu, sd,
            collect(DISTINCT ep) AS authEps,
            collect(DISTINCT anyEp) AS allEps,
            collect(DISTINCT h.name) AS secHeaders,
            collect(DISTINCT coalesce(v.type, v.vulnerability_type, v.name)) AS vulnTags
       WHERE size(authEps) > 0 OR size([x IN vulnTags WHERE x IS NOT NULL]) > 0
       RETURN bu.url                                 AS baseUrl,
              bu.scheme                              AS scheme,
              bu.status_code                         AS statusCode,
              bu.server                              AS server,
              sd.name                                AS subdomain,
              [e IN authEps | e.path]                AS authEndpointPaths,
              [e IN authEps | e.method]              AS authEndpointMethods,
              [e IN authEps WHERE e.category IS NOT NULL | e.category] AS authCategories,
              size(allEps)                           AS totalEndpointCount,
              size(authEps)                          AS authEndpointCount,
              [x IN vulnTags WHERE x IS NOT NULL]    AS vulnTags,
              [h IN secHeaders WHERE h IS NOT NULL]  AS securityHeadersPresent
       ORDER BY size([x IN vulnTags WHERE x IS NOT NULL]) DESC, size(authEps) DESC
       LIMIT 500`,
      {
        pid: projectId,
        authCategories: AUTH_CATEGORIES,
        allTypes: [...WEB_AUTH_TYPES, ...HEADER_HYGIENE_TYPES],
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
        baseUrl: (r.get('baseUrl') as string) || '',
        scheme: r.get('scheme') as string | null,
        statusCode: r.get('statusCode') != null ? toNum(r.get('statusCode')) : null,
        server: r.get('server') as string | null,
        subdomain: r.get('subdomain') as string | null,
        authEndpointPaths: authPaths,
        authEndpointMethods: authMethods,
        authCategories: authCategoriesList,
        authEndpointCount: toNum(r.get('authEndpointCount')),
        totalEndpointCount: toNum(r.get('totalEndpointCount')),
        vulnTags,
        headerGrid,
        grade,
      }
    })

    return NextResponse.json({ rows, meta: { totalRows: rows.length } })
  } catch (error) {
    console.error('Red-zone webInitAccess error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
