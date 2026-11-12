import { NextRequest, NextResponse } from 'next/server'
import { rowCap } from '../rowCap'
import { requirePermission } from '@/lib/authz/guards'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'
import { reportCountable } from '@/lib/triage/reportable'
import { internalError } from '@/lib/routeErrors'
import { currentDns } from '@/lib/graph/forwardDns'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

// Sensitive-port categories for network-layer initial-access targeting. Every
// port in ADMIN_PORTS, DATABASE_PORTS and KUBERNETES_API_PORTS of
// recon/helpers/security_checks.py is here (recon/tests/test_net_init_access_parity.py),
// except 443: the Kubernetes check only probes it, and categorising it would
// list every HTTPS service. The rest are management ports Python does not flag.
const PORT_CATEGORY: Record<number, string> = {
  22: 'ssh', 23: 'telnet', 3389: 'rdp', 5985: 'winrm', 5986: 'winrm',
  3306: 'database', 5432: 'database', 1433: 'database', 1521: 'database',
  27017: 'database', 27018: 'database', 6379: 'database', 9200: 'database',
  9300: 'database', 11211: 'database', 5984: 'database',
  2375: 'k8s', 2376: 'k8s', 10250: 'k8s', 6443: 'k8s', 8443: 'k8s',
  25: 'smtp', 465: 'smtp', 587: 'smtp',
  161: 'snmp', 623: 'ipmi', 445: 'smb', 139: 'smb', 5900: 'vnc', 5901: 'vnc',
}

// Vulnerability.type strings emitted by recon/helpers/security_checks.py
// for network-layer initial-access findings. MUST match the Python source.
const NET_VULN_TYPES = [
  'direct_ip_http', 'direct_ip_https', 'ip_api_exposed',
  'waf_bypass', 'admin_port_exposed', 'database_exposed',
  'redis_no_auth', 'kubernetes_api_exposed', 'smtp_open_relay',
]

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'graph:read', { projectId })
  if (auth instanceof NextResponse) return auth
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const sensitivePorts = Object.keys(PORT_CATEGORY).map(Number)

  const session = getGraphSession()
  try {
    // Part A: sensitive open ports (admin/db/mgmt/smtp/k8s etc.)
    const portResult = await session.run(
      `MATCH (ip:IP {project_id: $pid})-[:HAS_PORT]->(p:Port)
       WHERE p.number IN $ports
       OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(svc:Service)
       OPTIONAL MATCH (p)-[:HAS_TECHNOLOGY]->(t:Technology)
       OPTIONAL MATCH (sd:Subdomain)-[dnsr:RESOLVES_TO]->(ip) WHERE ${currentDns('dnsr')}
       OPTIONAL MATCH (ip)-[:HAS_VULNERABILITY]->(v:Vulnerability)
         WHERE (v.type IN $vulnTypes OR v.vulnerability_type IN $vulnTypes OR v.name IN $vulnTypes)
           AND ${notMuted('v')} AND ${reportCountable('v')}
       RETURN toString(id(p))       AS nodeId,
              'port'                AS origin,
              ip.address            AS ipAddress,
              p.number              AS port,
              p.protocol            AS protocol,
              svc.name              AS serviceName,
              svc.product           AS serviceProduct,
              svc.version           AS serviceVersion,
              collect(DISTINCT t.name + CASE WHEN t.version IS NULL THEN '' ELSE ' ' + t.version END) AS techs,
              collect(DISTINCT sd.name)[0..3] AS subdomains,
              collect(DISTINCT coalesce(v.type, v.vulnerability_type, v.name)) AS vulnTags,
              ip.is_cdn                               AS isCdn,
              ip.cdn_name                             AS cdnName,
              ip.asn                                  AS asn,
              ip.country                              AS country,
              coalesce(ip.isp, ip.organization)       AS isp,
              coalesce(p.updated_at, ip.updated_at)   AS updatedAt
       LIMIT ${rowCap()}`,
      { pid: projectId, ports: sensitivePorts, vulnTypes: NET_VULN_TYPES }
    )

    // Part B: IP-level security-check findings not already captured by port (e.g. waf_bypass)
    const vulnResult = await session.run(
      `MATCH (ip:IP {project_id: $pid})-[:HAS_VULNERABILITY]->(v:Vulnerability)
       WHERE (v.type IN $vulnTypes OR v.vulnerability_type IN $vulnTypes OR v.name IN $vulnTypes)
         AND ${notMuted('v')} AND ${reportCountable('v')}
       OPTIONAL MATCH (sd:Subdomain)-[dnsr:RESOLVES_TO]->(ip) WHERE ${currentDns('dnsr')}
       // Grouped on (ip, port, timestamp), not on v: in practice one
       // Vulnerability, but not by construction, and making v a grouping key
       // would split rows. Point at it when it is alone, at the IP otherwise.
       RETURN CASE count(DISTINCT v) WHEN 1 THEN toString(id(head(collect(v))))
                   ELSE toString(id(head(collect(ip)))) END AS nodeId,
              toString(id(head(collect(ip))))  AS ipNodeId,
              'vuln'                        AS origin,
              ip.address                    AS ipAddress,
              v.target_port                 AS port,
              'tcp'                         AS protocol,
              null                          AS serviceName,
              null                          AS serviceProduct,
              null                          AS serviceVersion,
              []                            AS techs,
              collect(DISTINCT sd.name)[0..3] AS subdomains,
              collect(DISTINCT coalesce(v.type, v.vulnerability_type, v.name)) AS vulnTags,
              ip.is_cdn                               AS isCdn,
              ip.cdn_name                             AS cdnName,
              ip.asn                                  AS asn,
              ip.country                              AS country,
              coalesce(ip.isp, ip.organization)       AS isp,
              coalesce(v.updated_at, ip.updated_at)   AS updatedAt
       LIMIT ${rowCap()}`,
      { pid: projectId, vulnTypes: NET_VULN_TYPES }
    )

    const mapRow = (r: any) => {
      const port = r.get('port') != null ? toNum(r.get('port')) : null
      const category = port != null ? PORT_CATEGORY[port] || null : null
      return {
        nodeId: (r.get('nodeId') as string | null) ?? null,
        origin: r.get('origin') as string,
        ipAddress: (r.get('ipAddress') as string) || '',
        port,
        protocol: (r.get('protocol') as string) || 'tcp',
        category,
        serviceName: r.get('serviceName') as string | null,
        serviceProduct: r.get('serviceProduct') as string | null,
        serviceVersion: r.get('serviceVersion') as string | null,
        techs: ((r.get('techs') as string[]) || []).filter(x => x && x.trim().length > 0),
        subdomains: (r.get('subdomains') as string[]) || [],
        vulnTags: ((r.get('vulnTags') as string[]) || []).filter(Boolean),
        isCdn: r.get('isCdn') as boolean | null,
        cdnName: r.get('cdnName') as string | null,
        asn: r.get('asn') as string | null,
        country: r.get('country') as string | null,
        isp: r.get('isp') as string | null,
        updatedAt: (r.get('updatedAt') ?? null) as unknown,
      }
    }

    const portRows = portResult.records.map(mapRow)
    // ipNodeId stays beside the row, not on it: it only decides a merge.
    const vulnRows = vulnResult.records.map(r => ({
      row: mapRow(r),
      ipNodeId: (r.get('ipNodeId') as string | null) ?? null,
    }))

    // Merge on (ip, port). Prefer port-row base; merge vuln tags.
    const keyOf = (r: any) => `${r.ipAddress}|${r.port ?? ''}`
    const merged = new Map<string, any>()
    const findingKeys = new Set<string>()
    for (const r of portRows) merged.set(keyOf(r), r)
    for (const { row: r, ipNodeId } of vulnRows) {
      const k = keyOf(r)
      const existing = merged.get(k)
      if (existing) {
        const tagSet = new Set<string>([...(existing.vulnTags || []), ...(r.vulnTags || [])])
        existing.vulnTags = Array.from(tagSet)
        // Two finding rows on one ip:port are several vulnerabilities on one
        // host, so the row is about the IP, as the Cypher already decides when
        // they share a timestamp. Keeping the first row's id would point at one
        // arbitrary finding, whichever Neo4j happened to return first.
        if (findingKeys.has(k)) existing.nodeId = ipNodeId
      } else {
        merged.set(k, r)
        findingKeys.add(k)
      }
    }

    const CRITICAL_TAGS = new Set(['waf_bypass', 'redis_no_auth', 'kubernetes_api_exposed', 'database_exposed'])
    const rows = Array.from(merged.values()).sort((a, b) => {
      const aCritical = (a.vulnTags || []).some((t: string) => CRITICAL_TAGS.has(t))
      const bCritical = (b.vulnTags || []).some((t: string) => CRITICAL_TAGS.has(t))
      if (aCritical !== bCritical) return aCritical ? -1 : 1
      return (b.vulnTags?.length || 0) - (a.vulnTags?.length || 0)
    })

    return NextResponse.json({ rows, meta: { totalRows: rows.length } })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Red-zone netInitAccess error' })
  } finally {
    await session.close()
  }
}
