import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

// Sensitive-port categories for network-layer initial-access targeting.
// Keep in sync with recon/helpers/security_checks.py port lists.
const PORT_CATEGORY: Record<number, string> = {
  22: 'ssh', 23: 'telnet', 3389: 'rdp', 5985: 'winrm', 5986: 'winrm',
  3306: 'database', 5432: 'database', 1433: 'database', 27017: 'database',
  6379: 'database', 9200: 'database', 11211: 'database', 5984: 'database',
  2375: 'k8s', 2376: 'k8s', 10250: 'k8s', 6443: 'k8s', 8443: 'k8s',
  25: 'smtp', 465: 'smtp', 587: 'smtp',
  161: 'snmp', 623: 'ipmi', 445: 'smb', 139: 'smb', 5900: 'vnc',
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
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const sensitivePorts = Object.keys(PORT_CATEGORY).map(Number)

  const session = getSession()
  try {
    // Part A: sensitive open ports (admin/db/mgmt/smtp/k8s etc.)
    const portResult = await session.run(
      `MATCH (ip:IP {project_id: $pid})-[:HAS_PORT]->(p:Port)
       WHERE p.number IN $ports
       OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(svc:Service)
       OPTIONAL MATCH (p)-[:HAS_TECHNOLOGY]->(t:Technology)
       OPTIONAL MATCH (sd:Subdomain)-[:RESOLVES_TO]->(ip)
       OPTIONAL MATCH (ip)-[:HAS_VULNERABILITY]->(v:Vulnerability)
         WHERE v.type IN $vulnTypes OR v.vulnerability_type IN $vulnTypes OR v.name IN $vulnTypes
       RETURN 'port'                AS origin,
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
              coalesce(ip.isp, ip.organization)       AS isp
       LIMIT 500`,
      { pid: projectId, ports: sensitivePorts, vulnTypes: NET_VULN_TYPES }
    )

    // Part B: IP-level security-check findings not already captured by port (e.g. waf_bypass)
    const vulnResult = await session.run(
      `MATCH (ip:IP {project_id: $pid})-[:HAS_VULNERABILITY]->(v:Vulnerability)
       WHERE v.type IN $vulnTypes OR v.vulnerability_type IN $vulnTypes OR v.name IN $vulnTypes
       OPTIONAL MATCH (sd:Subdomain)-[:RESOLVES_TO]->(ip)
       RETURN 'vuln'                        AS origin,
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
              coalesce(ip.isp, ip.organization)       AS isp
       LIMIT 500`,
      { pid: projectId, vulnTypes: NET_VULN_TYPES }
    )

    const mapRow = (r: any) => {
      const port = r.get('port') != null ? toNum(r.get('port')) : null
      const category = port != null ? PORT_CATEGORY[port] || null : null
      return {
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
      }
    }

    const portRows = portResult.records.map(mapRow)
    const vulnRows = vulnResult.records.map(mapRow)

    // Merge on (ip, port). Prefer port-row base; merge vuln tags.
    const keyOf = (r: any) => `${r.ipAddress}|${r.port ?? ''}`
    const merged = new Map<string, any>()
    for (const r of portRows) merged.set(keyOf(r), r)
    for (const r of vulnRows) {
      const k = keyOf(r)
      const existing = merged.get(k)
      if (existing) {
        const tagSet = new Set<string>([...(existing.vulnTags || []), ...(r.vulnTags || [])])
        existing.vulnTags = Array.from(tagSet)
      } else {
        merged.set(k, r)
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
    console.error('Red-zone netInitAccess error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
