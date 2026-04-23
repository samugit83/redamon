import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getSession()
  try {
    // Cluster type 1: Certificate SAN overlap
    //   Each Certificate node has a `san` list -> all Subdomains listed in SAN share a single certificate.
    const certResult = await session.run(
      `MATCH (cert:Certificate {project_id: $pid})
       OPTIONAL MATCH (bu:BaseURL)-[:HAS_CERTIFICATE]->(cert)
       OPTIONAL MATCH (sd:Subdomain)-[:HAS_BASE_URL]->(bu)
       WITH cert,
            collect(DISTINCT bu.url) AS baseurls,
            collect(DISTINCT sd.name) AS directSubs
       WITH cert,
            [x IN baseurls WHERE x IS NOT NULL] AS baseurlsClean,
            [x IN (directSubs + coalesce(cert.san, [])) WHERE x IS NOT NULL] AS allHostsRaw
       WITH cert, baseurlsClean,
            reduce(acc = [], x IN allHostsRaw | CASE WHEN x IN acc THEN acc ELSE acc + [x] END) AS allHosts
       WHERE size(allHosts) >= 2
       RETURN 'certificate'                  AS clusterType,
              coalesce(cert.subject_cn, toString(id(cert))) AS clusterKey,
              cert.subject_cn                AS certCn,
              cert.issuer                    AS certIssuer,
              cert.not_after                 AS certNotAfter,
              cert.tls_version               AS tlsVersion,
              cert.cipher                    AS cipher,
              size(allHosts)                 AS hostCount,
              allHosts[0..25]                AS hosts,
              baseurlsClean[0..10]           AS baseurls,
              null                           AS asn,
              null                           AS country,
              null                           AS ipAddress
       ORDER BY size(allHosts) DESC
       LIMIT 200`,
      { pid: projectId }
    )

    // Cluster type 2: ASN grouping
    //   Subdomains resolving to IPs sharing the same ASN.
    const asnResult = await session.run(
      `MATCH (ip:IP {project_id: $pid})
       WHERE ip.asn IS NOT NULL AND ip.asn <> ''
       OPTIONAL MATCH (sd:Subdomain)-[:RESOLVES_TO]->(ip)
       WITH ip.asn AS asnKey,
            collect(DISTINCT ip.country)                           AS countries,
            collect(DISTINCT coalesce(ip.isp, ip.organization))    AS orgs,
            collect(DISTINCT ip.address)                           AS ipAddrs,
            collect(DISTINCT sd.name)                              AS subs
       WITH asnKey,
            [x IN countries WHERE x IS NOT NULL] AS countriesClean,
            [x IN orgs WHERE x IS NOT NULL]      AS orgsClean,
            [x IN ipAddrs WHERE x IS NOT NULL]   AS ipsClean,
            [x IN subs WHERE x IS NOT NULL]      AS subsClean
       WHERE size(subsClean) >= 2
       RETURN 'asn'                           AS clusterType,
              asnKey                          AS clusterKey,
              null                            AS certCn,
              null                            AS certIssuer,
              null                            AS certNotAfter,
              null                            AS tlsVersion,
              null                            AS cipher,
              size(subsClean)                 AS hostCount,
              subsClean[0..25]                AS hosts,
              ipsClean[0..10]                 AS baseurls,
              asnKey                          AS asn,
              countriesClean[0]               AS country,
              null                            AS ipAddress
       ORDER BY size(subsClean) DESC
       LIMIT 200`,
      { pid: projectId }
    )

    // Cluster type 3: Shared origin IP (>=2 subdomains pointing to same IP)
    const ipResult = await session.run(
      `MATCH (ip:IP {project_id: $pid})
       OPTIONAL MATCH (sd:Subdomain)-[:RESOLVES_TO]->(ip)
       WITH ip, collect(DISTINCT sd.name) AS subs
       WITH ip, [x IN subs WHERE x IS NOT NULL] AS subsClean
       WHERE size(subsClean) >= 2
       RETURN 'ip'                            AS clusterType,
              ip.address                      AS clusterKey,
              null                            AS certCn,
              null                            AS certIssuer,
              null                            AS certNotAfter,
              null                            AS tlsVersion,
              null                            AS cipher,
              size(subsClean)                 AS hostCount,
              subsClean[0..25]                AS hosts,
              []                              AS baseurls,
              ip.asn                          AS asn,
              ip.country                      AS country,
              ip.address                      AS ipAddress
       ORDER BY size(subsClean) DESC
       LIMIT 200`,
      { pid: projectId }
    )

    const mapRow = (r: any) => ({
      clusterType: r.get('clusterType') as string,
      clusterKey: (r.get('clusterKey') as string) || '',
      certCn: r.get('certCn') as string | null,
      certIssuer: r.get('certIssuer') as string | null,
      certNotAfter: r.get('certNotAfter') as string | null,
      tlsVersion: r.get('tlsVersion') as string | null,
      cipher: r.get('cipher') as string | null,
      hostCount: toNum(r.get('hostCount')),
      hosts: (r.get('hosts') as string[]) || [],
      baseurls: (r.get('baseurls') as string[]) || [],
      asn: r.get('asn') as string | null,
      country: r.get('country') as string | null,
      ipAddress: r.get('ipAddress') as string | null,
    })

    const rows = [
      ...certResult.records.map(mapRow),
      ...asnResult.records.map(mapRow),
      ...ipResult.records.map(mapRow),
    ].sort((a, b) => b.hostCount - a.hostCount)

    return NextResponse.json({
      rows,
      meta: {
        totalRows: rows.length,
        certClusters: rows.filter(r => r.clusterType === 'certificate').length,
        asnClusters: rows.filter(r => r.clusterType === 'asn').length,
        ipClusters: rows.filter(r => r.clusterType === 'ip').length,
      },
    })
  } catch (error) {
    console.error('Red-zone sharedInfra error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
