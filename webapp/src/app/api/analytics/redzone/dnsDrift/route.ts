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
    // Surface owned domains with either:
    //   - HISTORICALLY_RESOLVED_TO edges to IPs (from OTX passive DNS), or
    //   - HAS_EXTERNAL_DOMAIN edges to foreign domains seen redirecting
    //   - Any dangling Subdomain (no DNS, no_http) belonging to the domain
    const result = await session.run(
      `MATCH (d:Domain {project_id: $pid})
       OPTIONAL MATCH (d)-[rel:HISTORICALLY_RESOLVED_TO]->(ipHist:IP)
       OPTIONAL MATCH (d)-[:HAS_EXTERNAL_DOMAIN]->(ext:ExternalDomain)
       OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(sd:Subdomain)
         WHERE sd.has_dns_records = false OR sd.status = 'no_http'
       OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(anySd:Subdomain)-[:RESOLVES_TO]->(currentIp:IP)
       WITH d,
            collect(DISTINCT {
              address: ipHist.address,
              asn: ipHist.asn,
              country: ipHist.country,
              firstSeen: rel.first_seen,
              lastSeen: rel.last_seen,
              recordType: rel.record_type
            }) AS historicResolutions,
            collect(DISTINCT currentIp.address) AS currentIps,
            collect(DISTINCT currentIp.asn)     AS currentAsns,
            collect(DISTINCT currentIp.country) AS currentCountries,
            collect(DISTINCT {
              domain: ext.domain,
              sources: ext.sources,
              timesSeen: ext.times_seen,
              countriesSeen: ext.countries_seen,
              firstSeenAt: ext.first_seen_at,
              redirectFromUrls: ext.redirect_from_urls
            }) AS externalDomains,
            collect(DISTINCT sd.name)           AS danglingSubs
       WITH d, historicResolutions, currentIps, currentAsns, currentCountries, externalDomains, danglingSubs,
            [x IN historicResolutions WHERE x.address IS NOT NULL]  AS historicResolutionsClean,
            [x IN externalDomains     WHERE x.domain  IS NOT NULL]  AS externalDomainsClean,
            [x IN currentIps          WHERE x IS NOT NULL]          AS currentIpsClean,
            [x IN currentAsns         WHERE x IS NOT NULL]          AS currentAsnsClean,
            [x IN currentCountries    WHERE x IS NOT NULL]          AS currentCountriesClean,
            [x IN danglingSubs        WHERE x IS NOT NULL]          AS danglingSubsClean
       WHERE size(historicResolutionsClean) > 0
          OR size(externalDomainsClean) > 0
          OR size(danglingSubsClean) > 0
       RETURN d.name                         AS domain,
              historicResolutionsClean       AS historicResolutions,
              size(historicResolutionsClean) AS historicIpCount,
              currentIpsClean                AS currentIps,
              currentAsnsClean               AS currentAsns,
              currentCountriesClean          AS currentCountries,
              externalDomainsClean           AS externalDomains,
              size(externalDomainsClean)     AS externalDomainCount,
              danglingSubsClean              AS danglingSubs,
              size(danglingSubsClean)        AS danglingSubCount
       ORDER BY
         size(historicResolutionsClean) + size(externalDomainsClean) + size(danglingSubsClean) DESC,
         d.name
       LIMIT 500`,
      { pid: projectId }
    )

    const rows = result.records.map(r => {
      const historicResolutions = ((r.get('historicResolutions') as any[]) || []).map(h => ({
        address: h.address as string | null,
        asn: h.asn as string | null,
        country: h.country as string | null,
        firstSeen: h.firstSeen as string | null,
        lastSeen: h.lastSeen as string | null,
        recordType: h.recordType as string | null,
      }))

      const externalDomains = ((r.get('externalDomains') as any[]) || []).map(e => ({
        domain: e.domain as string,
        sources: (e.sources as string[]) || [],
        timesSeen: e.timesSeen != null ? toNum(e.timesSeen) : null,
        countriesSeen: (e.countriesSeen as string[]) || [],
        firstSeenAt: e.firstSeenAt as string | null,
        redirectFromUrls: (e.redirectFromUrls as string[]) || [],
      }))

      // ASN / country drift: historic vs current
      const currentIps = (r.get('currentIps') as string[]) || []
      const currentAsns = (r.get('currentAsns') as string[]) || []
      const currentCountries = (r.get('currentCountries') as string[]) || []

      const historicAsns = new Set(historicResolutions.map(h => h.asn).filter(Boolean) as string[])
      const currentAsnSet = new Set(currentAsns)
      const asnDrift = Array.from(historicAsns).filter(a => !currentAsnSet.has(a))

      const historicCountries = new Set(historicResolutions.map(h => h.country).filter(Boolean) as string[])
      const currentCountrySet = new Set(currentCountries)
      const countryDrift = Array.from(historicCountries).filter(c => !currentCountrySet.has(c))

      // Most-recent historic resolution timestamp
      const lastSeenDates = historicResolutions
        .map(h => (h.lastSeen ? new Date(h.lastSeen).getTime() : null))
        .filter((x): x is number => x != null && !isNaN(x))
      const lastResolutionDate = lastSeenDates.length > 0
        ? new Date(Math.max(...lastSeenDates)).toISOString()
        : null

      return {
        domain: (r.get('domain') as string) || '',
        historicIpCount: toNum(r.get('historicIpCount')),
        historicResolutions,
        currentIps,
        currentAsns,
        currentCountries,
        asnDrift,
        countryDrift,
        externalDomains,
        externalDomainCount: toNum(r.get('externalDomainCount')),
        danglingSubs: (r.get('danglingSubs') as string[]) || [],
        danglingSubCount: toNum(r.get('danglingSubCount')),
        lastResolutionDate,
      }
    })

    return NextResponse.json({ rows, meta: { totalRows: rows.length } })
  } catch (error) {
    console.error('Red-zone dnsDrift error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
