import { NextRequest, NextResponse } from 'next/server'
import { rowCap } from '../rowCap'
import { requirePermission } from '@/lib/authz/guards'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { internalError } from '@/lib/routeErrors'
import { currentDns } from '@/lib/graph/forwardDns'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'graph:read', { projectId })
  if (auth instanceof NextResponse) return auth
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getGraphSession()
  try {
    // Domain-side hits: VT/OTX/CriminalIP reputation, ThreatPulse / Malware edges
    const domainResult = await session.run(
      `MATCH (d:Domain {project_id: $pid})
       OPTIONAL MATCH (d)-[:APPEARS_IN_PULSE]->(pulse:ThreatPulse)
       OPTIONAL MATCH (d)-[:ASSOCIATED_WITH_MALWARE]->(m:Malware)
       WITH d,
            collect(DISTINCT pulse.name)              AS pulseNames,
            collect(DISTINCT pulse.adversary)         AS pulseAdversaries,
            count(DISTINCT pulse)                     AS pulseCount,
            collect(DISTINCT m.hash)                  AS malwareHashes,
            count(DISTINCT m)                         AS malwareCount
       WHERE d.vt_malicious_count > 0
          OR d.otx_pulse_count > 0
          OR d.criminalip_abuse_count > 0
          OR size([x IN d.vt_tags WHERE x IS NOT NULL]) > 0
          OR pulseCount > 0
          OR malwareCount > 0
       RETURN toString(id(d))                             AS nodeId,
              'Domain'                                    AS assetType,
              d.name                                      AS asset,
              d.vt_malicious_count                        AS vtMaliciousCount,
              d.vt_suspicious_count                       AS vtSuspiciousCount,
              d.vt_reputation                             AS vtReputation,
              d.vt_tags                                   AS vtTags,
              d.vt_last_analysis_date                     AS vtLastAnalysisDate,
              d.vt_jarm                                   AS vtJarm,
              d.otx_pulse_count                           AS otxPulseCount,
              d.otx_url_count                             AS otxUrlCount,
              d.otx_adversaries                           AS otxAdversaries,
              d.otx_malware_families                      AS otxMalwareFamilies,
              d.otx_tlp                                   AS otxTlp,
              d.otx_attack_ids                            AS otxAttackIds,
              d.criminalip_risk_grade                     AS criminalipRiskGrade,
              d.criminalip_abuse_count                    AS criminalipAbuseCount,
              d.criminalip_current_service                AS criminalipCurrentService,
              [x IN pulseNames WHERE x IS NOT NULL]       AS pulseNames,
              [x IN pulseAdversaries WHERE x IS NOT NULL] AS pulseAdversaries,
              pulseCount                                  AS pulseCount,
              [x IN malwareHashes WHERE x IS NOT NULL]    AS malwareHashes,
              malwareCount                                AS malwareCount,
              d.updated_at                                AS updatedAt
       ORDER BY pulseCount DESC, vtMaliciousCount DESC, criminalipAbuseCount DESC
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    // IP-side hits: VT/OTX/CriminalIP, plus pulse/malware edges
    const ipResult = await session.run(
      `MATCH (ip:IP {project_id: $pid})
       OPTIONAL MATCH (ip)-[:APPEARS_IN_PULSE]->(pulse:ThreatPulse)
       OPTIONAL MATCH (ip)-[:ASSOCIATED_WITH_MALWARE]->(m:Malware)
       OPTIONAL MATCH (sd:Subdomain)-[dnsr:RESOLVES_TO]->(ip) WHERE ${currentDns('dnsr')}
       WITH ip,
            collect(DISTINCT sd.name)                 AS subdomains,
            collect(DISTINCT pulse.name)              AS pulseNames,
            collect(DISTINCT pulse.adversary)         AS pulseAdversaries,
            count(DISTINCT pulse)                     AS pulseCount,
            collect(DISTINCT m.hash)                  AS malwareHashes,
            count(DISTINCT m)                         AS malwareCount
       WHERE ip.vt_malicious_count > 0
          OR ip.otx_pulse_count > 0
          OR ip.criminalip_score_inbound IS NOT NULL
          OR ip.criminalip_is_tor = true
          OR ip.criminalip_is_proxy = true
          OR ip.criminalip_is_vpn = true
          OR ip.criminalip_is_darkweb = true
          OR size([x IN ip.vt_tags WHERE x IS NOT NULL]) > 0
          OR pulseCount > 0
          OR malwareCount > 0
       RETURN toString(id(ip))                             AS nodeId,
              'IP'                                         AS assetType,
              ip.address                                   AS asset,
              ip.vt_malicious_count                        AS vtMaliciousCount,
              ip.vt_suspicious_count                       AS vtSuspiciousCount,
              ip.vt_reputation                             AS vtReputation,
              ip.vt_tags                                   AS vtTags,
              ip.vt_last_analysis_date                     AS vtLastAnalysisDate,
              ip.vt_jarm                                   AS vtJarm,
              ip.otx_pulse_count                           AS otxPulseCount,
              ip.otx_url_count                             AS otxUrlCount,
              ip.otx_adversaries                           AS otxAdversaries,
              ip.otx_malware_families                      AS otxMalwareFamilies,
              ip.otx_tlp                                   AS otxTlp,
              ip.otx_attack_ids                            AS otxAttackIds,
              ip.criminalip_score_inbound                  AS criminalipScoreInbound,
              ip.criminalip_is_tor                         AS criminalipIsTor,
              ip.criminalip_is_proxy                       AS criminalipIsProxy,
              ip.criminalip_is_vpn                         AS criminalipIsVpn,
              ip.criminalip_is_darkweb                     AS criminalipIsDarkweb,
              ip.criminalip_is_hosting                     AS criminalipIsHosting,
              ip.criminalip_is_scanner                     AS criminalipIsScanner,
              ip.criminalip_country                        AS criminalipCountry,
              [x IN subdomains WHERE x IS NOT NULL]        AS subdomains,
              [x IN pulseNames WHERE x IS NOT NULL]        AS pulseNames,
              [x IN pulseAdversaries WHERE x IS NOT NULL]  AS pulseAdversaries,
              pulseCount                                   AS pulseCount,
              [x IN malwareHashes WHERE x IS NOT NULL]     AS malwareHashes,
              malwareCount                                 AS malwareCount,
              ip.updated_at                                AS updatedAt
       ORDER BY pulseCount DESC, vtMaliciousCount DESC
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    const mapDomainRow = (r: any) => ({
      nodeId: (r.get('nodeId') as string | null) ?? null,
      assetType: r.get('assetType') as string,
      asset: (r.get('asset') as string) || '',
      vtMaliciousCount: r.get('vtMaliciousCount') != null ? toNum(r.get('vtMaliciousCount')) : null,
      vtSuspiciousCount: r.get('vtSuspiciousCount') != null ? toNum(r.get('vtSuspiciousCount')) : null,
      vtReputation: r.get('vtReputation') != null ? toNum(r.get('vtReputation')) : null,
      vtTags: (r.get('vtTags') as string[]) || [],
      vtLastAnalysisDate: r.get('vtLastAnalysisDate') != null ? toNum(r.get('vtLastAnalysisDate')) : null,
      vtJarm: r.get('vtJarm') as string | null,
      otxPulseCount: toNum(r.get('otxPulseCount')),
      otxUrlCount: r.get('otxUrlCount') != null ? toNum(r.get('otxUrlCount')) : null,
      otxAdversaries: (r.get('otxAdversaries') as string[]) || [],
      otxMalwareFamilies: (r.get('otxMalwareFamilies') as string[]) || [],
      otxTlp: r.get('otxTlp') as string | null,
      otxAttackIds: (r.get('otxAttackIds') as string[]) || [],
      criminalipRiskGrade: r.get('criminalipRiskGrade') as string | null,
      criminalipAbuseCount: r.get('criminalipAbuseCount') != null ? toNum(r.get('criminalipAbuseCount')) : null,
      criminalipCurrentService: r.get('criminalipCurrentService') as string | null,
      // IP-specific (null for domain rows)
      criminalipScoreInbound: null,
      criminalipIsTor: null,
      criminalipIsProxy: null,
      criminalipIsVpn: null,
      criminalipIsDarkweb: null,
      criminalipIsHosting: null,
      criminalipIsScanner: null,
      criminalipCountry: null,
      subdomains: [] as string[],
      pulseNames: (r.get('pulseNames') as string[]) || [],
      pulseAdversaries: (r.get('pulseAdversaries') as string[]) || [],
      pulseCount: toNum(r.get('pulseCount')),
      malwareHashes: (r.get('malwareHashes') as string[]) || [],
      malwareCount: toNum(r.get('malwareCount')),
      updatedAt: (r.get('updatedAt') ?? null) as unknown,
    })

    const mapIpRow = (r: any) => ({
      nodeId: (r.get('nodeId') as string | null) ?? null,
      assetType: r.get('assetType') as string,
      asset: (r.get('asset') as string) || '',
      vtMaliciousCount: r.get('vtMaliciousCount') != null ? toNum(r.get('vtMaliciousCount')) : null,
      vtSuspiciousCount: r.get('vtSuspiciousCount') != null ? toNum(r.get('vtSuspiciousCount')) : null,
      vtReputation: r.get('vtReputation') != null ? toNum(r.get('vtReputation')) : null,
      vtTags: (r.get('vtTags') as string[]) || [],
      vtLastAnalysisDate: r.get('vtLastAnalysisDate') != null ? toNum(r.get('vtLastAnalysisDate')) : null,
      vtJarm: r.get('vtJarm') as string | null,
      otxPulseCount: toNum(r.get('otxPulseCount')),
      otxUrlCount: r.get('otxUrlCount') != null ? toNum(r.get('otxUrlCount')) : null,
      otxAdversaries: (r.get('otxAdversaries') as string[]) || [],
      otxMalwareFamilies: (r.get('otxMalwareFamilies') as string[]) || [],
      otxTlp: r.get('otxTlp') as string | null,
      otxAttackIds: (r.get('otxAttackIds') as string[]) || [],
      // Domain-specific (null for IP rows)
      criminalipRiskGrade: null,
      criminalipAbuseCount: null,
      criminalipCurrentService: null,
      criminalipScoreInbound: r.get('criminalipScoreInbound') != null ? toNum(r.get('criminalipScoreInbound')) : null,
      criminalipIsTor: r.get('criminalipIsTor') as boolean | null,
      criminalipIsProxy: r.get('criminalipIsProxy') as boolean | null,
      criminalipIsVpn: r.get('criminalipIsVpn') as boolean | null,
      criminalipIsDarkweb: r.get('criminalipIsDarkweb') as boolean | null,
      criminalipIsHosting: r.get('criminalipIsHosting') as boolean | null,
      criminalipIsScanner: r.get('criminalipIsScanner') as boolean | null,
      criminalipCountry: r.get('criminalipCountry') as string | null,
      subdomains: (r.get('subdomains') as string[]) || [],
      pulseNames: (r.get('pulseNames') as string[]) || [],
      pulseAdversaries: (r.get('pulseAdversaries') as string[]) || [],
      pulseCount: toNum(r.get('pulseCount')),
      malwareHashes: (r.get('malwareHashes') as string[]) || [],
      malwareCount: toNum(r.get('malwareCount')),
      updatedAt: (r.get('updatedAt') ?? null) as unknown,
    })

    // BaseURL-side hits: supply-chain incident correlation (A2). A different
    // claim from the two arms above, and the edge type is what keeps them
    // apart: APPEARS_IN_PULSE means "this asset of mine is named in the report",
    // CONTACTS_MALICIOUS_HOST means "my target reached out to a third-party host
    // that a published incident names".
    const contactResult = await session.run(
      `MATCH (u:BaseURL {project_id: $pid})-[c:CONTACTS_MALICIOUS_HOST]->(tp:ThreatPulse)
       // The row is an edge; the id points at its asset, as in the other two
       // arms. The incident is one CONTACTS_MALICIOUS_HOST hop from it.
       RETURN toString(id(u))              AS nodeId,
              'BaseURL'                    AS assetType,
              u.url                        AS asset,
              c.matched_host               AS contactedHost,
              c.evidence                   AS contactEvidence,
              tp.name                      AS incidentTitle,
              tp.sca_incident_id           AS incidentId,
              tp.sca_incident_url          AS incidentUrl,
              tp.sca_status                AS incidentStatus,
              tp.sca_summary               AS incidentSummary,
              tp.sca_feed_revised          AS incidentFeedRevised,
              coalesce(tp.tags, [])        AS incidentVectors,
              coalesce(u.updated_at, tp.updated_at) AS updatedAt
       ORDER BY u.url, c.matched_host
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    // Same row shape as the other two arms with the VT/OTX/CriminalIP columns
    // null, so the table renders one uniform grid and the per-column filter
    // engine sees every key.
    const mapContactRow = (r: any) => ({
      nodeId: (r.get('nodeId') as string | null) ?? null,
      assetType: r.get('assetType') as string,
      asset: (r.get('asset') as string) || '',
      vtMaliciousCount: null, vtSuspiciousCount: null, vtReputation: null,
      vtTags: [] as string[], vtLastAnalysisDate: null, vtJarm: null,
      otxPulseCount: 0, otxUrlCount: null,
      otxAdversaries: [] as string[], otxMalwareFamilies: [] as string[],
      otxTlp: null, otxAttackIds: [] as string[],
      criminalipRiskGrade: null, criminalipAbuseCount: null,
      criminalipCurrentService: null, criminalipScoreInbound: null,
      criminalipIsTor: null, criminalipIsProxy: null, criminalipIsVpn: null,
      criminalipIsDarkweb: null, criminalipIsHosting: null,
      criminalipIsScanner: null, criminalipCountry: null,
      subdomains: [] as string[],
      pulseNames: [(r.get('incidentTitle') as string) || ''].filter(Boolean),
      // Left empty on purpose: the incident feed carries no threat-actor field,
      // and this column feeds an adversary roll-up elsewhere.
      pulseAdversaries: [] as string[],
      pulseCount: 1,
      malwareHashes: [] as string[], malwareCount: 0,
      contactedHost: (r.get('contactedHost') as string) || null,
      contactEvidence: (r.get('contactEvidence') as string) || null,
      incidentId: (r.get('incidentId') as string) || null,
      incidentUrl: (r.get('incidentUrl') as string) || null,
      incidentStatus: (r.get('incidentStatus') as string) || null,
      incidentSummary: (r.get('incidentSummary') as string) || null,
      incidentFeedRevised: (r.get('incidentFeedRevised') as string) || null,
      incidentVectors: (r.get('incidentVectors') as string[]) || [],
      updatedAt: (r.get('updatedAt') ?? null) as unknown,
    })

    const rows = [
      ...domainResult.records.map(mapDomainRow),
      ...ipResult.records.map(mapIpRow),
      ...contactResult.records.map(mapContactRow),
    ].sort((a, b) => {
      if (a.pulseCount !== b.pulseCount) return b.pulseCount - a.pulseCount
      return (b.vtMaliciousCount || 0) - (a.vtMaliciousCount || 0)
    })

    return NextResponse.json({
      rows,
      meta: {
        totalRows: rows.length,
        domainCount: domainResult.records.length,
        ipCount: ipResult.records.length,
        contactCount: contactResult.records.length,
      },
    })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Red-zone threatIntel error' })
  } finally {
    await session.close()
  }
}
