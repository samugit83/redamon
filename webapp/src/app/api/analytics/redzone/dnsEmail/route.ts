import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'
import { reportCountable } from '@/lib/triage/reportable'
import {
  extractSpfRecord,
  isSpfStrict,
  extractDmarcRecord,
  parseDmarcPolicy,
  isDnssecEnabled,
  daysFromIso,
} from '@/app/graph/components/RedZoneTables/dnsParsers'
import { orgDomain } from '@/lib/publicSuffix'
import { internalError } from '@/lib/routeErrors'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

// Exact Vulnerability.type strings emitted by recon/helpers/security_checks.py
// for DNS + email-layer security findings.
const DNS_VULN_TYPES = [
  'spf_missing',
  'dmarc_missing',
  'dnssec_missing',
  'zone_transfer',
]

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'graph:read', { projectId })
  if (auth instanceof NextResponse) return auth
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getGraphSession()
  try {
    // One row per Domain, i.e. per org. DNS records attach to Subdomain (not
    // Domain) in domain_mixin, so the org apex's records are on the Subdomain
    // named like the Domain, which exists only when the apex was a target.
    // SPF/DMARC/DNSSEC findings are org-level and sit on the Domain itself.
    const result = await session.run(
      `MATCH (d:Domain {project_id: $pid})
       OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(apex:Subdomain {name: d.name})
       OPTIONAL MATCH (apex)-[:HAS_DNS_RECORD]->(dns:DNSRecord)
       OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
         WHERE (v.type IN $dnsTypes OR v.vulnerability_type IN $dnsTypes OR v.name IN $dnsTypes)
           AND ${notMuted('v')} AND ${reportCountable('v')}
       WITH d,
            collect(DISTINCT CASE WHEN dns.type = 'MX'  THEN dns.value END) AS mxVals,
            collect(DISTINCT CASE WHEN dns.type = 'NS'  THEN dns.value END) AS nsVals,
            collect(DISTINCT CASE WHEN dns.type = 'TXT' THEN dns.value END) AS txtVals,
            collect(DISTINCT CASE WHEN dns.type = 'SOA' THEN dns.value END) AS soaVals,
            collect(DISTINCT coalesce(v.type, v.vulnerability_type, v.name)) AS vulnTagsRaw,
            count(DISTINCT apex) > 0 AS apexResolved
       RETURN toString(id(d))                     AS nodeId,
              apexResolved                        AS apexResolved,
              d.name                              AS domain,
              d.dnssec                            AS dnssec,
              d.name_servers                      AS domainNameServers,
              d.whois_emails                      AS whoisEmails,
              d.registrar                         AS registrar,
              d.organization                      AS organization,
              d.country                           AS country,
              d.creation_date                     AS creationDate,
              d.expiration_date                   AS expirationDate,
              d.status                            AS registrarStatus,
              d.vt_malicious_count                AS vtMaliciousCount,
              d.vt_reputation                     AS vtReputation,
              d.otx_pulse_count                   AS otxPulseCount,
              [x IN mxVals  WHERE x IS NOT NULL]  AS mxRecords,
              [x IN nsVals  WHERE x IS NOT NULL]  AS nsRecords,
              [x IN txtVals WHERE x IS NOT NULL]  AS txtRecords,
              [x IN soaVals WHERE x IS NOT NULL]  AS soaRecords,
              [x IN vulnTagsRaw WHERE x IS NOT NULL] AS vulnTags,
              d.updated_at                        AS updatedAt
       ORDER BY d.name`,
      { pid: projectId, dnsTypes: DNS_VULN_TYPES }
    )

    const rows = result.records.map(r => {
      const txt = ((r.get('txtRecords') as string[]) || []).map(v => String(v))
      const mx = ((r.get('mxRecords') as string[]) || []).map(v => String(v))
      const ns = ((r.get('nsRecords') as string[]) || []).map(v => String(v))
      const dnssec = r.get('dnssec') as string | null
      const vulnTags = ((r.get('vulnTags') as string[]) || []).filter(Boolean)
      // An apex that was no target has no records to read: "not resolved",
      // never "missing". Its posture is the org-level findings alone.
      const apexResolved = r.get('apexResolved') !== false

      const spfRecord     = extractSpfRecord(txt)
      const dmarcRec      = extractDmarcRecord(txt)
      const dmarcPolicy   = parseDmarcPolicy(dmarcRec)
      const spfStrict     = isSpfStrict(spfRecord)
      const dnssecEnabled = isDnssecEnabled(dnssec)

      // Derive missing-flags from vuln tags OR from absence of records
      const spfMissing       = vulnTags.includes('spf_missing')     || (apexResolved && !spfRecord)
      const dmarcMissing     = vulnTags.includes('dmarc_missing')   || (apexResolved && !dmarcRec)
      const dnssecMissing    = vulnTags.includes('dnssec_missing')  || !dnssecEnabled
      const zoneTransferOpen = vulnTags.includes('zone_transfer')

      const nameServerCount = ns.length
      // Distinct NS providers by registrable domain: ns1.example.co.uk and
      // ns2.example.co.uk are one provider, not one per `co.uk`.
      const nsProviders = new Set(ns.map(n => {
        const host = n.toLowerCase().replace(/\.$/, '')
        return orgDomain(host) ?? host
      }))

      const whoisEmails   = (r.get('whoisEmails') as string[]) || []
      const expirationIso = r.get('expirationDate') as string | null
      const daysToExpiry  = daysFromIso(expirationIso)

      return {
        nodeId: (r.get('nodeId') as string | null) ?? null,
        domain: (r.get('domain') as string) || '',
        apexResolved,
        apexNote: apexResolved ? null : 'not resolved (apex not in scope)',
        spfPresent: apexResolved ? !!spfRecord : null,
        spfStrict: apexResolved ? spfStrict : null,
        spfRecord,
        dmarcPresent: apexResolved ? !!dmarcRec : null,
        dmarcPolicy,
        dnssec,
        dnssecEnabled,
        zoneTransferOpen,
        mxRecords: mx,
        mxCount: mx.length,
        nameServers: ns.length ? ns : ((r.get('domainNameServers') as string[]) || []),
        nameServerCount: Math.max(nameServerCount, ((r.get('domainNameServers') as string[]) || []).length),
        nsDistinctProviders: nsProviders.size || null,
        whoisEmails,
        registrar: r.get('registrar') as string | null,
        organization: r.get('organization') as string | null,
        country: r.get('country') as string | null,
        expirationDate: expirationIso,
        daysToExpiry,
        registrarStatus: (r.get('registrarStatus') as string[]) || [],
        vtMaliciousCount: r.get('vtMaliciousCount') != null ? toNum(r.get('vtMaliciousCount')) : null,
        vtReputation: r.get('vtReputation') != null ? toNum(r.get('vtReputation')) : null,
        otxPulseCount: r.get('otxPulseCount') != null ? toNum(r.get('otxPulseCount')) : null,
        vulnTags,
        spfMissing,
        dmarcMissing,
        dnssecMissing,
        updatedAt: (r.get('updatedAt') ?? null) as unknown,
      }
    })

    return NextResponse.json({ rows, meta: { totalRows: rows.length } })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Red-zone dnsEmail error' })
  } finally {
    await session.close()
  }
}
