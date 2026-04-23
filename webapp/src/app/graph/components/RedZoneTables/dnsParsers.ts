/**
 * Parsers used by the DNS & Email Security Posture table to derive SPF strictness,
 * DMARC policy, and DNSSEC enablement from raw DNS record values + Domain.dnssec
 * property.
 */

export function extractSpfRecord(txtRecords: string[] | null | undefined): string | null {
  if (!txtRecords) return null
  for (const t of txtRecords) {
    if (typeof t !== 'string') continue
    if (t.toLowerCase().includes('v=spf1')) return t
  }
  return null
}

export function isSpfStrict(spfRecord: string | null): boolean {
  if (!spfRecord) return false
  return /(-all|~all)/i.test(spfRecord)
}

export function extractDmarcRecord(txtRecords: string[] | null | undefined): string | null {
  if (!txtRecords) return null
  for (const t of txtRecords) {
    if (typeof t !== 'string') continue
    if (t.toLowerCase().includes('v=dmarc1')) return t
  }
  return null
}

export function parseDmarcPolicy(dmarcRecord: string | null): string | null {
  if (!dmarcRecord) return null
  const match = dmarcRecord.match(/p\s*=\s*([a-z]+)/i)
  return match ? match[1].toLowerCase() : null
}

export function isDnssecEnabled(dnssec: string | null | undefined): boolean {
  if (dnssec === null || dnssec === undefined) return false
  const s = String(dnssec).toLowerCase().trim()
  if (s === '') return false
  // "unsigned", "not signed", "none" all indicate DNSSEC is not active
  return !['unsigned', 'not signed', 'none', 'off', 'false'].includes(s)
}

/**
 * Days from now to the given ISO date. Returns null when the input is unparseable
 * or missing. Negative values indicate the date is in the past.
 */
export function daysFromIso(iso: string | null | undefined): number | null {
  if (!iso) return null
  const d = new Date(iso)
  if (isNaN(d.getTime())) return null
  return Math.floor((d.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
}
