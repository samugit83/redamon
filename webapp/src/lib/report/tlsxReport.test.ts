/** @vitest-environment node */
/**
 * Strategy row 4 (L1): the TLS certificate posture section must not be silently
 * empty when certificates exist.
 *
 * "Silently empty" is the exact bug class this whole feature exists to fix: the
 * certificate-health block in the customer report was permanently 0/0/0 because
 * every reader queried an anchor no writer wrote. A report section that renders
 * nothing looks identical to a project with no certificates, so nobody notices.
 *
 * Behavioural: calls renderTlsx and asserts the produced HTML, rather than
 * regex-matching the template source.
 *
 * Run: npx vitest run src/lib/report/tlsxReport.test.ts
 */
import { describe, test, expect } from 'vitest'
import { renderTlsx } from './reportTemplate'
import type { ReportData, TlsCertificateRecord } from './reportData'

function cert(over: Partial<TlsCertificateRecord> = {}): TlsCertificateRecord {
  return {
    subjectCn: 'mail.acme.com', issuer: "CN=R3, O=Let's Encrypt", sanCount: 3,
    notAfter: '2027-01-01T00:00:00Z', expired: false, selfSigned: false,
    mismatched: false, wildcard: false, source: 'tlsx', ...over,
  }
}

function data(tlsx: Partial<ReportData['tlsx']>): ReportData {
  return {
    tlsx: {
      totalCertificates: 0, expired: 0, selfSigned: 0, mismatched: 0,
      wildcard: 0, expiringSoon: 0, topIssuers: [], findings: [], ...tlsx,
    },
  } as unknown as ReportData
}

describe('renderTlsx — TLS certificate posture section', () => {
  test('renders nothing when the project has no certificates', () => {
    expect(renderTlsx(data({ totalCertificates: 0 }))).toBe('')
  })

  test('renders a populated section when certificates exist', () => {
    const html = renderTlsx(data({
      totalCertificates: 4, expired: 1, selfSigned: 1, mismatched: 0,
      wildcard: 2, expiringSoon: 1,
      topIssuers: [{ issuer: "CN=R3, O=Let's Encrypt", count: 3 }],
      findings: [cert(), cert({ subjectCn: 'imap.acme.com', expired: true })],
    }))
    expect(html).not.toBe('')
    expect(html).toContain('id="tls-certificates"')
    expect(html).toContain('TLS Certificate Posture')
    // the counts an operator actually reads
    expect(html).toContain('<strong>4</strong>')
    expect(html).toContain('mail.acme.com')
    expect(html).toContain('imap.acme.com')
  })

  test('posture problems are badged so an operator can see them', () => {
    const html = renderTlsx(data({
      totalCertificates: 1,
      findings: [cert({ expired: true, selfSigned: true, mismatched: true, wildcard: true })],
    }))
    expect(html).toContain('expired')
    expect(html).toContain('self-signed')
    expect(html).toContain('mismatch')
    expect(html).toContain('wildcard')
  })

  test('a healthy certificate carries no posture badge', () => {
    const html = renderTlsx(data({ totalCertificates: 1, findings: [cert()] }))
    expect(html).not.toContain('>expired<')
    expect(html).not.toContain('>self-signed<')
  })

  test('an empty Subject CN renders a placeholder, not a blank cell', () => {
    const html = renderTlsx(data({ totalCertificates: 1, findings: [cert({ subjectCn: null })] }))
    expect(html).toContain('(no CN)')
  })

  test('the 50-item cap is disclosed rather than silently truncating', () => {
    const many = Array.from({ length: 50 }, (_, i) => cert({ subjectCn: `h${i}.acme.com` }))
    const html = renderTlsx(data({ totalCertificates: 120, findings: many }))
    expect(html).toContain('Showing first 50')
  })
})
