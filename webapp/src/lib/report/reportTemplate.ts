/**
 * Report Template — generates self-contained HTML pentest reports.
 *
 * 14 sections: Cover, TOC, Executive Summary, Scope & Methodology,
 * Risk Summary, Findings (remediations), Vulnerability Details,
 * Attack Surface, CVE Intelligence, GitHub Secrets, Attack Chains,
 * Network Topology, Recommendations, Appendix.
 */

import type { ReportData, VulnFinding, CveChain, ExploitRecord } from './reportData'

// ── Narrative types (from LLM summarizer) ──────────────────────────────────

export interface LLMNarratives {
  executiveSummary: string
  scopeNarrative: string
  riskNarrative: string
  findingsNarrative: string
  attackSurfaceNarrative: string
  recommendationsNarrative: string
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function esc(s: string | null | undefined): string {
  if (!s) return ''
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function sevColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return '#dc2626'
    case 'high': return '#ea580c'
    case 'medium': return '#d97706'
    case 'low': return '#2563eb'
    case 'info': case 'informational': return '#6b7280'
    default: return '#6b7280'
  }
}

function sevBg(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return '#fef2f2'
    case 'high': return '#fff7ed'
    case 'medium': return '#fffbeb'
    case 'low': return '#eff6ff'
    default: return '#f9fafb'
  }
}

function sevBadge(severity: string): string {
  const s = severity?.toLowerCase() || 'unknown'
  return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;color:#fff;background:${sevColor(s)}">${esc(s)}</span>`
}

function riskScoreColor(score: number): string {
  if (score >= 80) return '#e53935'
  if (score >= 60) return '#f97316'
  if (score >= 40) return '#f59e0b'
  if (score >= 20) return '#3b82f6'
  return '#22c55e'
}

function riskScoreBadge(score: number, label: string): string {
  const bg = riskScoreColor(score)
  return `<span style="display:inline-block;padding:4px 16px;border-radius:6px;font-size:14px;font-weight:700;text-transform:uppercase;color:#fff;background:${bg}">${score}/100 ${esc(label)}</span>`
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
  } catch { return iso }
}

/** Logarithmic normalization (same as SecurityPostureRadar.tsx) */
function logNorm(value: number, scale: number): number {
  if (value <= 0) return 0
  return Math.min(100, Math.round(scale * Math.log(value + 1)))
}

/** CSS horizontal bar gauge */
function cssBarGauge(pct: number, label?: string): string {
  const clamped = Math.max(0, Math.min(100, pct))
  const color = clamped >= 80 ? '#22c55e' : clamped >= 40 ? '#f59e0b' : '#dc2626'
  const txt = label || `${Math.round(clamped)}%`
  return `<div style="background:#e2e8f0;border-radius:4px;height:18px;width:100%;position:relative;overflow:hidden">
    <div style="background:${color};border-radius:4px;height:100%;width:${clamped}%"></div>
    <span style="position:absolute;top:1px;left:8px;font-size:11px;font-weight:600;color:#1a1a1a">${txt}</span>
  </div>`
}

/** CSS bar gauge with custom color (inverted — red = high) */
function cssBarGaugeRisk(pct: number, label?: string): string {
  const clamped = Math.max(0, Math.min(100, pct))
  const color = clamped >= 50 ? '#dc2626' : clamped >= 25 ? '#f59e0b' : clamped >= 10 ? '#d97706' : '#3b82f6'
  const txt = label || `${Math.round(clamped)}%`
  return `<div style="background:#e2e8f0;border-radius:4px;height:18px;width:100%;position:relative;overflow:hidden">
    <div style="background:${color};border-radius:4px;height:100%;width:${clamped}%"></div>
    <span style="position:absolute;top:1px;left:8px;font-size:11px;font-weight:600;color:#1a1a1a">${txt}</span>
  </div>`
}

/** Compute 6-axis Security Posture scores (same as SecurityPostureRadar.tsx) */
function computePostureScores(data: ReportData): { metric: string; value: number; raw: number; detail: string }[] {
  const { graphOverview, attackSurface, vulnerabilities, cveIntelligence, attackChains } = data

  // Attack Surface
  const openPorts = attackSurface.ports.reduce((s, p) => s + p.count, 0)
  const techCount = attackSurface.technologies.length
  const attackSurfaceRaw = graphOverview.subdomainStats.total + graphOverview.infrastructureStats.totalIps
    + openPorts + graphOverview.endpointCoverage.baseUrls + graphOverview.endpointCoverage.endpoints
    + graphOverview.endpointCoverage.parameters + techCount

  // Vuln Density
  const totalVulns = vulnerabilities.severityDistribution.reduce((s, d) => s + d.count, 0)
  const totalCves = data.metrics.totalCves
  const secretsCount = cveIntelligence.githubSecrets.secrets + cveIntelligence.githubSecrets.sensitiveFiles + data.secrets.total + data.trufflehog.totalFindings
  const chainFindingsCount = attackChains.totalChainFindings
  const vulnDensityRaw = totalVulns + totalCves + secretsCount + chainFindingsCount + data.jsRecon.totalFindings

  // Exploitability
  const gvmExploits = cveIntelligence.exploits.length
  const kevCount = cveIntelligence.exploits.filter(e => e.cisaKev).length
  const cvesWithCapec = new Set(cveIntelligence.cveChains.filter(c => c.capecId).map(c => c.cveId)).size
  const exploitRaw = gvmExploits + attackChains.exploitSuccesses.length + kevCount + cvesWithCapec

  // Cert Health
  const certTotal = graphOverview.certificateHealth.total
  const certHealthy = Math.max(0, certTotal - graphOverview.certificateHealth.expired - graphOverview.certificateHealth.expiringSoon)
  const certScore = certTotal > 0 ? Math.round((certHealthy / certTotal) * 100) : 0

  // Injectable %
  const totalParams = attackSurface.parameterAnalysis.reduce((s, p) => s + p.total, 0)
  const injectableParams = attackSurface.parameterAnalysis.reduce((s, p) => s + p.injectable, 0)
  const injectableScore = totalParams > 0 ? Math.round((injectableParams / totalParams) * 100) : 0

  // Security Headers (weighted)
  const SEC_HEADERS: [string, number][] = [
    ['strict-transport-security', 3], ['content-security-policy', 3],
    ['x-frame-options', 2], ['x-content-type-options', 2],
    ['x-xss-protection', 1], ['referrer-policy', 1], ['permissions-policy', 1],
  ]
  const totalBaseUrls = graphOverview.endpointCoverage.baseUrls
  let secHeaderScore = 0
  if (totalBaseUrls > 0 && attackSurface.securityHeaders.length) {
    const headerMap = new Map(attackSurface.securityHeaders.map(h => [h.name.toLowerCase(), h.count]))
    const totalWeight = SEC_HEADERS.reduce((s, [, w]) => s + w, 0)
    const weightedSum = SEC_HEADERS.reduce((sum, [hdr, weight]) => {
      const coverage = Math.min((headerMap.get(hdr) || 0) / totalBaseUrls, 1)
      return sum + weight * coverage
    }, 0)
    secHeaderScore = Math.round((weightedSum / totalWeight) * 100)
  }

  return [
    { metric: 'Attack Surface', value: logNorm(attackSurfaceRaw, 13), raw: attackSurfaceRaw, detail: `${graphOverview.subdomainStats.total} subs, ${graphOverview.infrastructureStats.totalIps} IPs, ${openPorts} ports` },
    { metric: 'Vuln Density', value: logNorm(vulnDensityRaw, 15), raw: vulnDensityRaw, detail: `${totalVulns} vulns, ${totalCves} CVEs` },
    { metric: 'Exploitability', value: logNorm(exploitRaw, 25), raw: exploitRaw, detail: `${gvmExploits} GVM, ${attackChains.exploitSuccesses.length} chain, ${kevCount} KEV` },
    { metric: 'Cert Health', value: certScore, raw: certHealthy, detail: `${certHealthy}/${certTotal} healthy` },
    { metric: 'Injectable', value: injectableScore, raw: injectableParams, detail: `${injectableParams}/${totalParams} params` },
    { metric: 'Sec Headers', value: secHeaderScore, raw: secHeaderScore, detail: `weighted coverage` },
  ]
}

/** Render inline SVG radar chart for Security Posture */
function renderSecurityPostureRadar(data: ReportData): string {
  const axes = computePostureScores(data)
  if (axes.every(a => a.value === 0 && a.raw === 0)) return ''

  const cx = 200, cy = 160, maxR = 120
  const n = axes.length
  const angleStep = (2 * Math.PI) / n
  const startAngle = -Math.PI / 2 // top

  function polarToXY(angle: number, radius: number): [number, number] {
    return [cx + radius * Math.cos(angle), cy + radius * Math.sin(angle)]
  }

  // Grid rings
  const rings = [25, 50, 75, 100]
  const gridRings = rings.map(pct => {
    const r = (pct / 100) * maxR
    const points = Array.from({ length: n }, (_, i) => {
      const [x, y] = polarToXY(startAngle + i * angleStep, r)
      return `${x.toFixed(1)},${y.toFixed(1)}`
    }).join(' ')
    return `<polygon points="${points}" fill="none" stroke="#e2e8f0" stroke-width="1" />`
  }).join('\n    ')

  // Axis lines
  const axisLines = axes.map((_, i) => {
    const [x, y] = polarToXY(startAngle + i * angleStep, maxR)
    return `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" stroke="#e2e8f0" stroke-width="1" />`
  }).join('\n    ')

  // Data polygon
  const dataPoints = axes.map((a, i) => {
    const r = (a.value / 100) * maxR
    const [x, y] = polarToXY(startAngle + i * angleStep, r)
    return `${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')

  // Score dots
  const dots = axes.map((a, i) => {
    const r = (a.value / 100) * maxR
    const [x, y] = polarToXY(startAngle + i * angleStep, r)
    return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="4" fill="#3b82f6" />`
  }).join('\n    ')

  // Labels
  const labels = axes.map((a, i) => {
    const [x, y] = polarToXY(startAngle + i * angleStep, maxR + 24)
    const anchor = x < cx - 10 ? 'end' : x > cx + 10 ? 'start' : 'middle'
    return `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" text-anchor="${anchor}" font-size="11" fill="#475569" font-weight="600">${esc(a.metric)} (${a.value})</text>`
  }).join('\n    ')

  // Legend table
  const legendRows = axes.map(a => {
    const barColor = a.value >= 70 ? '#dc2626' : a.value >= 40 ? '#f59e0b' : a.value >= 20 ? '#3b82f6' : '#22c55e'
    // For Cert Health and Sec Headers, higher = better, so invert color
    const isPositive = a.metric === 'Cert Health' || a.metric === 'Sec Headers'
    const color = isPositive
      ? (a.value >= 80 ? '#22c55e' : a.value >= 40 ? '#f59e0b' : '#dc2626')
      : barColor
    return `<tr>
      <td style="font-weight:600">${esc(a.metric)}</td>
      <td style="width:60px;text-align:right;font-weight:700;color:${color}">${a.value}%</td>
      <td style="color:#64748b;font-size:11px">${esc(a.detail)}</td>
    </tr>`
  }).join('')

  return `
  <div style="display:flex;align-items:center;gap:32px;flex-wrap:wrap;margin:24px 0">
    <svg width="400" height="340" viewBox="0 0 400 340" style="flex-shrink:0">
      ${gridRings}
      ${axisLines}
      <polygon points="${dataPoints}" fill="rgba(59,130,246,0.15)" stroke="#3b82f6" stroke-width="2" />
      ${dots}
      ${labels}
    </svg>
    <table class="data-table" style="flex:1;min-width:260px">
      <thead><tr><th>Metric</th><th>Score</th><th>Detail</th></tr></thead>
      <tbody>${legendRows}</tbody>
    </table>
  </div>`
}

/** Render Security Headers Gap Analysis */
function renderSecurityHeadersGap(data: ReportData): string {
  const totalBaseUrls = data.graphOverview.endpointCoverage.baseUrls
  if (totalBaseUrls === 0) return ''

  const SEC_HEADERS: { name: string; label: string; weight: number }[] = [
    { name: 'strict-transport-security', label: 'HSTS', weight: 3 },
    { name: 'content-security-policy', label: 'CSP', weight: 3 },
    { name: 'x-frame-options', label: 'X-Frame-Options', weight: 2 },
    { name: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 2 },
    { name: 'x-xss-protection', label: 'X-XSS-Protection', weight: 1 },
    { name: 'referrer-policy', label: 'Referrer-Policy', weight: 1 },
    { name: 'permissions-policy', label: 'Permissions-Policy', weight: 1 },
  ]

  const headerMap = new Map(data.attackSurface.securityHeaders.map(h => [h.name.toLowerCase(), h.count]))
  const totalWeight = SEC_HEADERS.reduce((s, h) => s + h.weight, 0)

  let weightedSum = 0
  const rows = SEC_HEADERS.map(h => {
    const count = headerMap.get(h.name) || 0
    const pct = Math.round(Math.min(count / totalBaseUrls, 1) * 100)
    weightedSum += h.weight * Math.min(count / totalBaseUrls, 1)
    const priorityLabel = h.weight === 3 ? 'Critical' : h.weight === 2 ? 'High' : 'Low'
    const priorityColor = h.weight === 3 ? '#dc2626' : h.weight === 2 ? '#ea580c' : '#64748b'
    return `<tr>
      <td style="font-weight:600">${esc(h.label)}</td>
      <td><span style="color:${priorityColor};font-size:10px;font-weight:600">${priorityLabel}</span></td>
      <td>${count} / ${totalBaseUrls}</td>
      <td style="width:40%">${cssBarGauge(pct)}</td>
    </tr>`
  }).join('')

  const overallScore = Math.round((weightedSum / totalWeight) * 100)

  return `
  <h3>Security Headers Coverage</h3>
  <p style="margin-bottom:12px">Overall weighted score: <strong style="font-size:16px;color:${overallScore >= 80 ? '#22c55e' : overallScore >= 40 ? '#f59e0b' : '#dc2626'}">${overallScore}%</strong>
    <span style="color:#64748b;font-size:11px"> across ${totalBaseUrls} base URLs</span></p>
  <table class="data-table">
    <thead><tr><th>Header</th><th>Priority</th><th>Coverage</th><th>Deployment</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`
}

/** Render CISA KEV callout */
function renderCisaKevCallout(data: ReportData): string {
  const kevExploits = data.cveIntelligence.exploits.filter(e => e.cisaKev)
  if (kevExploits.length === 0) return ''

  const total = data.cveIntelligence.exploits.length
  const pct = total > 0 ? Math.round((kevExploits.length / total) * 100) : 0

  const rows = kevExploits.map(e => `
    <tr style="background:#fef2f2">
      <td style="font-weight:600">${esc(e.name)}</td>
      <td>${e.cvssScore != null ? e.cvssScore.toFixed(1) : '—'}</td>
      <td>${esc(e.targetIp || '—')}${e.targetPort ? `:${e.targetPort}` : ''}</td>
      <td>${e.cveIds.length > 0 ? e.cveIds.map(id => esc(id)).join(', ') : '—'}</td>
    </tr>`).join('')

  return `
  <div style="background:#fef2f2;border:2px solid #dc2626;border-radius:8px;padding:16px 20px;margin-bottom:24px">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
      <span style="background:#dc2626;color:#fff;padding:4px 12px;border-radius:4px;font-size:13px;font-weight:700">CISA KEV</span>
      <span style="font-size:14px;font-weight:600;color:#991b1b">${kevExploits.length} of ${total} exploits are in the CISA Known Exploited Vulnerabilities catalog</span>
    </div>
    <div style="margin-bottom:12px">${cssBarGaugeRisk(pct, `${kevExploits.length}/${total} (${pct}%)`)}</div>
    <table class="data-table" style="margin-bottom:0">
      <thead><tr><th>Exploit</th><th>CVSS</th><th>Target</th><th>CVEs</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`
}

/** Render Injectable Parameters Breakdown */
function renderInjectableBreakdown(data: ReportData): string {
  const params = data.attackSurface.parameterAnalysis
  if (params.length === 0) return ''

  const totalParams = params.reduce((s, p) => s + p.total, 0)
  const totalInjectable = params.reduce((s, p) => s + p.injectable, 0)
  if (totalParams === 0) return ''

  const overallPct = Math.round((totalInjectable / totalParams) * 100)
  const summaryColor = overallPct >= 25 ? '#dc2626' : overallPct >= 10 ? '#ea580c' : overallPct > 0 ? '#d97706' : '#22c55e'

  const rows = params.map(p => {
    const pct = p.total > 0 ? Math.round((p.injectable / p.total) * 100) : 0
    const highlight = pct > 10
    return `<tr${highlight ? ' style="background:#fef2f2"' : ''}>
      <td style="font-weight:600;text-transform:capitalize">${esc(p.position)}</td>
      <td>${p.total}</td>
      <td style="color:${p.injectable > 0 ? '#dc2626' : 'inherit'};font-weight:${p.injectable > 0 ? '600' : '400'}">${p.injectable}</td>
      <td style="width:35%">${cssBarGaugeRisk(pct)}</td>
    </tr>`
  }).join('')

  return `
  <h3>Injectable Parameters</h3>
  <p style="margin-bottom:12px">
    <strong style="font-size:16px;color:${summaryColor}">${totalInjectable}</strong>
    <span style="color:#64748b"> of ${totalParams} parameters (${overallPct}%) are injectable</span>
  </p>
  <div style="margin-bottom:12px">${cssBarGaugeRisk(overallPct, `${totalInjectable} injectable / ${totalParams} total (${overallPct}%)`)}</div>
  <table class="data-table">
    <thead><tr><th>Position</th><th>Total</th><th>Injectable</th><th>Rate</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`
}

/** Render Attack Flow Chains (Tech → CVE → CWE → CAPEC) */
function renderAttackFlowChains(data: ReportData): string {
  const chains = data.cveIntelligence.cveChains.filter(c => c.cweId)
  if (chains.length === 0) return ''

  // Deduplicate by CVE ID, keep highest CVSS
  const uniqueByCve = new Map<string, CveChain>()
  for (const c of chains) {
    const existing = uniqueByCve.get(c.cveId)
    if (!existing || (c.cvss ?? 0) > (existing.cvss ?? 0)) {
      uniqueByCve.set(c.cveId, c)
    }
  }

  const sorted = Array.from(uniqueByCve.values())
    .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
    .slice(0, 15)

  const arrow = '<td style="color:#94a3b8;text-align:center;font-size:16px;padding:4px 2px;overflow:hidden">&#x2192;</td>'

  const rows = sorted.map(c => {
    const cvssColor = (c.cvss ?? 0) >= 9 ? '#dc2626' : (c.cvss ?? 0) >= 7 ? '#ea580c' : (c.cvss ?? 0) >= 4 ? '#d97706' : '#3b82f6'
    return `<tr>
      <td style="font-weight:600">${esc(c.tech)}${c.techVersion ? ` <span style="color:#64748b">${esc(c.techVersion)}</span>` : ''}</td>
      ${arrow}
      <td><span style="font-family:monospace;font-size:11px">${esc(c.cveId)}</span> <span style="color:${cvssColor};font-weight:700">(${c.cvss != null ? Number(c.cvss).toFixed(1) : '?'})</span></td>
      ${arrow}
      <td>${esc(c.cweId || '')}${c.cweName ? `: ${esc(c.cweName)}` : ''}</td>
      ${arrow}
      <td>${c.capecId ? `${esc(c.capecId)}${c.capecName ? `: ${esc(c.capecName)}` : ''}` : '<span style="color:#94a3b8">—</span>'}</td>
    </tr>`
  }).join('')

  return `
  <h3>Attack Flow Chains (${sorted.length})</h3>
  <p style="color:#64748b;font-size:12px;margin-bottom:8px">Complete attack paths: Technology → CVE → CWE → CAPEC, sorted by CVSS score</p>
  <table class="data-table" style="table-layout:fixed;font-size:11.5px">
    <colgroup>
      <col style="width:18%"><col style="width:3%"><col style="width:22%"><col style="width:3%"><col style="width:24%"><col style="width:3%"><col style="width:27%">
    </colgroup>
    <thead>
      <tr><th>Technology</th><th></th><th>CVE (CVSS)</th><th></th><th>CWE</th><th></th><th>CAPEC</th></tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>`
}

// ── Main Generator ──────────────────────────────────────────────────────────

export function generateReportHtml(data: ReportData, narratives: LLMNarratives | null): string {
  const { project, metrics } = data
  const n = narratives || {} as Partial<LLMNarratives>
  const projectName = project.name || 'Security Assessment'
  const targetDomain = project.targetDomain || 'N/A'
  const generatedAt = formatDate(data.generatedAt)

  // RoE fields (optional)
  const clientName = (project as any).roeClientName || ''
  const engagementType = (project as any).roeEngagementType || ''

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(projectName)} — Penetration Test Report</title>
<style>
${CSS_STYLES}
</style>
</head>
<body>

${renderCover(projectName, targetDomain, generatedAt, clientName, engagementType, metrics.riskScore, metrics.riskLabel)}
${renderTOC(data)}
${renderExecutiveSummary(data, n.executiveSummary)}
${renderScope(data, n.scopeNarrative)}
${renderRiskSummary(data, n.riskNarrative)}
${renderFindings(data, n.findingsNarrative)}
${renderVulnerabilityDetails(data)}
${renderAttackSurface(data, n.attackSurfaceNarrative)}
${renderCveIntelligence(data)}
${renderGithubSecrets(data)}
${renderTrufflehog(data)}
${renderSecrets(data)}
${renderJsRecon(data)}
${renderGraphqlScan(data)}
${renderOtx(data)}
${renderAttackChains(data)}
${renderFireteams(data)}
${renderRecommendations(data, n.recommendationsNarrative)}
${renderAppendix(data)}

<div class="footer">
  <p>Generated by RedAmon on ${esc(generatedAt)}</p>
  <p>This document contains confidential security assessment results. Handle according to classification.</p>
</div>

</body>
</html>`
}

// ── Section Renderers ───────────────────────────────────────────────────────

function renderCover(name: string, domain: string, date: string, client: string, engType: string, riskScore: number, riskLabel: string): string {
  return `
<div class="cover">
  <div class="cover-header">
    <h1 class="cover-title">Penetration Test Report</h1>
    <h2 class="cover-subtitle">${esc(name)}</h2>
    <p class="cover-domain">${esc(domain)}</p>
  </div>
  <div class="cover-meta">
    <table class="cover-table">
      <tr><td class="cover-label">Date</td><td>${esc(date)}</td></tr>
      ${client ? `<tr><td class="cover-label">Client</td><td>${esc(client)}</td></tr>` : ''}
      ${engType ? `<tr><td class="cover-label">Engagement Type</td><td>${esc(engType.replace(/_/g, ' '))}</td></tr>` : ''}
      <tr><td class="cover-label">Risk Score</td><td>${riskScoreBadge(riskScore, riskLabel)}</td></tr>
      <tr><td class="cover-label">Classification</td><td><strong>CONFIDENTIAL</strong></td></tr>
    </table>
  </div>
</div>`
}

function renderTOC(data: ReportData): string {
  const dynamicSections: { id: string; label: string }[] = [
    { id: 'executive-summary', label: 'Executive Summary' },
    { id: 'scope', label: 'Scope & Methodology' },
    { id: 'risk-summary', label: 'Risk Summary' },
    { id: 'findings', label: 'Findings' },
    { id: 'vulnerability-details', label: 'Other Vulnerability Details' },
    { id: 'attack-surface', label: 'Attack Surface' },
    { id: 'cve-intelligence', label: 'CVE Intelligence' },
  ]
  if (data.cveIntelligence.githubSecrets.secrets > 0 || data.cveIntelligence.githubSecrets.sensitiveFiles > 0) {
    dynamicSections.push({ id: 'github-secrets', label: 'GitHub Secrets' })
  }
  if (data.trufflehog.totalFindings > 0) {
    dynamicSections.push({ id: 'trufflehog', label: 'TruffleHog Findings' })
  }
  if (data.secrets.total > 0) {
    dynamicSections.push({ id: 'secrets', label: 'Secret Detection' })
  }
  if (data.jsRecon.totalFindings > 0) {
    dynamicSections.push({ id: 'js-recon', label: 'JavaScript Reconnaissance' })
  }
  if (data.graphqlScan.endpointsTested > 0 || data.graphqlScan.totalFindings > 0) {
    dynamicSections.push({ id: 'graphql-scan', label: 'GraphQL Security' })
  }
  if (data.otx.totalPulses > 0 || data.otx.totalMalware > 0) {
    dynamicSections.push({ id: 'otx', label: 'OTX Threat Intelligence' })
  }
  if (data.attackChains.chains.length > 0) {
    dynamicSections.push({ id: 'attack-chains', label: 'Attack Chains' })
  }
  dynamicSections.push(
    { id: 'recommendations', label: 'Recommendations' },
    { id: 'appendix', label: 'Appendix' },
  )
  const sections = dynamicSections.map((s, i) => ({ id: s.id, title: `${i + 1}. ${s.label}` }))

  return `
<div class="page-break"></div>
<div class="section" id="toc">
  <h2 class="section-title">Table of Contents</h2>
  <ul class="toc-list">
    ${sections.map(s => `<li><a href="#${s.id}">${esc(s.title)}</a></li>`).join('\n    ')}
  </ul>
</div>`
}

function renderExecutiveSummary(data: ReportData, narrative?: string): string {
  const m = data.metrics
  return `
<div class="page-break"></div>
<div class="section" id="executive-summary">
  <h2 class="section-title">1. Executive Summary</h2>
  ${narrative ? `<div class="narrative">${esc(narrative)}</div>` : ''}
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
    <div class="metric-card-sm" style="border-left:3px solid #6366f1"><div class="metric-value-sm">${m.totalCves + m.totalVulnerabilities}</div><div class="metric-label-sm">Total Findings</div></div>
    <div class="metric-card-sm" style="border-left:3px solid ${riskScoreColor(m.riskScore)}"><div class="metric-value-sm">${riskScoreBadge(m.riskScore, m.riskLabel)}</div><div class="metric-label-sm">Risk Score</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${m.exploitableCount}</div><div class="metric-label-sm">Confirmed Exploits</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${m.cvssAverage}</div><div class="metric-label-sm">Avg CVSS</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${m.attackSurfaceSize}</div><div class="metric-label-sm">Attack Surface</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${m.totalRemediations}</div><div class="metric-label-sm">Remediations</div></div>
    ${m.secretsExposed > 0 ? `<div class="metric-card-sm" style="border-left:3px solid #dc2626"><div class="metric-value-sm">${m.secretsExposed}</div><div class="metric-label-sm">Secrets Exposed</div></div>` : ''}
  </div>

  <div class="two-col" style="margin-bottom:20px">
    <div>
      <h3 style="margin-top:8px">Known CVEs (${m.totalCves})</h3>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <div class="metric-card-sm" style="border-left:3px solid #dc2626"><div class="metric-value-sm">${m.cveCriticalCount}</div><div class="metric-label-sm">Critical</div></div>
        <div class="metric-card-sm" style="border-left:3px solid #ea580c"><div class="metric-value-sm">${m.cveHighCount}</div><div class="metric-label-sm">High</div></div>
        <div class="metric-card-sm" style="border-left:3px solid #d97706"><div class="metric-value-sm">${m.cveMediumCount}</div><div class="metric-label-sm">Medium</div></div>
        <div class="metric-card-sm" style="border-left:3px solid #2563eb"><div class="metric-value-sm">${m.cveLowCount}</div><div class="metric-label-sm">Low</div></div>
      </div>
    </div>
    <div>
      <h3 style="margin-top:8px">Other Vulnerabilities (${m.totalVulnerabilities})</h3>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <div class="metric-card-sm" style="border-left:3px solid #dc2626"><div class="metric-value-sm">${m.criticalCount}</div><div class="metric-label-sm">Critical</div></div>
        <div class="metric-card-sm" style="border-left:3px solid #ea580c"><div class="metric-value-sm">${m.highCount}</div><div class="metric-label-sm">High</div></div>
        <div class="metric-card-sm" style="border-left:3px solid #d97706"><div class="metric-value-sm">${m.mediumCount}</div><div class="metric-label-sm">Medium</div></div>
        <div class="metric-card-sm" style="border-left:3px solid #2563eb"><div class="metric-value-sm">${m.lowCount}</div><div class="metric-label-sm">Low</div></div>
      </div>
    </div>
  </div>

</div>`
}

function renderScope(data: ReportData, narrative?: string): string {
  const { project, graphOverview } = data
  const p = project as any
  const isIpMode = p.ipMode === true

  // Rules of Engagement
  let roeTable = ''
  if (p.roeClientName || p.roeEngagementType) {
    const rows: string[] = []
    if (p.roeClientName) rows.push(`<tr><td>Client</td><td>${esc(p.roeClientName)}</td></tr>`)
    if (p.roeClientContactName) rows.push(`<tr><td>Client Contact</td><td>${esc(p.roeClientContactName)} ${p.roeClientContactEmail ? `(${esc(p.roeClientContactEmail)})` : ''}</td></tr>`)
    if (p.roeEngagementType) rows.push(`<tr><td>Engagement Type</td><td>${esc(p.roeEngagementType.replace(/_/g, ' '))}</td></tr>`)
    if (p.roeEngagementStartDate) rows.push(`<tr><td>Start Date</td><td>${esc(String(p.roeEngagementStartDate).substring(0, 10))}</td></tr>`)
    if (p.roeEngagementEndDate) rows.push(`<tr><td>End Date</td><td>${esc(String(p.roeEngagementEndDate).substring(0, 10))}</td></tr>`)
    if (p.roeExcludedHosts?.length) rows.push(`<tr><td>Excluded Hosts</td><td>${esc(p.roeExcludedHosts.join(', '))}</td></tr>`)
    if (p.roeForbiddenCategories?.length) rows.push(`<tr><td>Forbidden Categories</td><td>${esc(p.roeForbiddenCategories.join(', '))}</td></tr>`)
    if (p.roeComplianceFrameworks?.length) rows.push(`<tr><td>Compliance Frameworks</td><td>${esc(p.roeComplianceFrameworks.join(', '))}</td></tr>`)
    roeTable = `<h3>Rules of Engagement</h3><table class="data-table"><tbody>${rows.join('')}</tbody></table>`
  }

  // Subdomain Resolution Map (domain mode)
  let mappingTable = ''
  if (!isIpMode) {
    const mappings = graphOverview.subdomainMappings || []
    if (mappings.length > 0) {
      const rows = mappings.map(m => {
        const ipList = m.ips.length > 0
          ? m.ips.map(ip => {
              const cdn = ip.isCdn && ip.cdnName
                ? ` <span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;background:#dbeafe;color:#1d4ed8">${esc(ip.cdnName)}</span>`
                : ''
              return `${esc(ip.address)}${cdn}`
            }).join('<br/>')
          : '<span style="color:#9ca3af;font-style:italic">Unresolved</span>'
        const ports = m.ips.length > 0 ? String(m.openPorts) : '<span style="color:#9ca3af">—</span>'
        return `<tr><td>${esc(m.subdomain)}</td><td>${ipList}</td><td>${ports}</td></tr>`
      }).join('')
      mappingTable = `
  <h3>Subdomain Resolution Map</h3>
  <table class="data-table">
    <thead><tr><th>Subdomain</th><th>Resolved IPs</th><th>Open Ports</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`
    } else {
      mappingTable = `<h3>Subdomain Resolution Map</h3><p style="color:#6b7280;font-style:italic">No subdomains discovered.</p>`
    }
  } else {
    // IP Target Map (IP mode)
    const mappings = graphOverview.ipMappings || []
    if (mappings.length > 0) {
      const rows = mappings.map(m => {
        const hostnames = m.hostnames.length > 0
          ? m.hostnames.map(h => esc(h)).join('<br/>')
          : '<span style="color:#9ca3af;font-style:italic">No reverse DNS</span>'
        const cdn = m.isCdn && m.cdnName
          ? `<span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;background:#dbeafe;color:#1d4ed8">${esc(m.cdnName)}</span>`
          : '<span style="color:#9ca3af">—</span>'
        return `<tr><td>${esc(m.ip)}</td><td>${esc(m.version || '')}</td><td>${hostnames}</td><td>${cdn}</td><td>${m.openPorts}</td></tr>`
      }).join('')
      mappingTable = `
  <h3>IP Target Map</h3>
  <table class="data-table">
    <thead><tr><th>IP Address</th><th>Version</th><th>Hostnames</th><th>CDN</th><th>Open Ports</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`
    } else {
      mappingTable = `<h3>IP Target Map</h3><p style="color:#6b7280;font-style:italic">No IP targets discovered.</p>`
    }
  }

  // Target info row
  const targetRow = isIpMode
    ? `<tr><td>Target IPs / CIDRs</td><td>${esc((project.targetIps || []).join(', ') || 'N/A')}</td></tr>`
    : `<tr><td>Target Domain</td><td>${esc(project.targetDomain || 'N/A')}</td></tr>`

  return `
<div class="page-break"></div>
<div class="section" id="scope">
  <h2 class="section-title">2. Scope & Methodology</h2>
  ${narrative ? `<div class="narrative">${esc(narrative)}</div>` : ''}

  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">
    <div class="metric-card-sm"><div class="metric-value-sm">${isIpMode ? 'IP / CIDR' : 'Domain'}</div><div class="metric-label-sm">Scan Mode</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${graphOverview.subdomainStats.total}</div><div class="metric-label-sm">Subdomains</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${graphOverview.infrastructureStats.totalIps}</div><div class="metric-label-sm">Unique IPs</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${graphOverview.endpointCoverage.baseUrls}</div><div class="metric-label-sm">Base URLs</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${graphOverview.endpointCoverage.endpoints}</div><div class="metric-label-sm">Endpoints</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${graphOverview.endpointCoverage.parameters}</div><div class="metric-label-sm">Parameters</div></div>
  </div>

  <h3>Target Information</h3>
  <table class="data-table">
    <tbody>
      ${targetRow}
      <tr><td>Stealth Mode</td><td>${project.stealthMode ? 'Enabled' : 'Disabled'}</td></tr>
    </tbody>
  </table>
  ${mappingTable}
  <h3>Discovery Summary</h3>
  <table class="data-table">
    <tbody>
      <tr><td>Total Graph Nodes</td><td>${graphOverview.totalNodes}</td></tr>
      <tr><td>Subdomains</td><td>${graphOverview.subdomainStats.total} (${graphOverview.subdomainStats.resolved} resolved)</td></tr>
      <tr><td>Unique IPs</td><td>${graphOverview.subdomainStats.uniqueIps}</td></tr>
      <tr><td>Base URLs</td><td>${graphOverview.endpointCoverage.baseUrls}</td></tr>
      <tr><td>Endpoints</td><td>${graphOverview.endpointCoverage.endpoints}</td></tr>
      <tr><td>Parameters</td><td>${graphOverview.endpointCoverage.parameters}</td></tr>
    </tbody>
  </table>
  ${roeTable}
</div>`
}

function renderRiskSummary(data: ReportData, narrative?: string): string {
  const { vulnerabilities, metrics } = data

  const sevRows = [...vulnerabilities.severityDistribution]
    .sort((a, b) => {
      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      return (order[a.severity] ?? 5) - (order[b.severity] ?? 5)
    })
    .map(d => `<tr><td>${sevBadge(d.severity)}</td><td>${d.count}</td><td>${metrics.totalVulnerabilities > 0 ? Math.round(d.count / metrics.totalVulnerabilities * 100) : 0}%</td></tr>`)
    .join('')

  const cvssRows = vulnerabilities.cvssHistogram
    .map(b => `<tr><td>${b.bucket}.0 – ${b.bucket}.9</td><td>${b.count}</td></tr>`)
    .join('')

  const gvmRows = vulnerabilities.gvmRemediation
    .map(r => `<tr><td>${esc(r.status)}</td><td>${r.count}</td></tr>`)
    .join('')

  return `
<div class="page-break"></div>
<div class="section" id="risk-summary">
  <h2 class="section-title">3. Risk Summary</h2>
  ${narrative ? `<div class="narrative">${esc(narrative)}</div>` : ''}
  ${renderSecurityPostureRadar(data)}
  <div class="two-col">
    <div>
      <h3>CVSS Score Distribution</h3>
      <table class="data-table">
        <thead><tr><th>CVSS Range</th><th>CVEs</th></tr></thead>
        <tbody>${cvssRows || '<tr><td colspan="2">No CVE data</td></tr>'}</tbody>
      </table>
      ${gvmRows ? `
      <h3>GVM Remediation Status</h3>
      <table class="data-table">
        <thead><tr><th>Status</th><th>Count</th></tr></thead>
        <tbody>${gvmRows}</tbody>
      </table>` : ''}
    </div>
    <div>
      <h3>Other Vulnerabilities Severity Distribution</h3>
      <table class="data-table">
        <thead><tr><th>Severity</th><th>Count</th><th>%</th></tr></thead>
        <tbody>${sevRows}</tbody>
      </table>
    </div>
  </div>
</div>`
}

function renderFindings(data: ReportData, narrative?: string): string {
  const { remediations } = data
  if (remediations.length === 0 && !narrative) {
    return `
<div class="page-break"></div>
<div class="section" id="findings">
  <h2 class="section-title">4. Findings</h2>
  <p class="muted">No remediation findings have been generated yet. Run CypherFix triage to generate prioritized findings.</p>
</div>`
  }

  // Group by severity
  const groups: Record<string, typeof remediations> = {}
  for (const r of remediations) {
    const sev = r.severity || 'info'
    if (!groups[sev]) groups[sev] = []
    groups[sev].push(r)
  }

  const sevOrder = ['critical', 'high', 'medium', 'low', 'info']
  let findingNum = 0

  const sections = sevOrder
    .filter(s => groups[s]?.length)
    .map(sev => {
      const items = groups[sev]
      const itemsHtml = items.map(r => {
        findingNum++
        // Cast to any for optional fields that may exist on extended remediation models
        const rx = r as Record<string, unknown>
        const fields: string[] = []
        if (r.category) fields.push(`<tr><td>Category</td><td>${esc(r.category)}</td></tr>`)
        if (rx.affectedAssets) {
          const assets = rx.affectedAssets as Array<Record<string, unknown>>
          if (Array.isArray(assets) && assets.length > 0) {
            const assetLines = assets.map(a => {
              const parts: string[] = []
              if (a.name) parts.push(String(a.name))
              if (a.ip) parts.push(String(a.ip))
              if (a.port) parts.push(`port ${a.port}`)
              if (a.url) parts.push(String(a.url))
              return parts.join(', ') || JSON.stringify(a)
            })
            fields.push(`<tr><td>Affected Assets</td><td>${assetLines.map(l => esc(l)).join('<br>')}</td></tr>`)
          }
        }
        if (rx.stepsToReproduce) fields.push(`<tr><td>Steps to Reproduce</td><td><pre class="pre-wrap">${esc(String(rx.stepsToReproduce))}</pre></td></tr>`)
        if (rx.suggestedFix) fields.push(`<tr><td>Suggested Fix</td><td><pre class="pre-wrap">${esc(String(rx.suggestedFix))}</pre></td></tr>`)
        if (rx.references) fields.push(`<tr><td>References</td><td>${esc(String(rx.references))}</td></tr>`)
        const statusBadge = r.status === 'completed' ? '<span class="status-done">Fixed</span>'
          : r.status === 'in_progress' ? '<span class="status-progress">In Progress</span>'
          : '<span class="status-open">Open</span>'

        return `
        <div class="finding-card" style="border-left:4px solid ${sevColor(sev)}; background:${sevBg(sev)}">
          <div class="finding-header">
            <span class="finding-num">${findingNum}.</span>
            ${sevBadge(sev)}
            <span class="finding-title">${esc(r.title)}</span>
            ${statusBadge}
          </div>
          ${r.description ? `<p class="finding-desc">${esc(r.description)}</p>` : ''}
          ${fields.length ? `<table class="finding-details">${fields.join('')}</table>` : ''}
        </div>`
      }).join('')

      return `<h3>${sevBadge(sev)} ${sev.charAt(0).toUpperCase() + sev.slice(1)} (${items.length})</h3>${itemsHtml}`
    }).join('')

  return `
<div class="page-break"></div>
<div class="section" id="findings">
  <h2 class="section-title">4. Findings</h2>
  ${narrative ? `<div class="narrative">${esc(narrative)}</div>` : ''}
  <p>Total remediation items: <strong>${remediations.length}</strong></p>
  ${sections}
</div>`
}

function renderVulnerabilityDetails(data: ReportData): string {
  const { findings } = data.vulnerabilities
  if (findings.length === 0) {
    return `
<div class="page-break"></div>
<div class="section" id="vulnerability-details">
  <h2 class="section-title">5. Other Vulnerability Details</h2>
  <p class="muted">No vulnerability nodes found in the graph.</p>
</div>`
  }

  // Group by source
  const bySource: Record<string, VulnFinding[]> = {}
  for (const f of findings) {
    const src = f.findingSource || 'Unknown'
    if (!bySource[src]) bySource[src] = []
    bySource[src].push(f)
  }

  const sourceSections = Object.entries(bySource).map(([source, items]) => {
    const rows = items.slice(0, 50).map(f => `
      <tr>
        <td>${esc(f.name)}</td>
        <td>${sevBadge(f.severity)}</td>
        <td>${f.cvssScore != null ? f.cvssScore.toFixed(1) : '—'}</td>
        <td>${esc(f.target || f.host || f.matchedAt || '—')}</td>
        <td>${esc(f.category || '—')}</td>
      </tr>`).join('')

    return `
    <h3>${esc(source)} (${items.length})</h3>
    <table class="data-table">
      <thead><tr><th>Name</th><th>Severity</th><th>CVSS</th><th>Target</th><th>Category</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    ${items.length > 50 ? `<p class="muted">Showing 50 of ${items.length} — see appendix for full list.</p>` : ''}`
  }).join('')

  return `
<div class="page-break"></div>
<div class="section" id="vulnerability-details">
  <h2 class="section-title">5. Other Vulnerability Details</h2>
  <p>Total vulnerability nodes: <strong>${findings.length}</strong></p>
  ${sourceSections}
</div>`
}

function renderAttackSurface(data: ReportData, narrative?: string): string {
  const { attackSurface, graphOverview } = data

  const techRows = attackSurface.technologies.slice(0, 30).map(t =>
    `<tr><td>${esc(t.name)}</td><td>${esc(t.version || '—')}</td><td>${t.cveCount}</td></tr>`
  ).join('')

  const svcRows = attackSurface.services.slice(0, 20).map(s =>
    `<tr><td>${esc(s.service)}</td><td>${s.port}</td><td>${s.count}</td></tr>`
  ).join('')

  const portRows = attackSurface.ports.slice(0, 20).map(p =>
    `<tr><td>${p.port}</td><td>${esc(p.protocol)}</td><td>${p.count}</td></tr>`
  ).join('')

  const dnsRows = attackSurface.dnsRecords.map(d =>
    `<tr><td>${esc(d.type)}</td><td>${d.count}</td></tr>`
  ).join('')

  const certInfo = graphOverview.certificateHealth

  return `
<div class="page-break"></div>
<div class="section" id="attack-surface">
  <h2 class="section-title">6. Attack Surface</h2>
  ${narrative ? `<div class="narrative">${esc(narrative)}</div>` : ''}

  <div class="two-col">
    <div>
      <h3>Technologies (${attackSurface.technologies.length})</h3>
      <table class="data-table">
        <thead><tr><th>Technology</th><th>Version</th><th>CVEs</th></tr></thead>
        <tbody>${techRows || '<tr><td colspan="3">None detected</td></tr>'}</tbody>
      </table>
    </div>
    <div>
      <h3>Services</h3>
      <table class="data-table">
        <thead><tr><th>Service</th><th>Port</th><th>Hosts</th></tr></thead>
        <tbody>${svcRows || '<tr><td colspan="3">None detected</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <div class="two-col">
    <div>
      <h3>Open Ports</h3>
      <table class="data-table">
        <thead><tr><th>Port</th><th>Protocol</th><th>Hosts</th></tr></thead>
        <tbody>${portRows || '<tr><td colspan="3">None detected</td></tr>'}</tbody>
      </table>
    </div>
    <div>
      <h3>DNS Records</h3>
      <table class="data-table">
        <thead><tr><th>Type</th><th>Count</th></tr></thead>
        <tbody>${dnsRows || '<tr><td colspan="2">None</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  ${renderSecurityHeadersGap(data)}

  <h3>Certificates</h3>
  <table class="data-table">
    <tbody>
      <tr><td>Total</td><td>${certInfo.total}</td></tr>
      <tr><td>Expired</td><td style="color:${certInfo.expired > 0 ? '#dc2626' : 'inherit'}">${certInfo.expired}</td></tr>
      <tr><td>Expiring Soon (30 days)</td><td style="color:${certInfo.expiringSoon > 0 ? '#d97706' : 'inherit'}">${certInfo.expiringSoon}</td></tr>
    </tbody>
  </table>

  <h3>Infrastructure</h3>
  ${(() => {
    const infra = graphOverview.infrastructureStats
    const directIps = infra.totalIps - infra.cdnCount
    const cdnPct = infra.totalIps > 0 ? Math.round((infra.cdnCount / infra.totalIps) * 100) : 0
    return `
  <table class="data-table">
    <tbody>
      <tr><td>Total IPs</td><td>${infra.totalIps}</td></tr>
      <tr><td>IPv4 / IPv6</td><td>${infra.ipv4} / ${infra.ipv6}</td></tr>
      <tr><td>CDN-Fronted</td><td>${infra.cdnCount} of ${infra.totalIps} (${cdnPct}%)</td></tr>
      <tr><td>Directly Exposed</td><td style="color:${directIps > 0 ? '#dc2626' : '#22c55e'};font-weight:600">${directIps}</td></tr>
      <tr><td>CDN Coverage</td><td style="width:50%">${cssBarGauge(cdnPct, `${infra.cdnCount} CDN / ${directIps} direct`)}</td></tr>
      <tr><td>CDN Providers</td><td>${infra.uniqueCdns}</td></tr>
      <tr><td>Unique ASNs</td><td>${infra.uniqueAsns}</td></tr>
    </tbody>
  </table>`
  })()}

  ${attackSurface.endpointCategories.length > 0 ? `
  <h3>Endpoint Categories</h3>
  <table class="data-table">
    <thead><tr><th>Category</th><th>Count</th></tr></thead>
    <tbody>${attackSurface.endpointCategories.map(c => `<tr><td>${esc(c.category)}</td><td>${c.count}</td></tr>`).join('')}</tbody>
  </table>` : ''}

  ${renderInjectableBreakdown(data)}
</div>`
}

function renderCveIntelligence(data: ReportData): string {
  const { cveChains, exploits } = data.cveIntelligence
  if (cveChains.length === 0 && exploits.length === 0) {
    return `
<div class="page-break"></div>
<div class="section" id="cve-intelligence">
  <h2 class="section-title">7. CVE Intelligence</h2>
  <p class="muted">No CVE intelligence data available.</p>
</div>`
  }

  // Unique CVEs
  const uniqueCves = new Map<string, CveChain>()
  for (const c of cveChains) {
    if (!uniqueCves.has(c.cveId)) uniqueCves.set(c.cveId, c)
  }

  const cveRows = Array.from(uniqueCves.values()).slice(0, 40).map(c => `
    <tr>
      <td>${esc(c.cveId)}</td>
      <td>${c.cvss != null ? Number(c.cvss).toFixed(1) : '—'}</td>
      <td>${c.cveSeverity ? sevBadge(c.cveSeverity) : '—'}</td>
      <td>${esc(c.tech)}${c.techVersion ? ` ${esc(c.techVersion)}` : ''}</td>
      <td>${c.cweId ? esc(c.cweId) : '—'}</td>
    </tr>`).join('')

  // CWE summary
  const cweMap = new Map<string, { id: string; name: string; count: number }>()
  for (const c of cveChains) {
    if (c.cweId) {
      const key = c.cweId
      const existing = cweMap.get(key)
      if (existing) existing.count++
      else cweMap.set(key, { id: c.cweId, name: c.cweName || '', count: 1 })
    }
  }
  const cweRows = Array.from(cweMap.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, 15)
    .map(c => `<tr><td>${esc(c.id)}</td><td>${esc(c.name)}</td><td>${c.count}</td></tr>`)
    .join('')

  // Exploits
  const exploitRows = exploits.map((e: ExploitRecord) => `
    <tr style="background:${sevBg(e.severity)}">
      <td>${esc(e.name)}</td>
      <td>${sevBadge(e.severity)}</td>
      <td>${e.cvssScore != null ? e.cvssScore.toFixed(1) : '—'}</td>
      <td>${esc(e.targetIp || '—')}${e.targetPort ? `:${e.targetPort}` : ''}</td>
      <td>${e.cisaKev ? '<span style="color:#dc2626;font-weight:600">YES</span>' : 'No'}</td>
      <td>${e.cveIds.length > 0 ? e.cveIds.map(id => esc(id)).join(', ') : '—'}</td>
    </tr>`).join('')

  return `
<div class="page-break"></div>
<div class="section" id="cve-intelligence">
  <h2 class="section-title">7. CVE Intelligence</h2>

  ${renderCisaKevCallout(data)}

  <h3>Known CVEs (${uniqueCves.size})</h3>
  <table class="data-table">
    <thead><tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Technology</th><th>CWE</th></tr></thead>
    <tbody>${cveRows}</tbody>
  </table>
  ${uniqueCves.size > 40 ? `<p class="muted">Showing 40 of ${uniqueCves.size} — see appendix.</p>` : ''}

  ${cweRows ? `
  <h3>CWE Breakdown</h3>
  <table class="data-table">
    <thead><tr><th>CWE ID</th><th>Name</th><th>CVEs</th></tr></thead>
    <tbody>${cweRows}</tbody>
  </table>` : ''}

  ${renderAttackFlowChains(data)}

  ${exploitRows ? `
  <h3>Confirmed Exploits (${exploits.length})</h3>
  <table class="data-table">
    <thead><tr><th>Name</th><th>Severity</th><th>CVSS</th><th>Target</th><th>CISA KEV</th><th>CVEs</th></tr></thead>
    <tbody>${exploitRows}</tbody>
  </table>` : ''}
</div>`
}

function renderGithubSecrets(data: ReportData): string {
  const gh = data.cveIntelligence.githubSecrets
  if (gh.secrets === 0 && gh.sensitiveFiles === 0) return ''

  return `
<div class="page-break"></div>
<div class="section" id="github-secrets">
  <h2 class="section-title">GitHub Secrets</h2>
  <div class="alert alert-critical">
    Exposed secrets and sensitive files were discovered in GitHub repositories associated with the target.
  </div>
  <table class="data-table">
    <tbody>
      <tr><td>Repositories Analyzed</td><td>${gh.repos}</td></tr>
      <tr><td>Secrets Found</td><td style="color:#dc2626;font-weight:600">${gh.secrets}</td></tr>
      <tr><td>Sensitive Files</td><td style="color:#ea580c;font-weight:600">${gh.sensitiveFiles}</td></tr>
    </tbody>
  </table>
</div>`
}

function renderTrufflehog(data: ReportData): string {
  const th = data.trufflehog
  if (th.totalFindings === 0) return ''

  const findingRows = th.findings.map(f => `
    <tr${f.verified ? ' style="background:#fef2f2"' : ''}>
      <td>${esc(f.detectorName)}</td>
      <td>${f.verified ? '<span style="color:#dc2626;font-weight:600">VERIFIED</span>' : '<span style="color:#d97706">Unverified</span>'}</td>
      <td style="font-family:monospace;font-size:11px">${esc(f.redacted || '')}</td>
      <td>${esc(f.repository || '')}</td>
      <td>${esc(f.file || '')}</td>
    </tr>`).join('')

  return `
<div class="page-break"></div>
<div class="section" id="trufflehog">
  <h2 class="section-title">TruffleHog Findings</h2>
  ${th.verifiedFindings > 0 ? `<div class="alert alert-critical">
    ${th.verifiedFindings} verified credential(s) detected in git history. These credentials have been confirmed as active and represent immediate risk.
  </div>` : ''}
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">
    <div class="metric-card-sm" style="border-left:3px solid #6366f1"><div class="metric-value-sm">${th.totalFindings}</div><div class="metric-label-sm">Total Findings</div></div>
    <div class="metric-card-sm" style="border-left:3px solid #dc2626"><div class="metric-value-sm">${th.verifiedFindings}</div><div class="metric-label-sm">Verified</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${th.repositories}</div><div class="metric-label-sm">Repositories</div></div>
  </div>
  <table class="data-table">
    <thead><tr><th>Detector</th><th>Status</th><th>Redacted</th><th>Repository</th><th>File</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>
</div>`
}

function renderSecrets(data: ReportData): string {
  const sec = data.secrets
  if (sec.total === 0) return ''

  const sevRows = sec.bySeverity.map(s => `
    <tr><td>${sevBadge(s.severity)}</td><td>${s.count}</td></tr>`).join('')

  const typeRows = sec.byType.map(t => `
    <tr><td>${esc(t.secretType)}</td><td>${t.count}</td></tr>`).join('')

  const findingRows = sec.findings.map(f => `
    <tr>
      <td>${esc(f.secretType)}</td>
      <td>${sevBadge(f.severity)}</td>
      <td>${esc(f.source)}</td>
      <td style="font-family:monospace;font-size:11px">${esc(f.sample || '')}</td>
      <td>${f.validationStatus ? esc(f.validationStatus) : ''}</td>
    </tr>`).join('')

  return `
<div class="page-break"></div>
<div class="section" id="secrets">
  <h2 class="section-title">Secret Detection</h2>
  <div class="alert alert-critical">
    ${sec.total} secret(s) detected across web resources and JavaScript files.
  </div>
  <div class="two-col">
    <div>
      <h3>By Severity</h3>
      <table class="data-table">
        <thead><tr><th>Severity</th><th>Count</th></tr></thead>
        <tbody>${sevRows}</tbody>
      </table>
    </div>
    <div>
      <h3>By Type (Top 20)</h3>
      <table class="data-table">
        <thead><tr><th>Secret Type</th><th>Count</th></tr></thead>
        <tbody>${typeRows}</tbody>
      </table>
    </div>
  </div>
  <h3>Findings Detail</h3>
  <table class="data-table">
    <thead><tr><th>Type</th><th>Severity</th><th>Source</th><th>Sample</th><th>Validation</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>
  ${sec.findings.length >= 50 ? '<p class="muted">Showing first 50 findings.</p>' : ''}
</div>`
}

function renderJsRecon(data: ReportData): string {
  const js = data.jsRecon
  if (js.totalFindings === 0) return ''

  const sevRows = js.bySeverity.map(s => `
    <tr><td>${sevBadge(s.severity)}</td><td>${s.count}</td></tr>`).join('')

  const typeRows = js.byType.map(t => `
    <tr><td>${esc(t.findingType.replace(/_/g, ' '))}</td><td>${t.count}</td></tr>`).join('')

  const findingRows = js.findings.map(f => `
    <tr>
      <td>${esc(f.title)}</td>
      <td>${sevBadge(f.severity)}</td>
      <td>${esc(f.findingType.replace(/_/g, ' '))}</td>
      <td>${f.confidence ? esc(f.confidence) : ''}</td>
      <td style="font-size:11px;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.sourceUrl || '')}</td>
    </tr>`).join('')

  return `
<div class="page-break"></div>
<div class="section" id="js-recon">
  <h2 class="section-title">JavaScript Reconnaissance</h2>
  <p style="margin-bottom:12px">Deep analysis of JavaScript files revealed ${js.totalFindings} finding(s) across dependency confusion risks, source map exposure, DOM sinks, developer comments, and framework detection.</p>
  <div class="two-col">
    <div>
      <h3>By Severity</h3>
      <table class="data-table">
        <thead><tr><th>Severity</th><th>Count</th></tr></thead>
        <tbody>${sevRows}</tbody>
      </table>
    </div>
    <div>
      <h3>By Finding Type</h3>
      <table class="data-table">
        <thead><tr><th>Type</th><th>Count</th></tr></thead>
        <tbody>${typeRows}</tbody>
      </table>
    </div>
  </div>
  <h3>Findings Detail</h3>
  <table class="data-table">
    <thead><tr><th>Title</th><th>Severity</th><th>Type</th><th>Confidence</th><th>Source URL</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>
  ${js.findings.length >= 50 ? '<p class="muted">Showing first 50 findings.</p>' : ''}
</div>`
}

function renderGraphqlScan(data: ReportData): string {
  const gql = data.graphqlScan
  if (gql.endpointsTested === 0 && gql.totalFindings === 0) return ''

  const sevRows = gql.bySeverity.map(s => `
    <tr><td>${sevBadge(s.severity)}</td><td>${s.count}</td></tr>`).join('')

  const typeRows = gql.byType.map(t => `
    <tr><td>${esc(t.vulnerabilityType.replace(/_/g, ' '))}</td><td>${t.count}</td></tr>`).join('')

  const endpointRows = gql.endpoints.map(e => `
    <tr>
      <td style="font-family:monospace;font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.url)}</td>
      <td>${e.introspectionEnabled ? '<span style="color:#dc2626;font-weight:600">YES</span>' : 'no'}</td>
      <td>${e.queriesCount}</td>
      <td>${e.mutationsCount}</td>
      <td>${e.subscriptionsCount}</td>
      <td style="font-family:monospace;font-size:10px;color:#6b7280">${e.schemaHash ? esc(e.schemaHash.substring(0, 16)) + '...' : ''}</td>
    </tr>`).join('')

  const findingRows = gql.findings.map(f => {
    const sourceBadge = f.source === 'graphql_cop'
      ? '<span style="font-size:9px;padding:1px 4px;border-radius:3px;background:rgba(99,102,241,0.15);color:#818cf8;margin-left:4px">cop</span>'
      : ''
    const curlBlock = f.curlVerify
      ? `<details style="margin-top:4px"><summary style="font-size:10px;cursor:pointer;color:#9ca3af">Reproduce (cURL)</summary><pre style="font-family:monospace;font-size:10px;background:#f3f4f6;padding:6px;border-radius:3px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:4px 0 0 0">${esc(f.curlVerify)}</pre></details>`
      : ''
    return `
    <tr>
      <td>${esc(f.title)}${sourceBadge}${curlBlock}</td>
      <td>${sevBadge(f.severity)}</td>
      <td>${esc(f.vulnerabilityType.replace(/_/g, ' '))}</td>
      <td style="font-family:monospace;font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.endpoint)}</td>
    </tr>`
  }).join('')

  return `
<div class="page-break"></div>
<div class="section" id="graphql-scan">
  <h2 class="section-title">GraphQL Security</h2>
  <p style="margin-bottom:12px">Active GraphQL security scan tested <strong>${gql.endpointsTested}</strong> endpoint(s). <strong>${gql.introspectionEnabled}</strong> had introspection enabled, exposing schema details. ${gql.totalFindings} vulnerability finding(s) produced.</p>
  ${gql.totalFindings > 0 ? `
  <div class="two-col">
    <div>
      <h3>By Severity</h3>
      <table class="data-table">
        <thead><tr><th>Severity</th><th>Count</th></tr></thead>
        <tbody>${sevRows}</tbody>
      </table>
    </div>
    <div>
      <h3>By Vulnerability Type</h3>
      <table class="data-table">
        <thead><tr><th>Type</th><th>Count</th></tr></thead>
        <tbody>${typeRows}</tbody>
      </table>
    </div>
  </div>` : ''}
  ${gql.endpoints.length > 0 ? `
  <h3>Tested GraphQL Endpoints</h3>
  <table class="data-table">
    <thead><tr><th>Endpoint</th><th>Introspection</th><th>Queries</th><th>Mutations</th><th>Subscriptions</th><th>Schema Hash</th></tr></thead>
    <tbody>${endpointRows}</tbody>
  </table>` : ''}
  ${gql.findings.length > 0 ? `
  <h3>Findings Detail</h3>
  <table class="data-table">
    <thead><tr><th>Title</th><th>Severity</th><th>Type</th><th>Endpoint</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>
  ${gql.findings.length >= 50 ? '<p class="muted">Showing first 50 findings.</p>' : ''}` : ''}
</div>`
}

function renderOtx(data: ReportData): string {
  const otx = data.otx
  if (otx.totalPulses === 0 && otx.totalMalware === 0) return ''

  const pulseRows = otx.pulses.map(p => `
    <tr>
      <td>${esc(p.name)}</td>
      <td>${p.adversary ? esc(p.adversary) : ''}</td>
      <td>${p.malwareFamilies.length > 0 ? p.malwareFamilies.map(m => esc(m)).join(', ') : ''}</td>
      <td>${p.attackIds.length > 0 ? p.attackIds.map(a => esc(a)).join(', ') : ''}</td>
      <td>${p.tlp ? esc(p.tlp.toUpperCase()) : ''}</td>
      <td>${esc(p.ipAddress || '')}</td>
    </tr>`).join('')

  const malwareRows = otx.malware.map(m => `
    <tr>
      <td style="font-family:monospace;font-size:11px">${esc(m.hash)}</td>
      <td>${esc(m.hashType || '')}</td>
      <td>${esc(m.fileType || '')}</td>
      <td>${esc(m.source || '')}</td>
      <td>${esc(m.ipAddress || '')}</td>
    </tr>`).join('')

  return `
<div class="page-break"></div>
<div class="section" id="otx">
  <h2 class="section-title">OTX Threat Intelligence</h2>
  <p style="margin-bottom:12px">AlienVault OTX threat intelligence enrichment identified associations between discovered infrastructure and known threat activity.</p>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">
    <div class="metric-card-sm" style="border-left:3px solid #6366f1"><div class="metric-value-sm">${otx.totalPulses}</div><div class="metric-label-sm">Threat Pulses</div></div>
    <div class="metric-card-sm" style="border-left:3px solid #dc2626"><div class="metric-value-sm">${otx.totalMalware}</div><div class="metric-label-sm">Malware Samples</div></div>
    <div class="metric-card-sm"><div class="metric-value-sm">${otx.enrichedIps}</div><div class="metric-label-sm">Enriched IPs</div></div>
    ${otx.adversaries.length > 0 ? `<div class="metric-card-sm" style="border-left:3px solid #ea580c"><div class="metric-value-sm">${otx.adversaries.length}</div><div class="metric-label-sm">Threat Actors</div></div>` : ''}
  </div>

  ${otx.adversaries.length > 0 ? `
  <h3>Known Threat Actors</h3>
  <p>${otx.adversaries.map(a => `<span style="display:inline-block;padding:2px 10px;margin:2px 4px;border-radius:4px;background:#fef2f2;color:#991b1b;font-weight:600;font-size:12px">${esc(a)}</span>`).join('')}</p>` : ''}

  ${pulseRows ? `
  <h3>Threat Pulses (${otx.totalPulses})</h3>
  <table class="data-table">
    <thead><tr><th>Pulse Name</th><th>Adversary</th><th>Malware</th><th>MITRE ATT&amp;CK</th><th>TLP</th><th>IP</th></tr></thead>
    <tbody>${pulseRows}</tbody>
  </table>` : ''}

  ${malwareRows ? `
  <h3>Associated Malware (${otx.totalMalware})</h3>
  <table class="data-table">
    <thead><tr><th>Hash</th><th>Type</th><th>File Type</th><th>Source</th><th>IP</th></tr></thead>
    <tbody>${malwareRows}</tbody>
  </table>` : ''}
</div>`
}

function renderAttackChains(data: ReportData): string {
  const { chains, exploitSuccesses, topFindings } = data.attackChains
  if (chains.length === 0) return ''

  const chainRows = chains.map(c => `
    <tr>
      <td>${esc(c.title)}</td>
      <td><span class="chain-status chain-status-${c.status}">${esc(c.status)}</span></td>
      <td>${c.steps}</td>
      <td>${c.findings}</td>
      <td>${c.failures}</td>
    </tr>`).join('')

  const exploitRows = exploitSuccesses.map(e => `
    <tr style="background:#fef2f2">
      <td>${esc(e.title)}</td>
      <td>${esc(e.targetIp || '—')}${e.targetPort ? `:${e.targetPort}` : ''}</td>
      <td>${esc(e.attackType || '—')}</td>
      <td>${esc(e.module || '—')}</td>
      <td>${e.cveIds.length > 0 ? e.cveIds.map(id => esc(id)).join(', ') : '—'}</td>
    </tr>`).join('')

  const findingRows = topFindings.slice(0, 15).map(f => `
    <tr>
      <td>${esc(f.title)}</td>
      <td>${sevBadge(f.severity)}</td>
      <td>${esc(f.findingType)}</td>
      <td>${esc(f.targetHost || '—')}</td>
    </tr>`).join('')

  return `
<div class="page-break"></div>
<div class="section" id="attack-chains">
  <h2 class="section-title">Attack Chains</h2>

  <h3>Chain Summary (${chains.length})</h3>
  <table class="data-table">
    <thead><tr><th>Title</th><th>Status</th><th>Steps</th><th>Findings</th><th>Failures</th></tr></thead>
    <tbody>${chainRows}</tbody>
  </table>

  ${exploitRows ? `
  <h3>Exploit Successes (${exploitSuccesses.length})</h3>
  <table class="data-table">
    <thead><tr><th>Title</th><th>Target</th><th>Type</th><th>Module</th><th>CVEs</th></tr></thead>
    <tbody>${exploitRows}</tbody>
  </table>` : ''}

  ${findingRows ? `
  <h3>Top Findings</h3>
  <table class="data-table">
    <thead><tr><th>Title</th><th>Severity</th><th>Type</th><th>Target</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>` : ''}
</div>`
}

function renderRecommendations(data: ReportData, narrative?: string): string {
  const { remediations } = data
  const openItems = remediations.filter(r => r.status !== 'completed')

  return `
<div class="page-break"></div>
<div class="section" id="recommendations">
  <h2 class="section-title">Recommendations</h2>
  ${narrative ? `<div class="narrative">${esc(narrative)}</div>` : ''}
  ${openItems.length > 0 ? `
  <h3>Priority Remediation Items (${openItems.length} open)</h3>
  <table class="data-table">
    <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Category</th><th>Status</th></tr></thead>
    <tbody>
      ${openItems.slice(0, 30).map((r, i) => `
      <tr>
        <td>${i + 1}</td>
        <td>${sevBadge(r.severity || 'info')}</td>
        <td>${esc(r.title)}</td>
        <td>${esc(r.category || '—')}</td>
        <td>${r.status === 'in_progress' ? '<span class="status-progress">In Progress</span>' : '<span class="status-open">Open</span>'}</td>
      </tr>`).join('')}
    </tbody>
  </table>
  ${openItems.length > 30 ? `<p class="muted">Showing 30 of ${openItems.length} open items.</p>` : ''}` : '<p class="muted">All remediation items have been completed.</p>'}
</div>`
}

function renderFireteams(data: ReportData): string {
  const ft = data.fireteams
  if (!ft || ft.totalFireteams === 0) return ''

  const deployments = ft.deployments.map(d => {
    const members = d.members.map(m => {
      const badge =
        m.status === 'success' ? 'badge-ok'
        : m.status === 'partial' ? 'badge-warn'
        : m.status === 'needs_confirmation' ? 'badge-warn'
        : 'badge-err'
      const skillsStr = (m.skills || []).length > 0 ? (m.skills || []).map(esc).join(', ') : 'none'
      return `
        <div class="ft-member">
          <div class="ft-member-head">
            <strong>${esc(m.name)}</strong>
            <span class="${badge}">${esc(m.status)}</span>
          </div>
          <div class="ft-member-task">${esc(m.task || '')}</div>
          <div class="ft-member-meta">
            Skills: ${skillsStr} &middot;
            Iterations: ${m.iterationsUsed} &middot;
            Tokens: ${m.tokensUsed} &middot;
            Findings: ${m.findingsCount}
            ${m.wallClockSeconds != null ? ` &middot; ${m.wallClockSeconds.toFixed(1)}s` : ''}
          </div>
          ${m.completionReason && m.status !== 'success'
            ? `<div class="ft-member-reason">Reason: ${esc(m.completionReason)}</div>` : ''}
          ${m.errorMessage ? `<div class="ft-member-error">Error: ${esc(m.errorMessage)}</div>` : ''}
        </div>`
    }).join('')
    const counts = d.statusCounts ? Object.entries(d.statusCounts).map(([k, v]) => `${v} ${k}`).join(' &middot; ') : ''
    return `
      <div class="ft-deployment">
        <div class="ft-head">
          <h3>Wave ${d.iteration} <span class="muted">(${esc(d.fireteamIdKey)})</span></h3>
          <span class="ft-status">${esc(d.status)}</span>
        </div>
        ${d.planRationale ? `<p class="ft-rationale">${esc(d.planRationale)}</p>` : ''}
        <p class="ft-timing muted">
          ${counts ? `${counts} &middot; ` : ''}
          Duration: ${d.wallClockSeconds != null ? `${d.wallClockSeconds.toFixed(1)}s` : 'n/a'}
        </p>
        <div class="ft-members">${members}</div>
      </div>`
  }).join('')

  return `
<div class="section" id="fireteams">
  <h2>Multi-Agent Analysis (Fireteam)</h2>
  <p class="intro">
    This engagement used ${ft.totalFireteams} parallel fireteam${ft.totalFireteams > 1 ? 's' : ''}
    across ${ft.totalMembers} specialist member${ft.totalMembers !== 1 ? 's' : ''}, producing
    ${ft.totalFindings} attributed finding${ft.totalFindings !== 1 ? 's' : ''}.
  </p>
  ${deployments}
</div>`
}

function renderAppendix(data: ReportData): string {
  const { graphOverview } = data

  const nodeRows = graphOverview.nodeCounts.map(n =>
    `<tr><td>${esc(n.label)}</td><td>${n.count}</td></tr>`
  ).join('')

  return `
<div class="page-break"></div>
<div class="section" id="appendix">
  <h2 class="section-title">Appendix</h2>

  <h3>A. Graph Node Distribution</h3>
  <table class="data-table">
    <thead><tr><th>Node Type</th><th>Count</th></tr></thead>
    <tbody>${nodeRows}</tbody>
  </table>

  <h3>B. Assessment Tools</h3>
  <table class="data-table">
    <tbody>
      <tr><td>Platform</td><td>RedAmon — Automated Security Assessment Platform</td></tr>
      <tr><td>Reconnaissance</td><td>Subfinder, HTTPX, Katana, Naabu, GAU</td></tr>
      <tr><td>Vulnerability Scanning</td><td>Nuclei, GreenBone (GVM)</td></tr>
      <tr><td>Exploitation</td><td>Metasploit Framework</td></tr>
      <tr><td>Secret Detection</td><td>GitHub Hunt, TruffleHog, jsluice, JS Recon</td></tr>
      <tr><td>JS Analysis</td><td>JS Recon (dependency confusion, source maps, DOM sinks)</td></tr>
      <tr><td>Threat Intelligence</td><td>AlienVault OTX</td></tr>
      <tr><td>Graph Database</td><td>Neo4j</td></tr>
    </tbody>
  </table>

  <h3>C. Severity Definitions</h3>
  <table class="data-table">
    <thead><tr><th>Severity</th><th>CVSS Range</th><th>Description</th></tr></thead>
    <tbody>
      <tr><td>${sevBadge('critical')}</td><td>9.0 – 10.0</td><td>Immediate exploitation likely. Direct impact on confidentiality, integrity, or availability.</td></tr>
      <tr><td>${sevBadge('high')}</td><td>7.0 – 8.9</td><td>Significant risk. Exploitation is feasible and could lead to substantial damage.</td></tr>
      <tr><td>${sevBadge('medium')}</td><td>4.0 – 6.9</td><td>Moderate risk. Exploitation requires specific conditions or user interaction.</td></tr>
      <tr><td>${sevBadge('low')}</td><td>0.1 – 3.9</td><td>Minor risk. Limited impact, difficult to exploit, or informational.</td></tr>
    </tbody>
  </table>
</div>`
}

// ── CSS Styles ──────────────────────────────────────────────────────────────

const CSS_STYLES = `
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  font-size: 13px;
  line-height: 1.6;
  color: #1a1a1a;
  background: #fff;
  max-width: 1100px;
  margin: 0 auto;
  padding: 20px 40px;
}

/* Cover */
.cover {
  text-align: center;
  padding: 80px 40px 60px;
  border-bottom: 3px solid #1e293b;
  margin-bottom: 40px;
}
.cover-title {
  font-size: 32px;
  font-weight: 800;
  color: #0f172a;
  margin-bottom: 8px;
}
.cover-subtitle {
  font-size: 22px;
  font-weight: 600;
  color: #334155;
  margin-bottom: 4px;
}
.cover-domain {
  font-size: 16px;
  color: #64748b;
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
}
.cover-meta {
  margin-top: 40px;
  display: inline-block;
  text-align: left;
}
.cover-table td {
  padding: 6px 16px;
  vertical-align: middle;
}
.cover-label {
  font-weight: 600;
  color: #64748b;
  text-align: right;
}

/* Sections */
.section {
  margin-bottom: 40px;
}
.section-title {
  font-size: 20px;
  font-weight: 700;
  color: #0f172a;
  border-bottom: 2px solid #e2e8f0;
  padding-bottom: 8px;
  margin-bottom: 16px;
}

/* TOC */
.toc-list {
  list-style: none;
  padding: 0;
}
.toc-list li {
  padding: 6px 0;
  border-bottom: 1px dotted #e2e8f0;
}
.toc-list a {
  color: #2563eb;
  text-decoration: none;
  font-size: 14px;
}
.toc-list a:hover { text-decoration: underline; }

/* Narrative */
.narrative {
  background: #f8fafc;
  border-left: 3px solid #3b82f6;
  padding: 16px 20px;
  margin-bottom: 20px;
  font-size: 13.5px;
  line-height: 1.7;
  color: #334155;
  white-space: pre-wrap;
}

/* Metric cards */
.metric-cards {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 20px;
}
.metric-card {
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 16px 20px;
  min-width: 130px;
  text-align: center;
}
.metric-value {
  font-size: 24px;
  font-weight: 700;
  color: #0f172a;
}
.metric-label {
  font-size: 11px;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-top: 4px;
}
.metric-card-sm {
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  padding: 8px 14px;
  min-width: 70px;
  text-align: center;
  flex: 1;
}
.metric-value-sm {
  font-size: 18px;
  font-weight: 700;
  color: #0f172a;
}
.metric-label-sm {
  font-size: 9px;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.4px;
  margin-top: 2px;
}

/* Tables */
.data-table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 16px;
  font-size: 12.5px;
}
.data-table th {
  background: #f1f5f9;
  font-weight: 600;
  text-align: left;
  padding: 8px 12px;
  border-bottom: 2px solid #e2e8f0;
  color: #475569;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.3px;
}
.data-table td {
  padding: 7px 12px;
  border-bottom: 1px solid #f1f5f9;
  vertical-align: top;
}
.data-table tbody tr:hover {
  background: #f8fafc;
}

/* Findings */
.finding-card {
  padding: 14px 18px;
  margin-bottom: 12px;
  border-radius: 6px;
}
.finding-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}
.finding-num {
  font-weight: 700;
  color: #64748b;
  font-size: 14px;
}
.finding-title {
  font-weight: 600;
  font-size: 14px;
  color: #0f172a;
}
.finding-desc {
  color: #475569;
  margin-bottom: 10px;
}
.finding-details {
  width: 100%;
  font-size: 12px;
}
.finding-details td {
  padding: 4px 10px;
  vertical-align: top;
}
.finding-details td:first-child {
  font-weight: 600;
  color: #64748b;
  white-space: nowrap;
  width: 140px;
}

/* Status badges */
.status-open { color: #dc2626; font-weight: 600; font-size: 11px; }
.status-progress { color: #d97706; font-weight: 600; font-size: 11px; }
.status-done { color: #16a34a; font-weight: 600; font-size: 11px; }

/* Chain status */
.chain-status {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
}
.chain-status-completed { background: #dcfce7; color: #16a34a; }
.chain-status-running { background: #dbeafe; color: #2563eb; }
.chain-status-failed { background: #fef2f2; color: #dc2626; }
.chain-status-paused { background: #fef9c3; color: #a16207; }

/* Alerts */
.alert {
  padding: 12px 16px;
  border-radius: 6px;
  margin-bottom: 16px;
  font-weight: 500;
}
.alert-critical {
  background: #fef2f2;
  border-left: 4px solid #dc2626;
  color: #991b1b;
}

/* Layout */
.two-col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  margin-bottom: 20px;
}

/* Fireteam (multi-agent) */
#fireteams .ft-deployment {
  border-left: 4px solid #2563eb;
  background: #f5f9ff;
  padding: 12px 16px;
  border-radius: 6px;
  margin: 16px 0;
}
#fireteams .ft-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
#fireteams .ft-head h3 { margin: 0; }
#fireteams .ft-status {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #475569;
  font-weight: 600;
}
#fireteams .ft-rationale {
  font-size: 13px;
  color: #475569;
  margin: 4px 0 8px;
  font-style: italic;
}
#fireteams .ft-timing { font-size: 12px; margin: 4px 0 10px; }
#fireteams .ft-members {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 10px;
}
#fireteams .ft-member {
  background: #ffffff;
  border: 1px solid #e2e8f0;
  border-radius: 5px;
  padding: 10px 12px;
  font-size: 12.5px;
}
#fireteams .ft-member-head { display: flex; align-items: center; gap: 8px; }
#fireteams .ft-member-task { font-style: italic; color: #475569; margin: 4px 0; line-height: 1.45; }
#fireteams .ft-member-meta { font-size: 11.5px; color: #64748b; }
#fireteams .ft-member-reason { font-size: 11.5px; color: #92400e; margin-top: 4px; }
#fireteams .ft-member-error {
  font-size: 11.5px; color: #b91c1c;
  background: #fef2f2; padding: 4px 6px;
  border-left: 2px solid #ef4444; border-radius: 3px;
  margin-top: 4px;
}
#fireteams .badge-ok, #fireteams .badge-warn, #fireteams .badge-err {
  font-size: 10.5px; padding: 2px 8px; border-radius: 10px; text-transform: uppercase;
  letter-spacing: 0.04em; font-weight: 600;
}
#fireteams .badge-ok { background: #d1fae5; color: #065f46; }
#fireteams .badge-warn { background: #fef3c7; color: #92400e; }
#fireteams .badge-err { background: #fee2e2; color: #991b1b; }

/* Misc */
.muted { color: #94a3b8; font-style: italic; }
h3 {
  font-size: 15px;
  font-weight: 600;
  color: #1e293b;
  margin: 20px 0 10px;
}
.pre-wrap {
  white-space: pre-wrap;
  word-break: break-word;
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 11.5px;
  background: #f8fafc;
  padding: 8px;
  border-radius: 4px;
  border: 1px solid #e2e8f0;
}

/* Footer */
.footer {
  margin-top: 60px;
  padding-top: 20px;
  border-top: 2px solid #e2e8f0;
  text-align: center;
  color: #94a3b8;
  font-size: 11px;
}

/* Print */
@media print {
  body { padding: 0; max-width: none; }
  .page-break { page-break-before: always; }
  .cover { page-break-after: always; }
  .finding-card { page-break-inside: avoid; }
  .data-table tr { page-break-inside: avoid; }
  .metric-cards { page-break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
  .narrative { border-left-color: #999; }
  svg { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  div[style*="background"] { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
}

@page {
  size: A4;
  margin: 15mm 20mm;
}
`
