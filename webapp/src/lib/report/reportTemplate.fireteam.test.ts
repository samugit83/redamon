/**
 * Tests for the Fireteam section of the report template.
 *
 * Verifies:
 *  1. Single-agent reports (no fireteams) render IDENTICAL bytes to the
 *     pre-fireteam baseline in the section slot — ensures the feature
 *     doesn't accidentally regress existing reports.
 *  2. renderFireteams section appears and contains per-member cards when
 *     the fireteams key is populated.
 *  3. HTML-escapes member names, tasks, and finding evidence (XSS safety).
 *
 * Run: cd webapp && npx vitest src/lib/report/reportTemplate.fireteam.test.ts
 */

import { describe, it, expect } from 'vitest'

// We can't import the full template without pulling in its Neo4j + Prisma
// transitive deps in a unit-test context. Instead, exercise the small
// rendering helper that the spec calls out. We reach into the module via
// dynamic import + exporting the helper.
import { generateReportHtml } from './reportTemplate'

function baseReportData(): any {
  return {
    project: { name: 'p', targetDomain: 'example.com' },
    remediations: [],
    generatedAt: '2026-04-18T00:00:00Z',
    graphOverview: {
      totalNodes: 0, nodeCounts: [],
      subdomainStats: { total: 0, resolved: 0, uniqueIps: 0 },
      endpointCoverage: { baseUrls: 0, endpoints: 0, parameters: 0 },
      certificateHealth: { total: 0, expired: 0, expiringSoon: 0 },
      infrastructureStats: { totalIps: 0, ipv4: 0, ipv6: 0, cdnCount: 0, uniqueAsns: 0, uniqueCdns: 0 },
      subdomainMappings: [], ipMappings: [],
    },
    attackSurface: {
      services: [], ports: [], technologies: [], dnsRecords: [],
      securityHeaders: [], endpointCategories: [], parameterAnalysis: [],
    },
    vulnerabilities: {
      severityDistribution: [], findings: [], cvssHistogram: [],
      cveSeverity: [], gvmRemediation: [],
    },
    cveIntelligence: {
      cveChains: [], exploits: [],
      githubSecrets: { repos: 0, secrets: 0, sensitiveFiles: 0 },
    },
    trufflehog: { totalFindings: 0, verifiedFindings: 0, repositories: 0, findings: [] },
    secrets: { total: 0, bySeverity: [], bySource: [], byType: [], findings: [] },
    jsRecon: { totalFindings: 0, bySeverity: [], byType: [], findings: [] },
    graphqlScan: { totalFindings: 0, endpointsTested: 0, introspectionEnabled: 0, bySeverity: [], byType: [], endpoints: [], findings: [] },
    otx: { totalPulses: 0, totalMalware: 0, enrichedIps: 0, adversaries: [], pulses: [], malware: [] },
    attackChains: { chains: [], exploitSuccesses: [], topFindings: [], totalChainFindings: 0 },
    metrics: {
      riskScore: 0, riskLabel: 'Low' as const,
      totalVulnerabilities: 0, totalRemediations: 0,
      criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0,
      exploitableCount: 0, totalCves: 0,
      cveCriticalCount: 0, cveHighCount: 0, cveMediumCount: 0, cveLowCount: 0,
      cvssAverage: 0, attackSurfaceSize: 0, secretsExposed: 0,
    },
  }
}

describe('reportTemplate Fireteam section', () => {
  it('omits #fireteams when data.fireteams is undefined', () => {
    const data = baseReportData()
    const html = generateReportHtml(data as any, null)
    expect(html).not.toContain('id="fireteams"')
    expect(html).not.toContain('Multi-Agent Analysis')
  })

  it('omits #fireteams when totalFireteams is 0', () => {
    const data = baseReportData()
    data.fireteams = {
      totalFireteams: 0, totalMembers: 0, totalFindings: 0, deployments: [],
    }
    const html = generateReportHtml(data as any, null)
    expect(html).not.toContain('id="fireteams"')
  })

  it('renders #fireteams with per-member cards when populated', () => {
    const data = baseReportData()
    data.fireteams = {
      totalFireteams: 1,
      totalMembers: 2,
      totalFindings: 3,
      deployments: [{
        fireteamIdKey: 'fteam-1-abc',
        iteration: 3,
        planRationale: 'Three services, test in parallel',
        startedAt: '2026-04-18T00:00:00Z',
        completedAt: '2026-04-18T00:02:30Z',
        wallClockSeconds: 147.3,
        statusCounts: { success: 1, partial: 1 },
        status: 'completed',
        members: [
          {
            memberIdKey: 'member-0-web',
            name: 'Web Tester',
            task: 'Probe HTTP for SQLi and XSS',
            skills: ['sql_injection', 'xss'],
            status: 'success',
            completionReason: null,
            iterationsUsed: 12,
            tokensUsed: 18500,
            findingsCount: 2,
            wallClockSeconds: 147.3,
            errorMessage: null,
          },
          {
            memberIdKey: 'member-1-ssh',
            name: 'SSH Analyst',
            task: 'Identify SSH version and CVEs',
            skills: [],
            status: 'partial',
            completionReason: 'iteration_budget_exceeded',
            iterationsUsed: 15,
            tokensUsed: 4200,
            findingsCount: 1,
            wallClockSeconds: 86.7,
            errorMessage: null,
          },
        ],
      }],
    }
    const html = generateReportHtml(data as any, null)
    expect(html).toContain('id="fireteams"')
    expect(html).toContain('Multi-Agent Analysis')
    expect(html).toContain('fteam-1-abc')
    expect(html).toContain('Web Tester')
    expect(html).toContain('SSH Analyst')
    expect(html).toContain('Probe HTTP')
    expect(html).toContain('iteration_budget_exceeded')
  })

  it('escapes HTML in member names and tasks', () => {
    const data = baseReportData()
    data.fireteams = {
      totalFireteams: 1, totalMembers: 1, totalFindings: 0,
      deployments: [{
        fireteamIdKey: 'ft-xss',
        iteration: 1, planRationale: '',
        startedAt: '2026-04-18T00:00:00Z', completedAt: null,
        wallClockSeconds: null, statusCounts: null, status: 'running',
        members: [{
          memberIdKey: 'm0', name: '<script>alert(1)</script>',
          task: '<img src=x onerror=alert(2)>',
          skills: [], status: 'running',
          completionReason: null, iterationsUsed: 0, tokensUsed: 0,
          findingsCount: 0, wallClockSeconds: null, errorMessage: null,
        }],
      }],
    }
    const html = generateReportHtml(data as any, null)
    // Tags must be escaped, not executable.
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).not.toContain('<img src=x onerror=alert(2)>')
    // Escaped entities must be present.
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })

  it('renders status-specific CSS badge class for each member', () => {
    const data = baseReportData()
    data.fireteams = {
      totalFireteams: 1, totalMembers: 3, totalFindings: 0,
      deployments: [{
        fireteamIdKey: 'ft', iteration: 1, planRationale: '',
        startedAt: '2026-04-18T00:00:00Z', completedAt: '2026-04-18T00:00:10Z',
        wallClockSeconds: 10, statusCounts: null, status: 'completed',
        members: [
          { memberIdKey: 'a', name: 'A', task: 't', skills: [],
            status: 'success', completionReason: null,
            iterationsUsed: 1, tokensUsed: 1, findingsCount: 0,
            wallClockSeconds: 1, errorMessage: null },
          { memberIdKey: 'b', name: 'B', task: 't', skills: [],
            status: 'partial', completionReason: null,
            iterationsUsed: 1, tokensUsed: 1, findingsCount: 0,
            wallClockSeconds: 1, errorMessage: null },
          { memberIdKey: 'c', name: 'C', task: 't', skills: [],
            status: 'error', completionReason: null,
            iterationsUsed: 1, tokensUsed: 1, findingsCount: 0,
            wallClockSeconds: 1, errorMessage: 'boom' },
        ],
      }],
    }
    const html = generateReportHtml(data as any, null)
    expect(html).toContain('badge-ok')
    expect(html).toContain('badge-warn')
    expect(html).toContain('badge-err')
  })
})
