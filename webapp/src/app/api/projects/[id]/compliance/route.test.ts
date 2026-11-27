import { describe, expect, it, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const { mockRequirePermission, mockGatherReportData } = vi.hoisted(() => ({
  mockRequirePermission: vi.fn(),
  mockGatherReportData: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => ({
  requirePermission: mockRequirePermission,
}))

vi.mock('@/lib/report/reportData', () => ({
  gatherReportData: mockGatherReportData,
}))

import { GET } from './route'

describe('GET /api/projects/[id]/compliance', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns 403 when requirePermission denies access', async () => {
    mockRequirePermission.mockResolvedValue(
      NextResponse.json({ code: 'forbidden', error: 'Forbidden' }, { status: 403 })
    )

    const req = new NextRequest('http://localhost/api/projects/p1/compliance')
    const res = await GET(req, { params: Promise.resolve({ id: 'p1' }) })
    expect(res.status).toBe(403)
    expect(mockRequirePermission).toHaveBeenCalledWith(req, 'reports:read', { projectId: 'p1' })
    expect(mockGatherReportData).not.toHaveBeenCalled()
  })

  it('evaluates configured RoE frameworks or ?frameworks= query override', async () => {
    mockRequirePermission.mockResolvedValue({ user: { id: 'u1' } })
    mockGatherReportData.mockResolvedValue({
      project: { ipMode: false, roeComplianceFrameworks: ['PCI-DSS 4.0'], roeForbiddenCategories: [] },
      graphOverview: { totalNodes: 4 },
      vulnerabilities: { severityDistribution: [] },
      tlsx: { totalCertificates: 1, expired: 0, mismatched: 0, selfSigned: 0 },
      secrets: { total: 0 },
      trufflehog: { sources: [], totalFindings: 0 },
      githubSecrets: { reposScanned: 0, totalSecrets: 0 },
      supplyChain: { totalPackages: 0, maliciousCount: 0, suspiciousCount: 0, findings: [] },
      graphqlScan: { endpointsTested: 0, totalFindings: 0 },
      webCachePoison: { totalFindings: 0 },
      jsRecon: { totalFindings: 0 },
      aiSurface: { totalAiEndpoints: 0, attackToolsRun: [], attackFindings: [] },
      metrics: {
        totalVulnerabilities: 0,
        totalRemediations: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        totalCves: 0,
        cveCriticalCount: 0,
        cveHighCount: 0,
        attackSurfaceSize: 2,
      },
    })

    const req = new NextRequest('http://localhost/api/projects/p1/compliance?frameworks=owasp_asvs_4_0')
    const res = await GET(req, { params: Promise.resolve({ id: 'p1' }) })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.projectId).toBe('p1')
    expect(body.frameworks).toHaveLength(1)
    expect(body.frameworks[0].framework).toBe('owasp_asvs_4_0')
  })
})
