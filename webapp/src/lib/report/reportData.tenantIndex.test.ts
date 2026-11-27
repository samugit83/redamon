import { describe, expect, it, vi } from 'vitest'

const { capturedRuns, mockSession, mockPrisma } = vi.hoisted(() => {
  const runs: Array<{ query: string; params: Record<string, unknown> }> = []
  const session = {
    run: vi.fn(async (query: string, params: Record<string, unknown> = {}) => {
      runs.push({ query, params })
      return { records: [] }
    }),
    close: vi.fn(async () => {}),
  }
  const mockProject = {
    id: 'proj-1',
    userId: 'owner-42',
    name: 'Test Project',
    targetDomain: 'example.test',
    ipMode: false,
    targetIps: [],
    subdomainList: [],
    roeEnabled: false,
    roeDocumentName: null,
    roeClientName: null,
    roeClientContact: null,
    roeEmergencyContact: null,
    roeEngagementStartDate: null,
    roeEngagementEndDate: null,
    roeEngagementType: null,
    roeExcludedHosts: [],
    roeAllowedPorts: [],
    roeTimeWindowEnabled: false,
    roeTimeWindowTimezone: null,
    roeTimeWindowDays: [],
    roeTimeWindowStartTime: null,
    roeTimeWindowEndTime: null,
    roeForbiddenCategories: [],
    roeMaxSeverityPhase: null,
    roeAllowDos: false,
    roeAllowSocialEngineering: false,
    roeAllowPhysicalAccess: false,
    roeAllowDataExfiltration: false,
    roeAllowAccountLockout: false,
    roeAllowProductionChanges: false,
    roeGlobalMaxRps: null,
    roeSensitiveDataHandling: null,
    roeDataRetentionDays: null,
    roeRequireDataEncryption: false,
    roeComplianceFrameworks: [],
    roeAuthorizationDocUrl: null,
    roeAuthorizationSignatory: null,
    roeAuthorizationDate: null,
    roeNotes: null,
    ipHostnamePolicy: null,
  }
  const prisma = {
    project: {
      findUnique: vi.fn(async () => mockProject),
      findUniqueOrThrow: vi.fn(async () => mockProject),
    },
    remediation: {
      findMany: vi.fn(async () => []),
    },
    reconRun: {
      findMany: vi.fn(async () => []),
      findFirst: vi.fn(async () => null),
    },
    agentRun: {
      findMany: vi.fn(async () => []),
    },
    jsReconCustomPattern: {
      findMany: vi.fn(async () => []),
    },
  }
  return { capturedRuns: runs, mockSession: session, mockPrisma: prisma }
})

vi.mock('@/lib/prisma', () => ({ default: mockPrisma }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => mockSession,
}))

import {
  gatherReportData,
  queryAttackChains,
  queryAttackSurface,
  queryCveIntelligence,
  queryGraphOverview,
  queryJsRecon,
  querySecrets,
  queryTlsx,
  queryVulnerabilities,
} from './reportData'
import { githubSecretCountsCypher } from '@/lib/secrets/githubSecretCounts'
import { queryJudgedFindings } from '@/lib/triage/reportable'

describe('reportData composite (user_id, project_id) index alignment', () => {
  it('scopes githubSecretCountsCypher by (user_id, project_id) only when uid is provided', () => {
    expect(githubSecretCountsCypher('u-1')).toContain('(d:Domain {user_id: $uid, project_id: $pid})')
    expect(githubSecretCountsCypher()).toContain('(d:Domain {project_id: $pid})')
    expect(githubSecretCountsCypher()).not.toContain('user_id')
  })

  it('scopes queryJudgedFindings by n.user_id = $uid when uid is provided', async () => {
    capturedRuns.length = 0
    await queryJudgedFindings(mockSession, 'proj-1', 'u-1')
    expect(capturedRuns).toHaveLength(1)
    expect(capturedRuns[0].query).toContain('n.user_id = $uid AND n.project_id = $pid')
    expect(capturedRuns[0].params).toEqual({ pid: 'proj-1', uid: 'u-1' })

    capturedRuns.length = 0
    await queryJudgedFindings(mockSession, 'proj-1')
    expect(capturedRuns).toHaveLength(1)
    expect(capturedRuns[0].query).toContain('n.project_id = $pid')
    expect(capturedRuns[0].query).not.toContain('n.user_id')
    expect(capturedRuns[0].params).toEqual({ pid: 'proj-1' })
  })

  it('passes { uid, pid } and composite property filters for all exported query helpers', async () => {
    const uid = 'owner-99'
    const pid = 'proj-99'
    const callers = [
      () => queryGraphOverview(mockSession, pid, null, uid),
      () => queryAttackSurface(mockSession, pid, uid),
      () => queryVulnerabilities(mockSession, pid, uid),
      () => queryCveIntelligence(mockSession, pid, uid),
      () => queryAttackChains(mockSession, pid, uid),
      () => querySecrets(mockSession, pid, uid),
      () => queryJsRecon(mockSession, pid, uid),
      () => queryTlsx(mockSession, pid, uid),
    ]

    for (const call of callers) {
      capturedRuns.length = 0
      await call()
      expect(capturedRuns.length).toBeGreaterThan(0)
      for (const { query, params } of capturedRuns) {
        expect(params.pid).toBe(pid)
        expect(params.uid).toBe(uid)
        const usesCompositeMatch =
          query.includes('user_id: $uid, project_id: $pid') ||
          query.includes('user_id = $uid AND')
        expect(usesCompositeMatch).toBe(true)
        // Global reference nodes must never be tenant-filtered.
        expect(query).not.toMatch(/:(CVE|MitreData|Capec)\s*\{[^}]*(user_id|project_id)/)
      }
    }
  })

  it('preserves legacy {project_id: $pid} fallback when uid is omitted', async () => {
    capturedRuns.length = 0
    await queryGraphOverview(mockSession, 'proj-legacy')
    expect(capturedRuns.length).toBeGreaterThan(0)
    for (const { query, params } of capturedRuns) {
      expect(params.pid).toBe('proj-legacy')
      expect(params.uid).toBeUndefined()
      expect(query).not.toContain('$uid')
    }
  })

  it('threads project.userId from gatherReportData to every Neo4j query', async () => {
    capturedRuns.length = 0
    await gatherReportData('proj-1')
    expect(capturedRuns.length).toBeGreaterThan(15)
    for (const { query, params } of capturedRuns) {
      if ('pid' in params) {
        expect(params.pid).toBe('proj-1')
        expect(params.uid).toBe('owner-42')
      }
      expect(query).not.toMatch(/:(CVE|MitreData|Capec)\s*\{[^}]*(user_id|project_id)/)
    }
  })
})
