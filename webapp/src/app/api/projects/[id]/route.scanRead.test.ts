/**
 * GHSA-8whg-rvcr-r88r (related finding): a scan container's project read handed it the owner's
 * secrets that no scan uses, the CypherFix GitHub token above all.
 *
 * A scan reads its project with the scanner key beside its job credential, and that read
 * returned the whole row, as the agent's does. Scan containers face the target, so one that a
 * hostile target compromised could take a token that pushes to the client's repositories. It now
 * gets the row without the owner's secret columns that are not a recon setting
 * (SCAN_UNREAD_SECRET_FIELDS); the header lists and the other recon settings it scans with stay,
 * and the agent (master key) still reads the whole row.
 *
 * The scanner key and the job credential are real (minted here); Prisma is mocked.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'

const MASTER = 'internal-key-for-tests-0000000000000'
const SCANNER = 'scanner-key-for-tests-000000000000'
vi.stubEnv('INTERNAL_API_KEY', MASTER)
vi.stubEnv('SCANNER_API_KEY', SCANNER)

const FAKE = 'scan-read-fake-secret-0001'

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: async ({ where }: { where: { id: string } }) => ({
        id: where.id, userId: 'owner-1', name: 'p', targetDomain: 'example.test', ipMode: false,
        domainBatchMode: false, nucleiSelectedCustomTemplates: [], nucleiTemplates: [], nucleiCustomTemplates: [],
        cypherfixGithubToken: FAKE,
        phishingSmtpConfig: { host: 'smtp.example.test', password: FAKE },
        roeClientName: 'Client Ltd',
        roeClientContactEmail: 'client@e2e.local',
        roeRawText: FAKE,
        roeParsedJson: { notes: FAKE },
        roeDocumentData: Buffer.from(FAKE),
        graphqlAuthValue: `Bearer ${FAKE}`,
        httpxCustomHeaders: [`X-Api-Key: ${FAKE}`],
        ownershipToken: 'ownership-token-0001',
        graphqlAuthHeader: 'Authorization',
        user: { id: 'owner-1', name: 'Owner', email: 'owner@e2e.local' },
        authProfile: null,
        nodeFilter: null, nodeFilterExemptions: [],
      }),
    },
    nucleiTemplate: { findMany: async () => [] },
    userSettings: { findUnique: async () => null },
  },
}))
vi.mock('@/lib/userSkillAgentPayload', () => ({ userSkillsForAgent: async () => [] }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { GET } from './route'
import { mintJobCredential } from '@/lib/authz/machineCredential'
import { SCAN_UNREAD_SECRET_FIELDS } from '@/lib/authz/projectReadView'

function get(headers: Record<string, string>) {
  return GET(new NextRequest('http://localhost/api/projects/proj-1', { headers }), { params: Promise.resolve({ id: 'proj-1' }) })
}
const scanHeaders = () => ({
  'x-internal-key': SCANNER,
  'x-redamon-job': mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' }),
})

const NEVER_TO_A_SCAN = ['cypherfixGithubToken', 'phishingSmtpConfig', 'roeClientName', 'roeClientContactEmail',
  'roeRawText', 'roeParsedJson', 'roeDocumentData']

describe('GET /api/projects/[id] for a scan container (GHSA-8whg-rvcr-r88r)', () => {
  test('the owner secrets no scan uses are left out', async () => {
    const res = await get(scanHeaders())
    expect(res.status).toBe(200)
    const body = await res.json()
    for (const key of NEVER_TO_A_SCAN) expect(body, key).not.toHaveProperty(key)
    expect(JSON.stringify(body)).not.toContain('client@e2e.local')
  })

  test('the recon settings it scans with stay, secrets included', async () => {
    const body = await (await get(scanHeaders())).json()
    expect(body.graphqlAuthValue).toBe(`Bearer ${FAKE}`)
    expect(body.httpxCustomHeaders).toEqual([`X-Api-Key: ${FAKE}`])
    expect(body.ownershipToken).toBe('ownership-token-0001')
    expect(body).toMatchObject({ id: 'proj-1', userId: 'owner-1', targetDomain: 'example.test' })
  })

  test('the agent (master key) still reads the whole row', async () => {
    const body = await (await get({ 'x-internal-key': MASTER })).json()
    expect(body.cypherfixGithubToken).toBe(FAKE)
    expect(body.phishingSmtpConfig).toEqual({ host: 'smtp.example.test', password: FAKE })
    expect(body.roeRawText).toBe(FAKE)
  })

  test('the scanner key without a job credential reads nothing', async () => {
    const res = await get({ 'x-internal-key': SCANNER })
    expect(res.status).toBeGreaterThanOrEqual(400)
    expect(await res.text()).not.toContain(FAKE)
  })
})

describe('SCAN_UNREAD_SECRET_FIELDS comes from the registry', () => {
  test('it names the agent-only secrets and no recon setting', () => {
    for (const key of NEVER_TO_A_SCAN) expect(SCAN_UNREAD_SECRET_FIELDS).toContain(key)
    for (const key of ['graphqlAuthValue', 'httpxCustomHeaders', 'ownershipToken', 'kiterunnerHeaders']) {
      expect(SCAN_UNREAD_SECRET_FIELDS).not.toContain(key)
    }
  })
})
