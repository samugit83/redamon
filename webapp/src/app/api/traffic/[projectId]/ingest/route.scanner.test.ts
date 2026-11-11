/**
 * Step 1.16 (HD-20): recon posts captured traffic with the scanner key AND its scan's
 * job credential, and writes only into the project that credential names. The bare
 * scanner key writes nothing; the agent's master key is unchanged.
 *
 * The real session and credential helpers run; Prisma is a double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const MASTER = 'internal-key-for-tests-0000000000000'
const SCANNER = 'scanner-key-for-tests-00000000000000'
vi.stubEnv('INTERNAL_API_KEY', MASTER)
vi.stubEnv('SCANNER_API_KEY', SCANNER)

const h = vi.hoisted(() => ({ written: [] as unknown[] }))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async () => ({ userId: 'owner-1', captureProxyEnabled: true }) },
    capturedHttpTransaction: {
      createMany: async ({ data }: { data: unknown[] }) => {
        h.written.push(...data)
        return { count: data.length }
      },
    },
  },
}))

import { mintJobCredential } from '@/lib/authz/machineCredential'
import { POST } from './route'

const TXN = { method: 'GET', url: 'http://app.example.test/', statusCode: 200, host: 'app.example.test' }

function post(projectId: string, headers: Record<string, string>) {
  return POST(
    new NextRequest(`http://localhost/api/traffic/${projectId}/ingest`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify({ source: 'recon', runId: 'run-1', transactions: [TXN] }),
    }),
    { params: Promise.resolve({ projectId }) },
  )
}

beforeEach(() => {
  h.written = []
  vi.restoreAllMocks()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe("scanner key ingests only into the credential's project", () => {
  test('with a credential for this project the transactions are stored', async () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    const res = await post('proj-1', { 'x-internal-key': SCANNER, 'x-redamon-job': token })
    expect(res.status).toBe(201)
    expect(h.written).toHaveLength(1)
  })

  test('a credential for another project writes nothing', async () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    const res = await post('proj-2', { 'x-internal-key': SCANNER, 'x-redamon-job': token })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'job_credential_required', reason: 'project_mismatch' })
    expect(h.written).toEqual([])
  })

  test('the bare scanner key writes nothing', async () => {
    const res = await post('proj-1', { 'x-internal-key': SCANNER })
    expect(res.status).toBe(403)
    expect((await res.json()).reason).toBe('missing')
    expect(h.written).toEqual([])
  })

  test('a credential without either key is refused before anything', async () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    const res = await post('proj-1', { 'x-redamon-job': token })
    expect(res.status).toBe(401)
    expect(h.written).toEqual([])
  })

  test('the master key (the agent) ingests without a credential, as before', async () => {
    const res = await post('proj-2', { 'x-internal-key': MASTER })
    expect(res.status).toBe(201)
    expect(h.written).toHaveLength(1)
  })
})
