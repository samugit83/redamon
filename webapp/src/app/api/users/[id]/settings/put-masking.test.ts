/**
 * PUT /api/users/[id]/settings masks every secret it returns, exactly like the
 * GET. It used to mask only the API-key columns, so a save echoed the Secret
 * Multiscanner credentials (GitLab/Postman/AWS/GCP...) back in cleartext - even
 * ones the browser had sent masked and never held.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { TRUFFLEHOG_KEY_FIELDS } from '@/lib/credentialFields'

const STORED = Object.fromEntries(TRUFFLEHOG_KEY_FIELDS.map((f, i) => [f.name, `STORED-SECRET-${f.name}-${1000 + i}`]))

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: async () => ({ userId: 'u1', ...STORED, shodanApiKey: 'STORED-SHODAN-KEY-9999' }),
      upsert: async ({ update }: { update: Record<string, unknown> }) => ({
        userId: 'u1', ...STORED, shodanApiKey: 'STORED-SHODAN-KEY-9999', githubEnterpriseHost: 'ghe.example.test', ...update,
      }),
    },
    apiKeyRotationConfig: { findMany: async () => [] },
  },
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: async () => null,
  isInternalRequest: () => false,
  isScannerRequest: () => false,
  getSession: async () => ({ userId: 'u1', role: 'standard' }),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { PUT } from './route'

describe('PUT response masking', () => {
  test('a save that sends masked values back returns every credential masked', async () => {
    const masked = Object.fromEntries(TRUFFLEHOG_KEY_FIELDS.map(f => [f.name, '••••••••xxxx']))
    const res = await PUT(
      new NextRequest('http://x', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...masked, shodanApiKey: '••••••••9999' }) }),
      { params: Promise.resolve({ id: 'u1' }) },
    )
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toContain('STORED-SECRET')
    expect(text).not.toContain('STORED-SHODAN-KEY')
    const body = JSON.parse(text)
    for (const f of TRUFFLEHOG_KEY_FIELDS) {
      expect(body[f.name], f.name).toMatch(/^••••••••\d{4}$/)
    }
    // Configuration, not a secret: still readable.
    expect(body.githubEnterpriseHost).toBe('ghe.example.test')
  })
})
