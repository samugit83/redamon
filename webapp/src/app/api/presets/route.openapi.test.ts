/** @vitest-environment node */
import { beforeEach, expect, test, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ create: vi.fn(), findUnique: vi.fn() }))
vi.mock('@/lib/prisma', () => ({ default: { userProjectPreset: h } }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn(async () => ({ userId: 'u1' })),
  assertOwner: vi.fn(() => null),
  ownerScope: vi.fn(() => ({ userId: 'u1' })),
}))

import { POST } from './route'
import { GET } from './[id]/route'

const settings = {
  openapiEnabled: true,
  openapiSources: [{ url: 'https://example.test/spec?token=source-secret' }],
}

beforeEach(() => {
  vi.clearAllMocks()
  h.create.mockResolvedValue({ id: 'p1', name: 'preset' })
  h.findUnique.mockResolvedValue({ id: 'p1', userId: 'u1', name: 'preset', settings })
})

test('saving a preset excludes the OpenAPI document sources', async () => {
  const response = await POST(new NextRequest('http://x/api/presets', {
    method: 'POST', body: JSON.stringify({ name: 'preset', settings }),
  }))
  expect(response.status).toBe(201)
  const saved = h.create.mock.calls[0][0].data.settings
  expect(saved.openapiEnabled).toBe(true)
  expect(saved).not.toHaveProperty('openapiSources')
  expect(JSON.stringify(saved)).not.toContain('source-secret')
})

test('reading a legacy preset excludes project-specific OpenAPI settings', async () => {
  const response = await GET(new NextRequest('http://x/api/presets/p1'), {
    params: Promise.resolve({ id: 'p1' }),
  })
  expect(response.status).toBe(200)
  const body = await response.json()
  expect(body.settings).toEqual({ openapiEnabled: true })
  expect(JSON.stringify(body)).not.toContain('legacy-secret')
  expect(settings.openapiSources).toHaveLength(1)
})
