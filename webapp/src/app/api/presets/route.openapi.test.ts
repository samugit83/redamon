/** @vitest-environment node */
import { beforeEach, expect, test, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ create: vi.fn(), findUnique: vi.fn() }))
vi.mock('@/lib/prisma', () => ({ default: { userProjectPreset: h } }))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn(async () => ({ userId: 'u1' })),
  assertOwner: vi.fn(() => null),
  ownerScope: vi.fn(() => ({ userId: 'u1' })),
}))

import { POST } from './route'
import { GET } from './[id]/route'

const settings = {
  openapiEnabled: true,
  openapiSources: [{ url: 'https://example.test/spec', headers: ['Authorization: legacy-secret'] }],
  openapiDiscoveryHeaders: [{ origin: 'https://example.test', headers: ['Cookie: legacy-secret'] }],
}

beforeEach(() => {
  vi.clearAllMocks()
  h.create.mockResolvedValue({ id: 'p1', name: 'preset' })
  h.findUnique.mockResolvedValue({ id: 'p1', userId: 'u1', name: 'preset', settings })
})

test('saving a preset excludes OpenAPI source and discovery credentials', async () => {
  const response = await POST(new NextRequest('http://x/api/presets', {
    method: 'POST', body: JSON.stringify({ name: 'preset', settings }),
  }))
  expect(response.status).toBe(201)
  expect(h.create.mock.calls[0][0].data.settings).toEqual({ openapiEnabled: true })
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
