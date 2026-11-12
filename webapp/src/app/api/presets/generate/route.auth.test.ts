/**
 * B-1: POST /api/presets/generate spends a user's LLM key, so WHOSE key it
 * spends must come from the session.
 *
 * It used to read `userId` from the request body and had no route-level auth,
 * so any caller could name another user and generate on their provider.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockProviders = vi.fn()
const mockEffectiveUser = vi.fn()

const mockSettings = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userLlmProvider: { findMany: (...a: unknown[]) => mockProviders(...a) },
    userSettings: { findUnique: (...a: unknown[]) => mockSettings(...a) },
  },
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => mockEffectiveUser() }))

import { POST } from './route'

function generate(body: Record<string, unknown>) {
  return POST(new NextRequest('http://localhost/api/presets/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }))
}

beforeEach(() => {
  vi.clearAllMocks()
  mockProviders.mockResolvedValue([])
  mockSettings.mockResolvedValue({ featureModels: { preset_generator: 'gpt-4o' } })
  mockEffectiveUser.mockResolvedValue({ userId: 'session-user', isAdmin: false })
})

describe('preset generation is bound to the session user', () => {
  test('no session is a 401 and reads no provider', async () => {
    mockEffectiveUser.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    const res = await generate({ userId: 'victim', model: 'gpt-4o', prompt: 'stealth' })
    expect(res.status).toBe(401)
    expect(mockProviders).not.toHaveBeenCalled()
  })

  test('a userId in the body is ignored: the providers read are the session user\'s', async () => {
    await generate({ userId: 'victim', model: 'gpt-4o', prompt: 'stealth' })
    expect(mockProviders).toHaveBeenCalledWith({ where: { userId: 'session-user' } })
  })

  test('a body without userId is no longer a 400', async () => {
    const res = await generate({ model: 'gpt-4o', prompt: 'stealth' })
    // No provider configured, so it stops at provider resolution, past the
    // point where a missing body userId used to refuse it.
    expect((await res.json()).error ?? '').not.toContain('userId is required')
  })
})
