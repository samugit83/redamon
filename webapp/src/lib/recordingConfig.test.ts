/** @vitest-environment node */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockFindFirst = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { recordingSession: { findFirst: (...a: unknown[]) => mockFindFirst(...a) } },
}))

import { activeRecordingBlock } from './recordingConfig'

const SESSION = {
  id: 'rec1', projectId: 'p1', userId: 'u1',
  scopeHosts: ['app.target.test'], expiresAt: new Date('2099-01-01T00:00:00Z'),
  project: { id: 'p1', captureProxyEnabled: true },
}

beforeEach(() => {
  vi.clearAllMocks()
  process.env.INTERNAL_API_KEY = 'test-key-123'
})

describe('activeRecordingBlock', () => {
  test('mints an operator tag block for a live session', async () => {
    mockFindFirst.mockResolvedValue(SESSION)
    const block = await activeRecordingBlock()
    expect(block).toMatchObject({ scope_hosts: ['app.target.test'], expires_at: '2099-01-01T00:00:00.000Z' })
    expect(block!.tag.split('.')).toHaveLength(2)
    // The tag must not leak any secret; it only carries ids.
    expect(block!.tag).not.toContain('test-key-123')
  })

  test('null when no session', async () => {
    mockFindFirst.mockResolvedValue(null)
    expect(await activeRecordingBlock()).toBeNull()
  })

  test('null when the project has capture disabled', async () => {
    mockFindFirst.mockResolvedValue({ ...SESSION, project: { id: 'p1', captureProxyEnabled: false } })
    expect(await activeRecordingBlock()).toBeNull()
  })

  test('null when INTERNAL_API_KEY is unset/default', async () => {
    mockFindFirst.mockResolvedValue(SESSION)
    process.env.INTERNAL_API_KEY = 'changeme'
    expect(await activeRecordingBlock()).toBeNull()
  })
})
