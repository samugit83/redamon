/**
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const findUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({ default: { userSettings: { findUnique: (...a: unknown[]) => findUnique(...a) } } }))

import { githubTokenForImport } from './githubToken'

beforeEach(() => {
  findUnique.mockReset().mockResolvedValue({ githubAccessToken: 'TEST-SENTINEL-TOKEN-0000' })
})

describe('githubTokenForImport', () => {
  test('reads only the token, for a GitHub link', async () => {
    expect(await githubTokenForImport('u1', 'https://github.com/o/r')).toBe('TEST-SENTINEL-TOKEN-0000')
    expect(findUnique).toHaveBeenCalledWith({ where: { userId: 'u1' }, select: { githubAccessToken: true } })
  })

  test('other hosts never read it', async () => {
    expect(await githubTokenForImport('u1', 'https://gitlab.com/o/r')).toBe('')
    expect(await githubTokenForImport('u1', 'https://github.com.example.test/o/r')).toBe('')
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('no settings row is no token', async () => {
    findUnique.mockResolvedValue(null)
    expect(await githubTokenForImport('u1', 'https://github.com/o/r')).toBe('')
  })
})
