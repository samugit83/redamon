/** Project teardown ends AI Navigator answers right after the agent chats, before the row goes (plan §5.7). */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { TEARDOWN_STEPS } from './projectTeardown'

describe('TEARDOWN_STEPS', () => {
  test('stop_navigator follows stop_chats and comes before the project row is deleted', () => {
    const i = TEARDOWN_STEPS.indexOf('stop_navigator')
    expect(i).toBe(TEARDOWN_STEPS.indexOf('stop_chats') + 1)
    expect(i).toBeLessThan(TEARDOWN_STEPS.indexOf('delete_project'))
  })
})
