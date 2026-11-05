/**
 * validateApplication and the Jev engine flags.
 *
 * A saved preset can name an engine flag (a user preset is a snapshot of a
 * project's settings). Applying one that switches a hook onto Jev needs the
 * project's explicit owner-owned Jev provider selection. The owner and selection
 * are read from the receiving project, never replayed from the preset.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockProjectFind = vi.fn()
const mockProviderFind = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userProjectPreset: { findFirst: vi.fn() },
    userSettings: { findUnique: vi.fn() },
    project: { findUnique: (...a: unknown[]) => mockProjectFind(...a) },
    userLlmProvider: { findFirst: (...a: unknown[]) => mockProviderFind(...a) },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { extractPresetSettings } from '@/lib/project-preset-utils'
import { validateApplication } from './server'

const row = (): Record<string, unknown> => ({
  ...extractPresetSettings({}),
  mcpKaliExecEnabled: false,
  updateGraphDb: true,
  targetDomain: 'lab.example.com',
})

beforeEach(() => {
  vi.clearAllMocks()
  mockProjectFind.mockResolvedValue({ userId: 'owner', jevProviderId: null })
  mockProviderFind.mockResolvedValue(null)
})

describe('validateApplication: a preset that switches a hook onto Jev', () => {
  const switchOn = () => {
    const current = row()
    return { current, application: { data: { ...current, ffufAiUseJev: true }, changed: ['ffufAiUseJev'] } }
  }

  test('with an explicit provider selection on the owner\'s account it is accepted', async () => {
    mockProviderFind.mockResolvedValue({ id: 'jev-selected' })
    mockProjectFind.mockResolvedValue({ userId: 'owner', jevProviderId: 'jev-selected' })
    const { current, application } = switchOn()
    expect(await validateApplication(application, current, 'p1', 'actor')).toBeNull()
    expect(mockProjectFind).toHaveBeenCalledWith({ where: { id: 'p1' }, select: { userId: true, jevProviderId: true } })
    expect(mockProviderFind).toHaveBeenCalledWith({ where: { id: 'jev-selected', userId: 'owner', providerType: { in: ['jev', 'jev_openrouter'] } }, select: { id: true } })
  })

  test('without a provider selection it is refused, keyless, so the caller does not say "re-save the preset"', async () => {
    const { current, application } = switchOn()
    const problem = await validateApplication(application, current, 'p1', 'actor')
    expect(problem).not.toBeNull()
    expect(problem!.key).toBe('')
    expect(problem!.error).toContain('ffufAiUseJev')
    expect(problem!.error).toContain('Settings')
    expect(problem!.error.endsWith('.')).toBe(false)
  })

  test('an account provider never implicitly configures an unselected project', async () => {
    mockProviderFind.mockResolvedValue({ id: 'jev-selected' })
    const { current, application } = switchOn()
    const problem = await validateApplication(application, current, 'p1', 'actor')
    expect(problem?.key).toBe('')
    expect(problem?.error).toContain('select an explicit Jev provider')
    expect(mockProviderFind).not.toHaveBeenCalled()
  })

  test('an unavailable selected provider is refused, keyless', async () => {
    mockProjectFind.mockResolvedValue({ userId: 'owner', jevProviderId: 'jev-selected' })
    const { current, application } = switchOn()
    const problem = await validateApplication(application, current, 'p1', 'actor')
    expect(problem?.key).toBe('')
    expect(problem?.error).toContain('does not belong to the project owner')
    expect(mockProviderFind).toHaveBeenCalledWith({
      where: { id: 'jev-selected', userId: 'owner', providerType: { in: ['jev', 'jev_openrouter'] } },
      select: { id: true },
    })
  })

  test('it fails closed when the selected provider lookup throws', async () => {
    mockProjectFind.mockResolvedValue({ userId: 'owner', jevProviderId: 'jev-selected' })
    mockProviderFind.mockRejectedValue(new Error('db down'))
    const { current, application } = switchOn()
    expect(await validateApplication(application, current, 'p1', 'actor')).toEqual({
      key: '', error: "Couldn't verify the project's Jev provider, try again",
    })
  })

  test('it fails closed when the project owner or selection cannot be read', async () => {
    mockProjectFind.mockRejectedValue(new Error('db down'))
    const { current, application } = switchOn()
    const problem = await validateApplication(application, current, 'p1', 'actor')
    expect(problem?.error).toContain("Couldn't verify the project's Jev provider")
  })

  test('it fails closed when the project has no owner', async () => {
    mockProjectFind.mockResolvedValue(null)
    const { current, application } = switchOn()
    expect(await validateApplication(application, current, 'p1', 'actor')).not.toBeNull()
    expect(mockProviderFind).not.toHaveBeenCalled()
  })
})

describe('validateApplication: no switch-on, no lookup', () => {
  test('an apply that leaves every engine as it was never touches the owner or provider tables', async () => {
    const current = row()
    expect(await validateApplication({ data: { ...current }, changed: [] }, current, 'p1', 'actor')).toBeNull()
    expect(mockProjectFind).not.toHaveBeenCalled()
    expect(mockProviderFind).not.toHaveBeenCalled()
  })

  test('a stored true that the preset leaves alone does not need a provider', async () => {
    const current = { ...row(), wafAiUseJev: true }
    expect(await validateApplication({ data: { ...current }, changed: [] }, current, 'p1', 'actor')).toBeNull()
    expect(mockProviderFind).not.toHaveBeenCalled()
  })

  test('switching a hook back to the LLM needs no provider selection', async () => {
    const current = { ...row(), wafAiUseJev: true }
    const application = { data: { ...current, wafAiUseJev: false }, changed: ['wafAiUseJev'] }
    expect(await validateApplication(application, current, 'p1', 'actor')).toBeNull()
    expect(mockProviderFind).not.toHaveBeenCalled()
  })
})

describe('validateApplication: a preset that turns on a Jev-only hook', () => {
  test('without a provider selection it is refused, naming the field', async () => {
    const current = row()
    const application = { data: { ...current, httpxJevPageType: true }, changed: ['httpxJevPageType'] }
    const problem = await validateApplication(application, current, 'p1', 'actor')
    expect(problem).not.toBeNull()
    expect(problem!.error).toContain('httpxJevPageType')
  })

  test('with an explicit provider selection it is accepted', async () => {
    mockProviderFind.mockResolvedValue({ id: 'jev-selected' })
    mockProjectFind.mockResolvedValue({ userId: 'owner', jevProviderId: 'jev-selected' })
    const current = row()
    const application = { data: { ...current, hakrawlerJevSeedOrder: true }, changed: ['hakrawlerJevSeedOrder'] }
    expect(await validateApplication(application, current, 'p1', 'actor')).toBeNull()
  })
})
