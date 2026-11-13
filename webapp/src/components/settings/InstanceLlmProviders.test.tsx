/**
 * Global Settings' list of the instance LLM providers an administrator made available to the account
 * (step 6.11, GV-15): names and kinds from /api/account/llm-providers, and their count for "Models
 * by feature". With RBAC_GOVERNANCE_ENABLED off nothing is read or shown and the count is 0 (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/components/settings/InstanceLlmProviders.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { InstanceLlmProviders } from './InstanceLlmProviders'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }
let answer: { status: number; body: unknown }
const fetchMock = vi.fn(async () => new Response(JSON.stringify(answer.body), { status: answer.status }))
const onCount = vi.fn()

beforeEach(() => {
  answer = { status: 200, body: { providers: [{ id: 'inst-1', name: 'Shared OpenAI', providerType: 'openai' }] } }
  fetchMock.mockClear()
  onCount.mockClear()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const renderWith = (flags: typeof FLAGS_ON) => render(
  <AuthContext.Provider value={fakeAuth(flags, [])}><InstanceLlmProviders onCount={onCount} /></AuthContext.Provider>)

describe('the instance providers in Global Settings', () => {
  test('switch off (and outside an AuthProvider): nothing read or shown, count 0', () => {
    renderWith({ ...FLAGS_GOV, governance: false })
    cleanup()
    render(<InstanceLlmProviders onCount={onCount} />)
    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.queryByRole('list')).toBeNull()
    expect(onCount).toHaveBeenLastCalledWith(0)
  })

  test('on: the names and kinds, and their count for Models by feature', async () => {
    renderWith(FLAGS_GOV)
    expect(screen.getByRole('status')).toHaveTextContent('Loading')
    expect(await screen.findByRole('list', { name: 'Instance LLM providers' })).toHaveTextContent('Shared OpenAI (OpenAI)')
    expect(fetchMock).toHaveBeenCalledWith('/api/account/llm-providers', { cache: 'no-store' })
    await waitFor(() => expect(onCount).toHaveBeenLastCalledWith(1))
  })

  test('none made available: nothing shown, count 0', async () => {
    answer = { status: 200, body: { providers: [] } }
    renderWith(FLAGS_GOV)
    await waitFor(() => expect(screen.queryByRole('status')).toBeNull())
    expect(screen.queryByRole('list')).toBeNull()
    expect(onCount).toHaveBeenLastCalledWith(0)
  })

  test('a failed read: the cause and Retry', async () => {
    answer = { status: 500, body: { error: 'x', code: 'P1001' } }
    renderWith(FLAGS_GOV)
    expect(await screen.findByRole('alert')).toHaveTextContent('(P1001 · HTTP 500)')
    answer = { status: 200, body: { providers: [{ id: 'inst-1', name: 'Shared OpenAI', providerType: 'openai' }] } }
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('list', { name: 'Instance LLM providers' })).toBeInTheDocument()
  })
})
