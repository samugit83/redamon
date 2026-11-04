import { useState } from 'react'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import { JevSelectionProvider, useHasJevProvider, notifyJevProviderChanged } from '@/hooks/useHasJevProvider'
import { JevTokenPanel } from './JevTokenPanel'
import { JevEngineControl } from './JevEngineControl'

vi.mock('@/components/settings/LlmProviderForm', () => ({
  LlmProviderForm: ({ onSave, userId }: { onSave: () => void; userId: string }) =>
    <button type="button" onClick={onSave}>Save account configuration for {userId}</button>,
}))

const DIRECT = { id: 'direct', name: 'Synthetic direct', providerType: 'jev', apiKey: 'masked', modelIdentifier: 'jev-1.13.0' }
const ROUTER = { ...DIRECT, id: 'router', name: 'Synthetic routed', providerType: 'jev_openrouter', modelIdentifier: 'typesafe/jev-1.13' }
let rows: unknown
let responseStatus: number
const fetchMock = vi.fn()

beforeEach(() => {
  rows = [DIRECT, ROUTER]
  responseStatus = 200
  fetchMock.mockReset().mockImplementation(async () => new Response(JSON.stringify(rows), { status: responseStatus }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function OtherSectionControl() {
  return <JevEngineControl value={false} enabled jevStatus={useHasJevProvider()} onSelect={() => {}} />
}

function Form({ initial = null, owner = 'owner-1', actor = 'owner-1' }: {
  initial?: string | null; owner?: string | null; actor?: string | null
}) {
  const [selected, setSelected] = useState(initial)
  return <JevSelectionProvider ownerUserId={owner} selectedProviderId={selected} ownerUnavailable={!owner}>
    <JevTokenPanel userId={actor} onSelect={setSelected} />
    <OtherSectionControl />
    <output data-testid="selection">{selected ?? 'null'}</output>
  </JevSelectionProvider>
}

const select = () => screen.getByRole('combobox', { name: 'Jev provider' })

describe('project Jev provider picker', () => {
  test('new and legacy null projects require an explicit selection despite multiple configured entries', async () => {
    render(<Form />)
    await screen.findByRole('combobox', { name: 'Jev provider' })
    expect(select()).toHaveValue('')
    expect(screen.getByText('Not selected')).toBeInTheDocument()
    expect(screen.getByText(/No Jev provider is selected for this project/)).toHaveTextContent('scan start is not blocked')
    expect(screen.getByRole('button', { name: 'Jev' })).toBeDisabled()
    expect(screen.getByRole('option', { name: /Synthetic direct · TypeSafe · jev-1.13.0/ })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: /Synthetic routed · OpenRouter · typesafe\/jev-1.13/ })).toBeInTheDocument()
  })

  test('unsaved selection and clear update every section control without another lookup', async () => {
    render(<Form />)
    await screen.findByRole('combobox', { name: 'Jev provider' })
    fireEvent.change(select(), { target: { value: 'router' } })
    expect(screen.getByRole('button', { name: 'Jev' })).toBeEnabled()
    expect(screen.getByTestId('selection')).toHaveTextContent('router')
    expect(screen.getByTestId('jev-provider-selected')).toHaveTextContent('OpenRouter')
    expect(screen.queryByText('Connected')).not.toBeInTheDocument()
    expect(screen.getByTestId('jev-provider-selected')).toHaveTextContent('do not confirm live model access')
    fireEvent.change(select(), { target: { value: '' } })
    expect(screen.getByTestId('selection')).toHaveTextContent('null')
    expect(screen.getByRole('button', { name: 'Jev' })).toBeDisabled()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test('deleting the selected entry warns without selecting another account entry or clearing unsaved state', async () => {
    render(<Form initial="direct" />)
    await screen.findByTestId('jev-provider-selected')
    rows = [ROUTER]
    notifyJevProviderChanged()
    await screen.findByText(/The selected Jev configuration was deleted/)
    expect(select()).toHaveValue('direct')
    expect(screen.getByTestId('selection')).toHaveTextContent('direct')
    expect(screen.getByRole('button', { name: 'Jev' })).toBeDisabled()
    fireEvent.change(select(), { target: { value: '' } })
    expect(screen.getByTestId('selection')).toHaveTextContent('null')
  })

  test('adding an account configuration refreshes all hooks but never selects the saved entry', async () => {
    rows = []
    render(<Form />)
    await screen.findByText('The project owner has no Jev configurations.')
    fireEvent.click(screen.getByRole('button', { name: 'Add Jev configuration' }))
    rows = [DIRECT]
    fireEvent.click(screen.getByRole('button', { name: 'Save account configuration for owner-1' }))
    await screen.findByRole('option', { name: /Synthetic direct/ })
    expect(select()).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Jev' })).toBeDisabled()
    expect(screen.getByTestId('selection')).toHaveTextContent('null')
    expect(screen.getByRole('link', { name: /Manage/ })).toHaveAttribute('target', '_blank')
  })

  test('loading and lookup error are not reported as missing configurations; retry retains selection', async () => {
    responseStatus = 503
    rows = { error: 'Lookup unavailable', code: 'P2024' }
    render(<Form initial="direct" />)
    expect(screen.getByText(/Loading the project owner/)).toBeInTheDocument()
    expect(screen.queryByText('Not selected')).not.toBeInTheDocument()
    const warning = await screen.findByRole('alert')
    expect(warning).toHaveTextContent('P2024 · HTTP 503')
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add Jev configuration' })).not.toBeInTheDocument()
    responseStatus = 200
    rows = [DIRECT]
    fireEvent.click(screen.getByRole('button', { name: /Retry/ }))
    await screen.findByTestId('jev-provider-selected')
    expect(select()).toHaveValue('direct')
  })

  test('a shared/admin view lists the known project owner, never the actor’s configurations or add form', async () => {
    render(<Form owner="project-owner" actor="actor" initial="direct" />)
    await screen.findByTestId('jev-provider-selected')
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith('/api/users/project-owner/llm-providers')
    expect(screen.queryByRole('button', { name: 'Add Jev configuration' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Manage/ })).not.toBeInTheDocument()
  })

  test('an unknown project owner has a safe limited state and does not load actor configs', () => {
    render(<Form owner={null} actor="actor" />)
    expect(screen.getByRole('alert')).toHaveTextContent('unavailable in this view')
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Jev' })).toBeDisabled()
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
