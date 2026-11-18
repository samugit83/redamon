/**
 * The gate's suggested model (Q10, T7.5; R-401, AC-71): the Tradecraft librarian's gate offers
 * the section picker's model first and preselected, and nothing is saved until the person
 * confirms; Cancel saves nothing; a model the feature may not use, or one no longer among the
 * person's models, is not offered; a gate without a suggestion is unchanged.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { useEffect } from 'react'
import { render, screen, cleanup, fireEvent, act, waitFor } from '@testing-library/react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))

import { FeatureModelGate, FeatureModelGateProvider, useFeatureModelGate, type FeatureModelGateApi } from './FeatureModelGate'
import { GATE_MODELS, stubGateFetch, jsonResponse, type GateFetchStub } from './featureModelGate.testUtils'

let stub: GateFetchStub
beforeEach(() => {
  stub = stubGateFetch({ tradecraft_section_picker: 'claude-haiku-4-5' }, () => jsonResponse(404, {}))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

let api: FeatureModelGateApi
function Grab() {
  const gate = useFeatureModelGate()
  useEffect(() => { api = gate }, [gate])
  return null
}
const SETTINGS = '/api/users/user-1/settings'

describe('the suggested model', () => {
  test('suggestion_not_saved_until_confirm: shown first and preselected; saved only on Save', async () => {
    render(<FeatureModelGateProvider><Grab /></FeatureModelGateProvider>)
    let result!: Promise<string | null>
    act(() => { result = api.ensureFeatureModel('tradecraft_librarian', { force: true, suggestFrom: 'tradecraft_section_picker', suggestedFrom: 'your Tradecraft section picker model' }) })
    const suggestion = await screen.findByTestId('gate-suggestion')
    expect(suggestion).toHaveTextContent('Suggested: claude-haiku-4-5 (your Tradecraft section picker model). Nothing is saved until you confirm.')
    const save = screen.getByRole('button', { name: 'Save and continue' })
    await waitFor(() => expect(save).toBeEnabled())
    expect(stub.calls(SETTINGS, 'PUT')).toEqual([])
    expect(stub.saved).toEqual({ tradecraft_section_picker: 'claude-haiku-4-5' })
    fireEvent.click(save)
    expect(await result).toBe('claude-haiku-4-5')
    expect(stub.saved).toEqual({ tradecraft_section_picker: 'claude-haiku-4-5', tradecraft_librarian: 'claude-haiku-4-5' })
  })

  test('Cancel saves nothing, the suggestion included', async () => {
    render(<FeatureModelGateProvider><Grab /></FeatureModelGateProvider>)
    let result!: Promise<string | null>
    act(() => { result = api.ensureFeatureModel('tradecraft_librarian', { force: true, suggestFrom: 'tradecraft_section_picker' }) })
    await screen.findByTestId('gate-suggestion')
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(await result).toBeNull()
    expect(stub.calls(SETTINGS, 'PUT')).toEqual([])
  })

  test('fetchWithFeatureModel: a model_required answer opens the gate with the suggestion; confirmed, the request runs once more', async () => {
    render(<FeatureModelGateProvider><Grab /></FeatureModelGateProvider>)
    const doFetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse(409, { error: 'Choose a model', code: 'model_required', featureId: 'tradecraft_librarian' }))
      .mockResolvedValueOnce(jsonResponse(201, { resource: null, job: null }))
    let result!: Promise<Response>
    act(() => { result = api.fetchWithFeatureModel('tradecraft_librarian', doFetch, {}, { suggestFrom: 'tradecraft_section_picker' }) })
    await screen.findByTestId('gate-suggestion')
    expect(doFetch).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save and continue' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Save and continue' }))
    expect((await result).status).toBe(201)
    expect(doFetch).toHaveBeenCalledTimes(2)
    expect(stub.saved.tradecraft_librarian).toBe('claude-haiku-4-5')
  })

  test('a suggestion this feature may not use, or no longer among the models, is not offered', async () => {
    const { rerender } = render(<FeatureModelGate featureId="tradecraft_librarian" userId="user-1" suggestedModel="loop/mcp" onSaved={vi.fn()} onCancel={vi.fn()} />)
    await screen.findByText('Choose a model')
    expect(screen.queryByTestId('gate-suggestion')).toBeNull()
    rerender(<FeatureModelGate featureId="tradecraft_librarian" userId="user-1" suggestedModel="gone-model" onSaved={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.queryByTestId('gate-suggestion')).toBeNull()
    expect(screen.getByRole('button', { name: 'Save and continue' })).toBeDisabled()
    expect(Object.keys(GATE_MODELS)).toEqual(['Anthropic'])
  })

  test('without a suggestion the gate is as before: nothing preselected', async () => {
    render(<FeatureModelGateProvider><Grab /></FeatureModelGateProvider>)
    act(() => { void api.ensureFeatureModel('tradecraft_librarian', { force: true }) })
    await screen.findByText('Choose a model')
    expect(screen.queryByTestId('gate-suggestion')).toBeNull()
    expect(screen.getByRole('button', { name: 'Save and continue' })).toBeDisabled()
  })
})
