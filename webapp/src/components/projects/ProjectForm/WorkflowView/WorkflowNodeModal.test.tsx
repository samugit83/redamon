/**
 * The workflow node modal must close ONLY on a real save.
 *
 * Reported bug: creating a project, forgetting the Project Name, and pressing
 * Save in the Target & Modules modal showed the validation warning AND closed the
 * modal, dropping the operator onto the workflow graph with their unsaved input
 * gone and no way to act on the message.
 *
 * Cause: handleSaveAndStay RESOLVES (it does not throw) when it refuses on a
 * validation error, and this modal closed on "resolved". The save contract is now
 * an explicit boolean, and these tests pin it: a refusal keeps the modal open, so
 * the offending field - Project Name lives in this very modal - stays on screen.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/WorkflowView/WorkflowNodeModal.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { WorkflowNodeModal } from './WorkflowNodeModal'

vi.mock('@/components/shared/ModelPicker', () => ({ ModelPicker: () => null }))
vi.mock('@/providers/ProjectProvider', async orig => ({
  ...(await orig<typeof import('@/providers/ProjectProvider')>()),
  useProject: () => ({ userId: 'u1' }),
  useOptionalProject: () => ({ userId: 'u1' }),
}))

afterEach(cleanup)

const DATA = {
  name: '', description: '', targetDomain: '', subdomainList: [],
  ipMode: false, targetIps: [], domainBatchMode: false, domainBatchHosts: [],
  subdomainDiscoveryEnabled: true, aiInPipeline: false, verifyDomainOwnership: false,
  ownershipToken: '', ownershipTxtPrefix: '', aiPipelineModel: '',
}

function renderModal(onSave: () => Promise<boolean>) {
  const onClose = vi.fn()
  render(
    <WorkflowNodeModal
      toolId="input"
      onClose={onClose}
      data={DATA as never}
      updateField={vi.fn() as never}
      onSave={onSave}
      mode="create"
    />,
  )
  return onClose
}

/** The modal's primary action reads "Update Settings" (or "Saving..." in flight). */
const saveButton = () =>
  screen.getAllByRole('button')
    .find(b => /update settings|saving/i.test(b.textContent ?? ''))!

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({
    matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: vi.fn(),
  }))
})

describe('closing is gated on the save succeeding', () => {
  test('a validation refusal leaves the modal open', async () => {
    const onSave = vi.fn().mockResolvedValue(false)
    const onClose = renderModal(onSave)

    fireEvent.click(saveButton())

    await waitFor(() => expect(onSave).toHaveBeenCalled())
    expect(onClose).not.toHaveBeenCalled()
  })

  test('the settings are still on screen after a refusal', async () => {
    // The point of staying open: Project Name lives in THIS modal, so the
    // operator can fix what the warning just told them about.
    const onSave = vi.fn().mockResolvedValue(false)
    renderModal(onSave)

    fireEvent.click(saveButton())

    await waitFor(() => expect(onSave).toHaveBeenCalled())
    expect(screen.getByText('Project Name')).toBeTruthy()
  })

  test('a real save closes the modal', async () => {
    const onSave = vi.fn().mockResolvedValue(true)
    const onClose = renderModal(onSave)

    fireEvent.click(saveButton())

    await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
  })

  test('a thrown error leaves the modal open', async () => {
    const onSave = vi.fn().mockRejectedValue(new Error('network down'))
    const onClose = renderModal(onSave)

    fireEvent.click(saveButton())

    await waitFor(() => expect(onSave).toHaveBeenCalled())
    expect(onClose).not.toHaveBeenCalled()
  })

  test('the save button is re-enabled after a refusal so it can be retried', async () => {
    const onSave = vi.fn().mockResolvedValue(false)
    renderModal(onSave)

    fireEvent.click(saveButton())
    await waitFor(() => expect(saveButton()).not.toBeDisabled())

    fireEvent.click(saveButton())
    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(2))
  })
})
