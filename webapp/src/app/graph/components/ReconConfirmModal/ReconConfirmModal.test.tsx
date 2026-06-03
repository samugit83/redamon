import { afterEach, describe, test, expect, vi } from 'vitest'
import { cleanup, render, screen, fireEvent } from '@testing-library/react'
import { ReconConfirmModal } from './ReconConfirmModal'

const defaultProps = {
  isOpen: true,
  onClose: vi.fn(),
  projectName: 'Acme',
  targetDomain: 'example.com',
  stats: { totalNodes: 3, nodesByType: { Domain: 1, Subdomain: 2 } },
  isLoading: false,
}

afterEach(cleanup)

function renderModal(onConfirm = vi.fn(), props = {}) {
  const view = render(
    <ReconConfirmModal
      {...defaultProps}
      {...props}
      onConfirm={onConfirm}
    />
  )
  return { onConfirm, ...view }
}

describe('ReconConfirmModal delete graph toggle', () => {
  test('defaults delete graph to off and starts without deletion', () => {
    const { onConfirm } = renderModal()

    const checkbox = screen.getByRole('checkbox', {
      name: /delete existing graph before starting/i,
    }) as HTMLInputElement
    expect(checkbox.checked).toBe(false)
    expect(screen.getByText(/Existing graph data will be retained/i)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /start recon/i }))
    expect(onConfirm).toHaveBeenCalledWith(false)
  })

  test('submits true when delete graph is enabled', () => {
    const { onConfirm } = renderModal()

    const checkbox = screen.getByRole('checkbox', {
      name: /delete existing graph before starting/i,
    })
    fireEvent.click(checkbox)

    expect(screen.getByText(/will delete all existing graph data/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /delete & start/i }))
    expect(onConfirm).toHaveBeenCalledWith(true)
  })

  test('resets delete graph when the target changes', () => {
    const { rerender } = renderModal()

    const checkbox = screen.getByRole('checkbox', {
      name: /delete existing graph before starting/i,
    }) as HTMLInputElement
    fireEvent.click(checkbox)
    expect(checkbox.checked).toBe(true)

    rerender(
      <ReconConfirmModal
        {...defaultProps}
        onConfirm={vi.fn()}
        targetDomain="next.example.com"
      />
    )

    expect(screen.getByRole('checkbox', {
      name: /delete existing graph before starting/i,
    })).not.toBeChecked()
    expect(screen.getByText(/Existing graph data will be retained/i)).toBeInTheDocument()
  })

  test('submits false when existing data is removed before confirming', () => {
    const onConfirm = vi.fn()
    const { rerender } = renderModal(onConfirm)

    fireEvent.click(screen.getByRole('checkbox', {
      name: /delete existing graph before starting/i,
    }))

    rerender(
      <ReconConfirmModal
        {...defaultProps}
        onConfirm={onConfirm}
        stats={null}
      />
    )

    expect(screen.queryByRole('checkbox', {
      name: /delete existing graph before starting/i,
    })).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /start recon/i }))
    expect(onConfirm).toHaveBeenLastCalledWith(false)
  })
})
