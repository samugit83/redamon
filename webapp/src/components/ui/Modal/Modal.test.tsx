import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import React, { useState } from 'react'
import { Modal } from './Modal'

afterEach(() => {
  cleanup()
  document.body.style.overflow = ''
})

function renderModal(onClose = vi.fn()) {
  render(
    <Modal isOpen onClose={onClose} title="Create User">
      <input placeholder="email" autoFocus />
    </Modal>
  )
  const overlay = screen.getByRole('dialog').parentElement as HTMLElement
  return { onClose, overlay, input: screen.getByPlaceholderText('email') }
}

describe('Modal: backdrop close', () => {
  test('a press that starts and ends on the backdrop closes it', () => {
    const { onClose, overlay } = renderModal()
    fireEvent.mouseDown(overlay)
    fireEvent.click(overlay)
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  // Browsers dispatch the click to the common ancestor of the mousedown and
  // mouseup targets, so a press inside a field released over the backdrop
  // arrives as a click whose target IS the overlay.
  test('a press that starts inside the dialog and ends on the backdrop does not close it', () => {
    const { onClose, overlay, input } = renderModal()
    fireEvent.mouseDown(input)
    fireEvent.click(overlay)
    expect(onClose).not.toHaveBeenCalled()
  })

  test('a click with no press on the backdrop does not close it', () => {
    const { onClose, overlay } = renderModal()
    fireEvent.click(overlay)
    expect(onClose).not.toHaveBeenCalled()
  })

  test('a stale backdrop press does not arm a later click', () => {
    const { onClose, overlay, input } = renderModal()
    fireEvent.mouseDown(overlay)
    fireEvent.click(overlay)
    fireEvent.mouseDown(input)
    fireEvent.click(overlay)
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  test('closeOnOverlayClick=false never closes from the backdrop', () => {
    const onClose = vi.fn()
    render(
      <Modal isOpen onClose={onClose} closeOnOverlayClick={false}>
        <p>body</p>
      </Modal>
    )
    const overlay = screen.getByRole('dialog').parentElement as HTMLElement
    fireEvent.mouseDown(overlay)
    fireEvent.click(overlay)
    expect(onClose).not.toHaveBeenCalled()
  })
})

describe('Modal: initial focus', () => {
  test('keeps focus on an autoFocus field instead of pulling it to the dialog', () => {
    const { input } = renderModal()
    expect(document.activeElement).toBe(input)
  })

  test('focuses the dialog when nothing inside claims focus', () => {
    render(
      <Modal isOpen onClose={() => {}} title="Info">
        <p>body</p>
      </Modal>
    )
    expect(document.activeElement).toBe(screen.getByRole('dialog'))
  })
})

describe('Modal: its accessible name', () => {
  test('two modals open at once are each named by their own title', () => {
    // A refusal alert opens over the dialog that asked: each must announce its own title.
    render(
      <>
        <Modal isOpen onClose={vi.fn()} title="Install Echo">
          <p>body</p>
        </Modal>
        <Modal isOpen onClose={vi.fn()} title="The plugin operation was refused">
          <p>why</p>
        </Modal>
      </>
    )
    expect(screen.getByRole('dialog', { name: 'Install Echo' })).toBeTruthy()
    expect(screen.getByRole('dialog', { name: 'The plugin operation was refused' })).toBeTruthy()
  })
})

describe('Modal: focus trap & restoration', () => {
  test('Tab and Shift+Tab wrap around across focusable children', () => {
    render(
      <Modal isOpen onClose={vi.fn()} title="Actions" showCloseButton={false}>
        <button type="button">First</button>
        <input aria-label="Middle" />
        <button type="button">Last</button>
      </Modal>
    )

    const dialog = screen.getByRole('dialog')
    const first = screen.getByRole('button', { name: 'First' })
    const last = screen.getByRole('button', { name: 'Last' })

    // Shift+Tab from dialog element itself wraps to the last focusable element.
    expect(document.activeElement).toBe(dialog)
    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(last)

    // Tab from last wraps to first.
    fireEvent.keyDown(last, { key: 'Tab' })
    expect(document.activeElement).toBe(first)

    // Shift+Tab from first wraps back to last.
    fireEvent.keyDown(first, { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(last)
  })

  test('keeps focus on [role="dialog"] on Tab/Shift+Tab when there are no focusable children', () => {
    render(
      <Modal isOpen onClose={vi.fn()} title="Readonly" showCloseButton={false}>
        <p>No interactive elements</p>
      </Modal>
    )

    const dialog = screen.getByRole('dialog')
    expect(document.activeElement).toBe(dialog)

    fireEvent.keyDown(dialog, { key: 'Tab' })
    expect(document.activeElement).toBe(dialog)

    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(dialog)
  })

  test('restores focus to the triggering button when closed', () => {
    function Harness() {
      const [open, setOpen] = useState(false)
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            Open Dialog
          </button>
          <Modal isOpen={open} onClose={() => setOpen(false)} title="Confirm">
            <button type="button">Inside</button>
          </Modal>
        </>
      )
    }

    render(<Harness />)
    const trigger = screen.getByRole('button', { name: 'Open Dialog' })
    trigger.focus()
    expect(document.activeElement).toBe(trigger)

    fireEvent.click(trigger)
    const dialog = screen.getByRole('dialog', { name: 'Confirm' })
    expect(document.activeElement).toBe(dialog)

    fireEvent.keyDown(dialog, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(trigger)
  })
})

describe('Modal: background inert & stacked modals', () => {
  test('marks background siblings inert while open and restores on close, skipping live portals', () => {
    const liveToast = document.createElement('div')
    liveToast.setAttribute('role', 'status')
    liveToast.textContent = 'Live status'
    document.body.appendChild(liveToast)

    try {
      const { container, rerender } = render(
        <>
          <div data-testid="background-app">
            <button type="button">Background Action</button>
          </div>
          <Modal isOpen={true} onClose={vi.fn()} title="Overlay">
            <p>Modal body</p>
          </Modal>
        </>
      )

      const overlay = screen.getByRole('dialog').parentElement as HTMLElement
      expect(overlay).toHaveAttribute('data-modal-overlay', 'true')
      expect(overlay.hasAttribute('inert')).toBe(false)
      expect(overlay.hasAttribute('aria-hidden')).toBe(false)

      expect(container.inert).toBe(true)
      expect(container.hasAttribute('inert')).toBe(true)
      expect(liveToast.hasAttribute('inert')).toBe(false)

      rerender(
        <>
          <div data-testid="background-app">
            <button type="button">Background Action</button>
          </div>
          <Modal isOpen={false} onClose={vi.fn()} title="Overlay">
            <p>Modal body</p>
          </Modal>
        </>
      )

      expect(container.inert).toBe(false)
      expect(container.hasAttribute('inert')).toBe(false)
    } finally {
      liveToast.remove()
    }
  })

  test('Escape closes only the topmost stacked modal and restores body overflow only when all close', () => {
    function StackedHarness() {
      const [firstOpen, setFirstOpen] = useState(true)
      const [secondOpen, setSecondOpen] = useState(true)
      return (
        <>
          <Modal isOpen={firstOpen} onClose={() => setFirstOpen(false)} title="Lower Modal">
            <p>Lower</p>
            <Modal isOpen={secondOpen} onClose={() => setSecondOpen(false)} title="Upper Modal">
              <p>Upper</p>
            </Modal>
          </Modal>
        </>
      )
    }

    render(<StackedHarness />)

    expect(document.body.style.overflow).toBe('hidden')
    const lowerDialog = screen.getByRole('dialog', { name: 'Lower Modal' })
    const upperDialog = screen.getByRole('dialog', { name: 'Upper Modal' })

    // Escape on upper modal closes only upper modal (and does not bubble through React portal to lower).
    fireEvent.keyDown(upperDialog, { key: 'Escape' })
    expect(screen.queryByRole('dialog', { name: 'Upper Modal' })).toBeNull()
    expect(screen.getByRole('dialog', { name: 'Lower Modal' })).toBeInTheDocument()
    expect(document.body.style.overflow).toBe('hidden')

    // Escape on remaining lower modal closes it and restores body overflow.
    fireEvent.keyDown(lowerDialog, { key: 'Escape' })
    expect(screen.queryByRole('dialog', { name: 'Lower Modal' })).toBeNull()
    expect(document.body.style.overflow).toBe('')
  })
})
