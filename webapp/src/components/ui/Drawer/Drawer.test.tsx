import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import React from 'react'
import { Drawer } from './Drawer'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  document.body.style.userSelect = ''
  document.body.style.cursor = ''
})

describe('Drawer: resize handle semantics', () => {
  test('renders separator with ARIA range attributes and close button type="button"', () => {
    render(
      <Drawer
        isOpen
        onClose={vi.fn()}
        title="Inspector"
        width="320px"
        resizable
        minWidth={240}
        maxWidth={900}
      >
        <p>content</p>
      </Drawer>
    )

    const closeBtn = screen.getByRole('button', { name: 'Close drawer' })
    expect(closeBtn).toHaveAttribute('type', 'button')

    const handle = screen.getByRole('separator', { name: 'Resize drawer' })
    expect(handle).toHaveAttribute('aria-orientation', 'vertical')
    expect(handle).toHaveAttribute('tabindex', '0')
    expect(handle).toHaveAttribute('aria-valuemin', '240')
    expect(handle).toHaveAttribute('aria-valuemax', '900')
    expect(handle).toHaveAttribute('aria-valuenow', '320')
  })

  test('falls back to minWidth for aria-valuenow when width is not in px', () => {
    render(
      <Drawer isOpen onClose={vi.fn()} width="50%" resizable minWidth={260} maxWidth={800}>
        <p>content</p>
      </Drawer>
    )

    const handle = screen.getByRole('separator', { name: 'Resize drawer' })
    expect(handle).toHaveAttribute('aria-valuenow', '260')
  })
})

describe('Drawer: keyboard resizing', () => {
  test('ArrowLeft/ArrowRight step by 16px and Shift+Arrow steps by 64px for left drawer', () => {
    const onResize = vi.fn()
    const onResizeEnd = vi.fn()

    render(
      <Drawer
        isOpen
        onClose={vi.fn()}
        position="left"
        width="300px"
        resizable
        minWidth={240}
        maxWidth={1200}
        onResize={onResize}
        onResizeEnd={onResizeEnd}
      >
        <p>content</p>
      </Drawer>
    )

    const handle = screen.getByRole('separator', { name: 'Resize drawer' })

    fireEvent.keyDown(handle, { key: 'ArrowRight' })
    expect(onResize).toHaveBeenLastCalledWith(316)
    expect(onResizeEnd).toHaveBeenLastCalledWith(316)
    expect(handle).toHaveAttribute('aria-valuenow', '316')

    fireEvent.keyDown(handle, { key: 'ArrowRight', shiftKey: true })
    expect(onResize).toHaveBeenLastCalledWith(380)
    expect(onResizeEnd).toHaveBeenLastCalledWith(380)
    expect(handle).toHaveAttribute('aria-valuenow', '380')

    fireEvent.keyDown(handle, { key: 'ArrowLeft' })
    expect(onResize).toHaveBeenLastCalledWith(364)
    expect(onResizeEnd).toHaveBeenLastCalledWith(364)

    fireEvent.keyDown(handle, { key: 'ArrowLeft', shiftKey: true })
    expect(onResize).toHaveBeenLastCalledWith(300)
    expect(onResizeEnd).toHaveBeenLastCalledWith(300)
  })

  test('ArrowLeft/ArrowRight invert direction for right drawer and Shift+Arrow steps by 64px', () => {
    const onResize = vi.fn()
    const onResizeEnd = vi.fn()

    render(
      <Drawer
        isOpen
        onClose={vi.fn()}
        position="right"
        width="400px"
        resizable
        minWidth={240}
        maxWidth={1200}
        onResize={onResize}
        onResizeEnd={onResizeEnd}
      >
        <p>content</p>
      </Drawer>
    )

    const handle = screen.getByRole('separator', { name: 'Resize drawer' })

    // Right drawer grows leftward on ArrowLeft.
    fireEvent.keyDown(handle, { key: 'ArrowLeft' })
    expect(onResize).toHaveBeenLastCalledWith(416)
    expect(onResizeEnd).toHaveBeenLastCalledWith(416)

    fireEvent.keyDown(handle, { key: 'ArrowLeft', shiftKey: true })
    expect(onResize).toHaveBeenLastCalledWith(480)
    expect(onResizeEnd).toHaveBeenLastCalledWith(480)

    // Right drawer shrinks rightward on ArrowRight.
    fireEvent.keyDown(handle, { key: 'ArrowRight' })
    expect(onResize).toHaveBeenLastCalledWith(464)
    expect(onResizeEnd).toHaveBeenLastCalledWith(464)

    fireEvent.keyDown(handle, { key: 'ArrowRight', shiftKey: true })
    expect(onResize).toHaveBeenLastCalledWith(400)
    expect(onResizeEnd).toHaveBeenLastCalledWith(400)
  })

  test('Home and End jump to minWidth/maxWidth and arrows clamp within bounds', () => {
    const onResize = vi.fn()
    const onResizeEnd = vi.fn()

    render(
      <Drawer
        isOpen
        onClose={vi.fn()}
        position="left"
        width="300px"
        resizable
        minWidth={240}
        maxWidth={600}
        onResize={onResize}
        onResizeEnd={onResizeEnd}
      >
        <p>content</p>
      </Drawer>
    )

    const handle = screen.getByRole('separator', { name: 'Resize drawer' })

    fireEvent.keyDown(handle, { key: 'Home' })
    expect(onResize).toHaveBeenLastCalledWith(240)
    expect(onResizeEnd).toHaveBeenLastCalledWith(240)
    expect(handle).toHaveAttribute('aria-valuenow', '240')

    fireEvent.keyDown(handle, { key: 'ArrowLeft' })
    expect(onResize).toHaveBeenLastCalledWith(240)
    expect(handle).toHaveAttribute('aria-valuenow', '240')

    fireEvent.keyDown(handle, { key: 'End' })
    expect(onResize).toHaveBeenLastCalledWith(600)
    expect(onResizeEnd).toHaveBeenLastCalledWith(600)
    expect(handle).toHaveAttribute('aria-valuenow', '600')

    fireEvent.keyDown(handle, { key: 'ArrowRight', shiftKey: true })
    expect(onResize).toHaveBeenLastCalledWith(600)
    expect(handle).toHaveAttribute('aria-valuenow', '600')
  })
})

describe('Drawer: pointer resizing', () => {
  test('tracks pointerDown -> pointerMove -> pointerUp, clamps to bounds, and restores body styles', () => {
    const onResize = vi.fn()
    const onResizeEnd = vi.fn()

    render(
      <Drawer
        isOpen
        onClose={vi.fn()}
        position="left"
        width="300px"
        resizable
        minWidth={240}
        maxWidth={500}
        onResize={onResize}
        onResizeEnd={onResizeEnd}
      >
        <p>content</p>
      </Drawer>
    )

    const handle = screen.getByRole('separator', { name: 'Resize drawer' })
    const setPointerCapture = vi.fn()
    const releasePointerCapture = vi.fn()
    handle.setPointerCapture = setPointerCapture
    handle.releasePointerCapture = releasePointerCapture
    handle.hasPointerCapture = vi.fn(() => true)

    fireEvent.pointerDown(handle, { pointerId: 1, pointerType: 'mouse', button: 0, clientX: 300 })
    expect(setPointerCapture).toHaveBeenCalledWith(1)
    expect(document.body.style.userSelect).toBe('none')
    expect(document.body.style.cursor).toBe('col-resize')

    fireEvent.pointerMove(handle, { pointerId: 1, clientX: 420 })
    expect(onResize).toHaveBeenLastCalledWith(420)
    expect(handle).toHaveAttribute('aria-valuenow', '420')

    // Exceeding maxWidth clamps to 500.
    fireEvent.pointerMove(handle, { pointerId: 1, clientX: 900 })
    expect(onResize).toHaveBeenLastCalledWith(500)
    expect(handle).toHaveAttribute('aria-valuenow', '500')

    fireEvent.pointerUp(handle, { pointerId: 1, clientX: 900 })
    expect(onResizeEnd).toHaveBeenCalledTimes(1)
    expect(onResizeEnd).toHaveBeenCalledWith(500)
    expect(releasePointerCapture).toHaveBeenCalledWith(1)
    expect(document.body.style.userSelect).toBe('')
    expect(document.body.style.cursor).toBe('')
  })

  test('ignores secondary mouse button and restores body styles when unmounted mid-drag', () => {
    const onResize = vi.fn()
    const { unmount } = render(
      <Drawer
        isOpen
        onClose={vi.fn()}
        position="right"
        width="350px"
        resizable
        minWidth={240}
        maxWidth={600}
        onResize={onResize}
      >
        <p>content</p>
      </Drawer>
    )

    const handle = screen.getByRole('separator', { name: 'Resize drawer' })

    // Non-primary mouse button is ignored.
    fireEvent.pointerDown(handle, { pointerId: 2, pointerType: 'mouse', button: 2, clientX: 500 })
    expect(document.body.style.userSelect).toBe('')

    document.body.style.userSelect = 'text'
    document.body.style.cursor = 'auto'

    fireEvent.pointerDown(handle, { pointerId: 3, pointerType: 'mouse', button: 0, clientX: 500 })
    expect(document.body.style.userSelect).toBe('none')
    expect(document.body.style.cursor).toBe('col-resize')

    fireEvent.pointerMove(handle, { pointerId: 3, clientX: 450 })
    expect(onResize).toHaveBeenLastCalledWith(400)

    unmount()
    expect(document.body.style.userSelect).toBe('text')
    expect(document.body.style.cursor).toBe('auto')
  })
})
