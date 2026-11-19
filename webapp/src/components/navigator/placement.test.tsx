/**
 * The launcher's place and the panel's placement and size (plan §9.3-9.4): clamped to the viewport,
 * kept in storage per account (storage that throws falls back to the default), stepping aside while
 * a drawer covers it, a panel never over a drawer, and a resize that moves only the dragged edges.
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { render, cleanup, fireEvent, screen } from '@testing-library/react'
import { clampPosition, DEFAULT_POSITION, readPosition, storageKey, useDraggablePosition } from './useDraggablePosition'
import {
  constrainSize, DEFAULT_PANEL_SIZE, MIN_PANEL_SIZE, panelSizeKey, readPanelSize, resizedSize, usePanelSize,
} from './usePanelSize'
import { launcherPlace, panelPlace, placePanel, resizeFits } from './NavigatorRoot'
import { NavigatorLauncher } from './NavigatorLauncher'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  try { window.localStorage.clear() } catch { /* jsdom */ }
})

const rect = (left: number, top: number, width: number, height: number) =>
  ({ left, top, width, height, right: left + width, bottom: top + height, x: left, y: top, toJSON: () => ({}) }) as DOMRect

describe('position', () => {
  test('clamped to an 8 px margin', () => {
    expect(clampPosition({ right: -50, bottom: 5000 }, 1000, 800)).toEqual({ right: 8, bottom: 800 - 48 - 8 })
  })

  test('read per account; corrupt or unavailable storage gives the default', () => {
    window.localStorage.setItem(storageKey('alice'), JSON.stringify({ right: 300, bottom: 200 }))
    expect(readPosition('alice')).toEqual({ right: 300, bottom: 200 })
    expect(readPosition('bob')).toEqual(DEFAULT_POSITION)
    window.localStorage.setItem(storageKey('carol'), '{nope')
    expect(readPosition('carol')).toEqual(DEFAULT_POSITION)
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
    expect(readPosition('alice')).toEqual(DEFAULT_POSITION)
  })

  test('the launcher steps aside while a drawer covers it and its saved place is kept', () => {
    const drawer = rect(1280 - 672, 0, 672, 800)
    const saved = { right: 24, bottom: 96 }
    const drawn = launcherPlace(saved, 1280, 800, [drawer])
    expect(drawn.right).toBeGreaterThanOrEqual(672)
    expect(launcherPlace(saved, 1280, 800, [])).toEqual(saved)
  })

  test('the panel goes beside the launcher, never over a drawer; no room closes it', () => {
    const p = panelPlace({ right: 24, bottom: 96 }, 1280, 800, [])!.box!
    expect(p.left + p.width).toBeLessThanOrEqual(1280 - 24 - 48)
    const drawer = rect(1280 - 672, 0, 672, 800)
    const beside = panelPlace({ right: 700, bottom: 96 }, 1280, 800, [drawer])!.box!
    expect(beside.left + beside.width).toBeLessThanOrEqual(1280 - 672)
    const full = rect(0, 0, 1280, 800)
    expect(panelPlace({ right: 24, bottom: 96 }, 1280, 800, [full])).toBeNull()
    expect(panelPlace({ right: 24, bottom: 96 }, 400, 800, [])).toMatchObject({ style: { width: '100%' }, handles: [] })
  })
})

describe('panel size', () => {
  const launcher = { right: 24, bottom: 96 }

  test('read per account, at least the minimum; corrupt or unavailable storage gives the default', () => {
    window.localStorage.setItem(panelSizeKey('alice'), JSON.stringify({ width: 700, height: 650 }))
    expect(readPanelSize('alice')).toEqual({ width: 700, height: 650 })
    expect(readPanelSize('bob')).toEqual(DEFAULT_PANEL_SIZE)
    window.localStorage.setItem(panelSizeKey('dave'), JSON.stringify({ width: 10, height: 1e9 }))
    expect(readPanelSize('dave')).toEqual({ width: MIN_PANEL_SIZE.width, height: 4000 })
    window.localStorage.setItem(panelSizeKey('carol'), '{nope')
    expect(readPanelSize('carol')).toEqual(DEFAULT_PANEL_SIZE)
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
    expect(readPanelSize('alice')).toEqual(DEFAULT_PANEL_SIZE)
  })

  test('drawn at its saved size, bottom in line with the launcher, the far edges free', () => {
    const p = panelPlace(launcher, 1280, 800, [], { width: 600, height: 650 })!
    const lbLeft = 1280 - 24 - 48
    expect(p.side).toBe('left')
    expect(p.box).toEqual({ left: lbLeft - 8 - 600, top: 800 - 96 - 650, width: 600, height: 650 })
    expect(p.handles).toEqual(['w', 'n', 'nw'])
    const right = panelPlace({ right: 1280 - 48 - 24, bottom: 96 }, 1280, 800, [], { width: 600, height: 650 })!
    expect(right.side).toBe('right')
    expect(right.handles).toEqual(['e', 'n', 'ne'])
  })

  test('a launcher near the top pins the panel there and frees its bottom edge', () => {
    const p = panelPlace({ right: 24, bottom: 800 - 48 - 40 }, 1280, 800, [], { width: 380, height: 560 })!
    expect(p.box!.top).toBe(8)
    expect(p.handles).toEqual(['w', 's', 'sw'])
  })

  test('a window too small for the saved size shrinks the drawn panel, never below the default', () => {
    const p = panelPlace(launcher, 1000, 600, [], { width: 3000, height: 3000 })!
    expect(p.box).toEqual({ left: 8, top: 8, width: 1000 - 24 - 48 - 8 - 8, height: 600 - 8 - 8 })
  })

  test('a wide panel narrows to the room before a drawer, a gap away from it', () => {
    const agentDrawer = rect(1280 - 672, 0, 672, 800)
    const p = panelPlace({ right: 1100, bottom: 96 }, 1280, 800, [agentDrawer], { width: 900, height: 560 })!
    expect(p.side).toBe('right')
    expect(p.box!.left + p.box!.width).toBe(1280 - 672 - 8)
  })

  test('a drawer that leaves no room for the saved size gets the default size, not a closed panel', () => {
    // A launcher near the top pins a tall panel there, reaching down into a drawer along the bottom.
    const bottomDrawer = rect(0, 600, 1280, 200)
    const high = { right: 24, bottom: 600 }
    const saved = { width: 380, height: 700 }
    expect(placePanel(high, 1280, 800, [bottomDrawer], saved)).toBeNull()
    expect(panelPlace(high, 1280, 800, [bottomDrawer], saved)!.box).toMatchObject({ top: 8, height: 560 })
  })

  test('a drag stops its edge at the margin and keeps the opposite edges in place', () => {
    const start = panelPlace(launcher, 1280, 800, [], DEFAULT_PANEL_SIZE)!
    const fits = (s: { width: number; height: number }) => resizeFits(start, 'nw', launcher, 1280, 800, [], s)
    const from = { width: start.box!.width, height: start.box!.height }
    const to = constrainSize(from, resizedSize(from, 'nw', -5000, -5000), fits)
    const lbLeft = 1280 - 24 - 48
    expect(to).toEqual({ width: lbLeft - 8 - 8, height: 800 - 96 - 8 })
    // Shrinking stops at the minimum.
    expect(resizedSize(from, 'nw', 5000, 5000)).toEqual(MIN_PANEL_SIZE)
    // An east drag on a panel anchored by its east edge would move it: refused.
    expect(resizeFits(start, 'e', launcher, 1280, 800, [], { width: 500, height: from.height })).toBe(false)
  })

  test('a drag stops its edge at a drawer', () => {
    const drawer = rect(0, 0, 300, 800)
    const start = panelPlace(launcher, 1280, 800, [drawer], DEFAULT_PANEL_SIZE)!
    const from = { width: start.box!.width, height: start.box!.height }
    const to = constrainSize(from, resizedSize(from, 'w', -2000, 0),
      (s) => resizeFits(start, 'w', launcher, 1280, 800, [drawer], s))
    const right = start.box!.left + start.box!.width
    expect(right - to.width).toBe(300 + 8)
  })
})

function SizeHarness({ fits, preview }: { fits: (s: { width: number; height: number }) => boolean; preview: () => void }) {
  const p = usePanelSize('alice')
  return (
    <div data-testid="handle" data-size={`${p.size.width}x${p.size.height}`}
      onPointerDown={(e) => p.startResize(e, 'nw', p.size, fits, preview)} />
  )
}

describe('panel resize', () => {
  test('a drag previews each move and saves the size on release', () => {
    const preview = vi.fn()
    render(<SizeHarness fits={() => true} preview={preview} />)
    const handle = screen.getByTestId('handle')
    fireEvent.pointerDown(handle, { button: 0, pointerId: 3, clientX: 500, clientY: 500 })
    fireEvent.pointerMove(window, { pointerId: 3, clientX: 400, clientY: 450 })
    expect(preview).toHaveBeenLastCalledWith({ width: 480, height: 610 })
    expect(window.localStorage.getItem(panelSizeKey('alice'))).toBeNull()
    expect(document.body.style.userSelect).toBe('none')
    fireEvent.pointerUp(window, { pointerId: 3, clientX: 380, clientY: 440 })
    expect(JSON.parse(window.localStorage.getItem(panelSizeKey('alice'))!)).toEqual({ width: 500, height: 620 })
    expect(handle.getAttribute('data-size')).toBe('500x620')
    expect(document.body.style.userSelect).toBe('')
    fireEvent.pointerMove(window, { pointerId: 3, clientX: 0, clientY: 0 })
    expect(preview).toHaveBeenCalledTimes(2)
  })

  test('a size that does not fit is not drawn or saved', () => {
    const preview = vi.fn()
    render(<SizeHarness fits={(s) => s.width <= 420 && s.height <= 600} preview={preview} />)
    const handle = screen.getByTestId('handle')
    fireEvent.pointerDown(handle, { button: 0, pointerId: 4, clientX: 500, clientY: 500 })
    fireEvent.pointerMove(window, { pointerId: 4, clientX: 300, clientY: 300 })
    fireEvent.pointerUp(window, { pointerId: 4, clientX: 300, clientY: 300 })
    expect(JSON.parse(window.localStorage.getItem(panelSizeKey('alice'))!)).toEqual({ width: 420, height: 600 })
  })
})

function Harness({ onToggle }: { onToggle: () => void }) {
  const drag = useDraggablePosition('alice', onToggle)
  return (
    <NavigatorLauncher style={{ right: drag.position.right, bottom: drag.position.bottom }} open={false} badge={false}
      panelId="p" handlers={drag} onKeyMove={drag.nudge} onKeyReset={drag.reset} onToggle={onToggle} />
  )
}

describe('launcher', () => {
  test('a click toggles; a drag moves, saves and does not toggle', () => {
    const toggle = vi.fn()
    render(<Harness onToggle={toggle} />)
    const btn = screen.getByTestId('navigator-launcher')
    fireEvent.pointerDown(btn, { button: 0, pointerId: 1, clientX: 100, clientY: 100 })
    fireEvent.pointerUp(btn, { pointerId: 1, clientX: 101, clientY: 101 })
    expect(toggle).toHaveBeenCalledTimes(1)
    fireEvent.pointerDown(btn, { button: 0, pointerId: 2, clientX: 100, clientY: 100 })
    fireEvent.pointerMove(btn, { pointerId: 2, clientX: 60, clientY: 40 })
    fireEvent.pointerUp(btn, { pointerId: 2, clientX: 60, clientY: 40 })
    expect(toggle).toHaveBeenCalledTimes(1)
    expect(JSON.parse(window.localStorage.getItem(storageKey('alice'))!)).toEqual({ right: 64, bottom: 156 })
  })

  test('keyboard: Enter toggles, Alt+Arrow moves, Alt+Home resets', () => {
    const toggle = vi.fn()
    render(<Harness onToggle={toggle} />)
    const btn = screen.getByTestId('navigator-launcher')
    fireEvent.keyDown(btn, { key: 'Enter' })
    expect(toggle).toHaveBeenCalledTimes(1)
    fireEvent.keyDown(btn, { key: 'ArrowLeft', altKey: true })
    expect(JSON.parse(window.localStorage.getItem(storageKey('alice'))!)).toEqual({ right: 40, bottom: 96 })
    fireEvent.keyDown(btn, { key: 'Home', altKey: true })
    expect(JSON.parse(window.localStorage.getItem(storageKey('alice'))!)).toEqual(DEFAULT_POSITION)
    expect(btn.getAttribute('aria-label')).toBe('AI Navigator')
    expect(btn.getAttribute('aria-controls')).toBe('p')
  })
})
