/**
 * The launcher's place and the panel's placement (plan §9.3-9.4): clamped to the viewport, kept in
 * storage per account (storage that throws falls back to the default), stepping aside while a drawer
 * covers it, and a panel never over a drawer.
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { render, cleanup, fireEvent, screen } from '@testing-library/react'
import { clampPosition, DEFAULT_POSITION, readPosition, storageKey, useDraggablePosition } from './useDraggablePosition'
import { launcherPlace, panelPlace } from './NavigatorRoot'
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
    const p = panelPlace({ right: 24, bottom: 96 }, 1280, 800, []) as { left: number; top: number; width: number }
    expect(p.left + p.width).toBeLessThanOrEqual(1280 - 24 - 48)
    const drawer = rect(1280 - 672, 0, 672, 800)
    const beside = panelPlace({ right: 700, bottom: 96 }, 1280, 800, [drawer]) as { left: number; width: number }
    expect(beside.left + beside.width).toBeLessThanOrEqual(1280 - 672)
    const full = rect(0, 0, 1280, 800)
    expect(panelPlace({ right: 24, bottom: 96 }, 1280, 800, [full])).toBeNull()
    expect(panelPlace({ right: 24, bottom: 96 }, 400, 800, [])).toMatchObject({ width: '100%' })
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
