/**
 * The plugin card's listing (README.PLUGINS.md §7.1): the catalog's avatar beside the text, a
 * placeholder when there is none or it fails to load, and the documentation link in the header.
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import type { PluginEntry } from '@/lib/plugins/pageModel'
import { PluginCard } from './PluginCard'

afterEach(() => cleanup())

function entry(over: Partial<PluginEntry> = {}): PluginEntry {
  return {
    id: 'echo',
    displayName: 'Echo',
    description: 'Echoes what it is given.',
    inCatalog: true,
    state: 'ready',
    installed: null,
    available: null,
    update: null,
    installBlocked: null,
    ...over,
  }
}

const show = (e: PluginEntry) => render(<PluginCard entry={e} manages={false} onAction={vi.fn()} />)

describe('PluginCard listing', () => {
  test('the catalog icon is shown, named after the plugin', () => {
    show(entry({ icon: '/api/plugins/echo/icon?v=abcd' }))
    const img = screen.getByRole('img', { name: 'Echo icon' }) as HTMLImageElement
    expect(img.getAttribute('src')).toBe('/api/plugins/echo/icon?v=abcd')
    expect(screen.queryByTestId('plugin-avatar-placeholder')).toBeNull()
  })

  test('no icon, or one that fails to load: the placeholder', () => {
    show(entry())
    expect(screen.getByTestId('plugin-avatar-placeholder')).toBeTruthy()
    cleanup()
    show(entry({ icon: '/api/plugins/echo/icon?v=abcd' }))
    fireEvent.error(screen.getByRole('img', { name: 'Echo icon' }))
    expect(screen.getByTestId('plugin-avatar-placeholder')).toBeTruthy()
  })

  test('the documentation link sits in the header beside the state and opens in a new tab', () => {
    show(entry({ docsUrl: 'https://github.com/o/r/wiki/Plugin-Echo' }))
    const card = screen.getByTestId('plugin-card-echo')
    const link = within(card).getByRole('link', { name: 'Open the Echo documentation' }) as HTMLAnchorElement
    expect(link.getAttribute('href')).toBe('https://github.com/o/r/wiki/Plugin-Echo')
    expect(link.getAttribute('target')).toBe('_blank')
    expect(link.getAttribute('rel')).toContain('noopener')
    expect(link.parentElement?.contains(screen.getByTestId('plugin-state'))).toBe(true)
  })

  test('no documentation in the catalog: no link', () => {
    show(entry())
    expect(screen.queryByRole('link')).toBeNull()
  })
})
