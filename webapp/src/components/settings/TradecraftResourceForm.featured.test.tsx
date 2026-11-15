/**
 * Quick Add shows the five Featured presets first, in a fixed order, then the
 * alphabetical list without them; search covers both; a click fills only the name and
 * the URL (U3: the Featured group ships before presets carry settings).
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui/AlertModal/AlertModal'
import { TradecraftResourceForm } from './TradecraftResourceForm'
import { ALPHABETICAL_PRESETS, FEATURED_PRESETS } from '@/lib/tradecraft/presets'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn(), back: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => '/settings',
  useSearchParams: () => new URLSearchParams(),
}))

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderAdd() {
  vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 200 })))
  render(
    <AlertProvider>
      <TradecraftResourceForm userId="user-1" resource={null} onSave={vi.fn()} onCancel={vi.fn()} />
    </AlertProvider>,
  )
  return screen.getByRole('listbox', { name: 'Curated tradecraft resources' })
}

const presetNames = (scope: HTMLElement) =>
  within(scope).getAllByRole('button').map(b => b.textContent)

const search = (text: string) =>
  fireEvent.change(screen.getByPlaceholderText(/search by name, type/), { target: { value: text } })

describe('Quick Add: Featured presets', () => {
  test('featured_group_first', () => {
    const list = renderAdd()
    const groups = within(list).getAllByRole('group')
    expect(groups.map(g => g.getAttribute('aria-label'))).toEqual(['Featured', 'All resources'])
    expect(presetNames(groups[0])).toEqual(FEATURED_PRESETS.map(p => p.name))
    expect(presetNames(list).slice(0, 5)).toEqual(FEATURED_PRESETS.map(p => p.name))
    // Shown once: the alphabetical group holds the other 100, in their order.
    expect(presetNames(groups[1])).toEqual(ALPHABETICAL_PRESETS.map(p => p.name))
  })

  test('search_finds_featured_and_others', () => {
    const list = renderAdd()
    search('payloads')
    const names = presetNames(list)
    expect(names).toContain('HexBrain payloads')
    expect(names).toContain('PayloadsAllTheThings')
    expect(within(list).getByRole('group', { name: 'Featured' })).toBeInTheDocument()
    search('agentic-bug')
    expect(presetNames(list)).toEqual(['Agentic-Bug-Hunter'])
    expect(within(list).queryByRole('group', { name: 'All resources' })).toBeNull()
    search('zzz-no-such-preset')
    expect(within(list).getByText(/No resources match/)).toBeInTheDocument()
    expect(screen.getByText(/· 0 of 105 resources/)).toBeInTheDocument()
  })

  test('counter_shows_105', () => {
    renderAdd()
    expect(screen.getByText(/· 105 of 105 resources/)).toBeInTheDocument()
    search('HexBrain')
    expect(screen.getByText(/· 1 of 105 resources/)).toBeInTheDocument()
  })

  test('click_fills_name_and_url_only', () => {
    renderAdd()
    const nameInput = screen.getByPlaceholderText('HackTricks') as HTMLInputElement
    const urlInput = screen.getByPlaceholderText('https://book.hacktricks.wiki') as HTMLInputElement
    const tokenInput = screen.getByPlaceholderText(/leave blank to use the user-level GitHub token/) as HTMLInputElement
    fireEvent.click(screen.getByRole('button', { name: 'Web Hacking Techniques Index' }))
    expect(nameInput.value).toBe('Web Hacking Techniques Index')
    expect(urlInput.value).toBe('https://webhacklist.com/?year=2026-ai')
    expect(tokenInput.value).toBe('')
    expect((screen.getByLabelText(/Enabled/) as HTMLInputElement).checked).toBe(true)
  })
})
