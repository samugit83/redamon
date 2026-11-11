/**
 * The Include / Exclude editor of Record + scan matching (04_ui_spec.md §2, §7,
 * §8): parsed with the save's own parser, invalid and hard-blocked entries
 * called out, file import, raw drafts that keep a separator while it is typed.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/IpHostnameFilterEditor.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'
import { useState } from 'react'
import { IpHostnameFilterEditor, parseFilterText } from './IpHostnameFilterEditor'

afterEach(() => { cleanup() })

function Harness({ include = [] as string[], exclude = [] as string[], spy = vi.fn() }) {
  const [inc, setInc] = useState(include)
  const [exc, setExc] = useState(exclude)
  const [expand, setExpand] = useState(true)
  return (
    <IpHostnameFilterEditor
      include={inc} exclude={exc} passiveExpand={expand}
      onIncludeChange={v => { setInc(v); spy('include', v) }}
      onExcludeChange={v => { setExc(v); spy('exclude', v) }}
      onPassiveExpandChange={v => { setExpand(v); spy('expand', v) }}
    />
  )
}

const includeBox = () => screen.getByLabelText('Include (one per line)') as HTMLTextAreaElement
const excludeBox = () => screen.getByLabelText('Exclude (one per line)') as HTMLTextAreaElement

describe('parse', () => {
  test('one per line, or separated by commas, semicolons or spaces', () => {
    expect(parseFilterText('*.example.com\nshop.example.fr, a.example.de; b.example.de  c.example.de\n\n'))
      .toEqual(['*.example.com', 'shop.example.fr', 'a.example.de', 'b.example.de', 'c.example.de'])
  })

  test('typed entries go up parsed; the textarea keeps the separator being typed', () => {
    const spy = vi.fn()
    render(<Harness spy={spy} />)
    fireEvent.change(includeBox(), { target: { value: '*.example.com\n' } })
    expect(includeBox().value).toBe('*.example.com\n')
    expect(spy).toHaveBeenLastCalledWith('include', ['*.example.com'])
    fireEvent.change(includeBox(), { target: { value: '*.example.com\n*.example.de, ' } })
    expect(includeBox().value).toBe('*.example.com\n*.example.de, ')
    expect(spy).toHaveBeenLastCalledWith('include', ['*.example.com', '*.example.de'])
  })

  test('leaving the box shows the list one per line', () => {
    render(<Harness />)
    fireEvent.change(excludeBox(), { target: { value: 'old.example.com, legacy.example.com' } })
    fireEvent.blur(excludeBox())
    expect(excludeBox().value).toBe('old.example.com\nlegacy.example.com')
  })
})

describe('callouts', () => {
  test('a refused entry is named with its reason; an address gets IP-mode wording', () => {
    render(<Harness include={['*.example.com', 'co.uk', '203.0.113.10']} />)
    const alert = screen.getByRole('alert')
    expect(within(alert).getByText('co.uk').closest('li')!.textContent).toMatch(/public suffix/)
    expect(within(alert).getByText('203.0.113.10').closest('li')!.textContent)
      .toMatch(/filters name hostnames, and your IPs are the targets above/)
    expect(includeBox().getAttribute('aria-invalid')).toBe('true')
    expect(document.getElementById(includeBox().getAttribute('aria-describedby')!)).toBe(alert)
  })

  test('a hard-blocked include entry is called out before the save', () => {
    render(<Harness include={['*.example.gov']} />)
    expect(screen.getByText(/Target permanently blocked: example\.gov/)).toBeInTheDocument()
  })

  test('no include entry: the save will be refused, and the editor says so', () => {
    render(<Harness />)
    expect(screen.getByText(/Add at least one include entry/)).toBeInTheDocument()
    fireEvent.change(includeBox(), { target: { value: '*.example.com' } })
    expect(screen.queryByText(/Add at least one include entry/)).toBeNull()
  })

  test('more than 200 entries is refused (D-05)', () => {
    render(<Harness exclude={Array.from({ length: 201 }, (_, i) => `h${i}.example.com`)} />)
    expect(screen.getByText(/At most 200 entries/)).toBeInTheDocument()
  })

  test('the matching rule is spelled out under the lists', () => {
    render(<Harness />)
    expect(screen.getByText(/every name under it/).textContent).toMatch(/exactly that host · exclude wins/)
  })
})

describe('import and the passive search', () => {
  test('each list has its own import button', () => {
    render(<Harness />)
    expect(screen.getAllByRole('button', { name: /import/i }).length).toBe(2)
  })

  test('an imported file replaces the list', async () => {
    const spy = vi.fn()
    const { container } = render(<Harness spy={spy} />)
    const input = container.querySelectorAll('input[type="file"]')[0] as HTMLInputElement
    const file = new File(['*.example.com\nshop.example.fr\n'], 'scope.txt', { type: 'text/plain' })
    fireEvent.change(input, { target: { files: [file] } })
    await vi.waitFor(() => expect(spy).toHaveBeenCalledWith('include', ['*.example.com', 'shop.example.fr']))
  })

  test('the passive search checkbox is on by default and reports a change', () => {
    const spy = vi.fn()
    render(<Harness spy={spy} include={['*.example.com', 'app.example.org']} />)
    const box = screen.getByLabelText(/Also search subdomains of the filter domains/) as HTMLInputElement
    expect(box.checked).toBe(true)
    expect(screen.getByText(/1 \*\. entry searched/)).toBeInTheDocument()
    fireEvent.click(box)
    expect(spy).toHaveBeenCalledWith('expand', false)
  })
})
