/** Shared by the resource form's section tests: render a section in the harness, open it, list its settings. */
import { render, fireEvent, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { Harness } from './formHarness'
import type { FormContext } from '../form/OverrideList'

export function renderSection(section: (ctx: FormContext) => ReactNode, initial: Record<string, unknown> = {}) {
  return render(<Harness initial={initial}>{section}</Harness>)
}

export function open(title: string): void {
  fireEvent.click(screen.getByRole('button', { name: new RegExp(`^${title}`) }))
}

/** The setting keys rendered, in order. */
export function shownKeys(container: HTMLElement): string[] {
  return [...container.querySelectorAll('[data-setting]')].map(e => e.getAttribute('data-setting')!)
}

/** The status line of a collapsed section. */
export function statusOf(title: string): string {
  const head = screen.getByRole('button', { name: new RegExp(`^${title}`) })
  return head.lastElementChild?.textContent ?? ''
}
