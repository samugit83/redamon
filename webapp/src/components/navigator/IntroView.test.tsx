/** The Intro placeholder (plan §9.5): its text, its variants and the AI Agent button. */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { render, cleanup, screen, fireEvent } from '@testing-library/react'
import { IntroView } from './views/IntroView'

afterEach(cleanup)

describe('IntroView', () => {
  test('says what it does, that it only reads, and that it is not the AI Agent', () => {
    const open = vi.fn()
    render(<IntroView agentAllowed onOpenAgent={open} />)
    expect(screen.getByText(/helps you find your way around RedAmon and this project/)).toBeTruthy()
    expect(screen.getByText('I only read.')).toBeTruthy()
    expect(screen.getByText('I am not the RedAmon AI Agent.')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Open the AI Agent →' }))
    expect(open).toHaveBeenCalled()
  })

  test('without agent:chat the button is replaced by why', () => {
    render(<IntroView agentAllowed={false} onOpenAgent={() => {}} />)
    expect(screen.queryByRole('button', { name: /Open the AI Agent/ })).toBeNull()
    expect(screen.getByText(/You don.t have access to the AI Agent on this project/)).toBeTruthy()
  })

  test.each([
    ['no_project', /Select a project in the header to start/],
    ['owner_disallowed', /hasn't enabled AI Navigator for collaborators/],
    ['navigator_not_available', /isn't available with this kind of access/],
  ] as const)('%s variant', (variant, text) => {
    render(<IntroView variant={variant} agentAllowed />)
    expect(screen.getByRole('status').textContent).toMatch(text)
  })
})
