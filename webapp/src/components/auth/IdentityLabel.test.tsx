/**
 * IdentityLabel (step 2.11, ID-31; feature document §3 F-21): a security screen names an account
 * by its name, its email and its account type (Root, Admin, Member), never by the display name
 * alone, which anyone can set to look like someone else. Used by the user switcher, the Users
 * page and the later security screens (act-as banner, share dialog, feed, approvals).
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { IdentityLabel, accountTypeFor, ACCOUNT_TYPE_LABEL } from './IdentityLabel'

afterEach(() => cleanup())

describe('IdentityLabel', () => {
  test('shows the name, the email and the account type', () => {
    render(<IdentityLabel name="Laura" email="laura@e2e.local" accountType="root" />)
    const label = screen.getByTestId('identity-label')
    expect(label).toHaveTextContent('Laura')
    expect(label).toHaveTextContent('laura@e2e.local')
    expect(screen.getByText('Root')).toBeInTheDocument()
    // Read as one phrase by a screen reader.
    expect(label).toHaveAttribute('aria-label', 'Laura, laura@e2e.local, Root')
  })

  test.each([['root', 'Root'], ['admin', 'Admin'], ['member', 'Member']] as const)('%s reads %s', (type, text) => {
    render(<IdentityLabel name="X" email="x@e2e.local" accountType={type} />)
    expect(screen.getByText(text)).toHaveAttribute('data-account-type', type)
    expect(ACCOUNT_TYPE_LABEL[type]).toBe(text)
  })

  test('two accounts with the same display name are told apart by their email', () => {
    render(
      <>
        <IdentityLabel name="Admin" email="real-admin@e2e.local" accountType="admin" />
        <IdentityLabel name="Admin" email="lookalike@e2e.local" accountType="member" />
      </>,
    )
    const labels = screen.getAllByTestId('identity-label')
    expect(labels[0]).toHaveTextContent('real-admin@e2e.local')
    expect(labels[1]).toHaveTextContent('lookalike@e2e.local')
    expect(labels[1]).toHaveTextContent('Member')
  })

  test('without an account type (identity switch off) the stored role shows, as before', () => {
    render(<IdentityLabel name="Bob" email="bob@e2e.local" role="standard" />)
    expect(screen.getByText('standard')).toBeInTheDocument()
    expect(screen.getByTestId('identity-label')).toHaveAttribute('aria-label', 'Bob, bob@e2e.local, standard')
  })

  test('an empty name falls back to the email, never to nothing', () => {
    render(<IdentityLabel name="" email="nameless@e2e.local" accountType="member" />)
    expect(screen.getByTestId('identity-label')).toHaveAttribute('aria-label', 'nameless@e2e.local, Member')
  })
})

describe('accountTypeFor', () => {
  const root = { email: 'root@e2e.local' }
  test('Root is the admin whose address is the Root\'s, ignoring case', () => {
    expect(accountTypeFor({ role: 'admin', email: 'ROOT@e2e.local' }, root)).toBe('root')
    expect(accountTypeFor({ role: 'admin', email: 'other@e2e.local' }, root)).toBe('admin')
    expect(accountTypeFor({ role: 'standard', email: 'root@e2e.local' }, root)).toBe('member')
  })

  test('no Root known: admins and members', () => {
    expect(accountTypeFor({ role: 'admin', email: 'a@e2e.local' }, null)).toBe('admin')
    expect(accountTypeFor({ role: 'standard', email: 'm@e2e.local' })).toBe('member')
  })
})
