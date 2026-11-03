/**
 * The Secret Multiscanner drawer in Global Settings.
 *
 * Putting 19 keys behind one drawer is only safe if the closed state answers
 * what the hidden fields would have. The failures pinned here are the ones that
 * turn a tidier page into a worse one: a mandatory unset key with nothing on
 * screen to say so, a drawer that shuts itself while being typed into, a
 * summary that leaks a stored secret, and a compacted label that stops
 * identifying its key to a screen reader.
 *
 * Run: npx vitest run src/components/settings/CredentialDrawer.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { CredentialDrawer } from './CredentialDrawer'
import { githubKeyGroups, trufflehogKeyGroups } from '@/lib/credentialFields'

afterEach(() => cleanup())

const GITHUB = 'trufflehogGithubToken'
const HF = 'trufflehogHuggingfaceToken'
/** Every key that has to be set before the drawer stops flagging one missing. */
const ALL_REQUIRED = {
  [GITHUB]: 'x',
  trufflehogGitlabToken: 'x',
  trufflehogPostmanToken: 'x',
  trufflehogCircleciToken: 'x',
  trufflehogTravisciToken: 'x',
}

function renderDrawer(values: Record<string, string> = {}, onChange = vi.fn()) {
  render(
    <CredentialDrawer
      id="trufflehog-keys"
      title="Secret Multiscanner"
      intro="One key per source."
      groups={trufflehogKeyGroups()}
      value={name => values[name] ?? ''}
      isSet={name => !!values[name]}
      visible={() => false}
      onToggleVisibility={vi.fn()}
      onChange={onChange}
    />,
  )
  return onChange
}

const drawerButton = () => screen.getByRole('button', { name: /Secret Multiscanner/ })

describe('CredentialDrawer: Secret Multiscanner', () => {
  test('a missing mandatory key opens the drawer rather than hiding behind it', () => {
    renderDrawer()
    expect(screen.getByLabelText('GitHub Token')).toBeDefined()
  })

  test('with every mandatory key set the drawer starts closed', () => {
    renderDrawer(ALL_REQUIRED)
    expect(screen.queryByLabelText('GitHub Token')).toBeNull()
    expect(drawerButton().textContent).not.toContain('required missing')
  })

  test('the header counts what is set and how many sources still block a scan', () => {
    renderDrawer({ [GITHUB]: 'ghp_x' })
    const header = drawerButton().textContent ?? ''
    expect(header).toContain('1 of 19 keys set')
    // GitHub is set; GitLab, Postman, CircleCI and Travis CI are not.
    expect(header).toContain('4 required missing')
  })

  test('the closed summary says per source what is set and what is not', () => {
    renderDrawer(ALL_REQUIRED)
    const summary = drawerButton().parentElement?.textContent ?? ''
    expect(summary).toContain('Jenkins')
    expect(summary).toContain('Elasticsearch')
    expect(summary).toContain('0/4')
  })

  test('neither the header nor the summary renders a stored value', () => {
    renderDrawer({ ...ALL_REQUIRED, [HF]: 'hf_supersecret' })
    expect(document.body.textContent).not.toContain('hf_supersecret')
  })

  test('clicking the header opens and closes the whole section', () => {
    renderDrawer(ALL_REQUIRED)
    fireEvent.click(drawerButton())
    expect(screen.getByLabelText('Hugging Face Token')).toBeDefined()
    expect(screen.getByLabelText('Jenkins Password')).toBeDefined()
    fireEvent.click(drawerButton())
    expect(screen.queryByLabelText('Hugging Face Token')).toBeNull()
  })

  // The four Elasticsearch keys are four ways to authenticate one cluster. Read
  // as four unrelated tokens, a user sets all of them and the scan fails.
  test('a source with several keys is one card, headed by the source name', () => {
    renderDrawer()
    const card = document.getElementById('trufflehog-keys-elasticsearch')!
    expect(card.textContent).toContain('Elasticsearch')
    expect(card.querySelectorAll('input').length).toBe(4)
    expect(card.className).toMatch(/cardGroup/)
  })

  test('a single-key source gets no card head to repeat itself', () => {
    renderDrawer()
    const card = document.getElementById('trufflehog-keys-github')!
    expect(card.querySelectorAll('input').length).toBe(1)
    expect(card.className).not.toMatch(/cardGroup/)
  })

  // One token, two sources: a footnote beside the name reads as a caveat, so
  // the second source is part of the name instead.
  test('a key read by a second source names it in the label', () => {
    renderDrawer()
    const card = document.getElementById('trufflehog-keys-github')!
    expect(card.querySelector('label')?.textContent).toBe('GitHub Token + GitHub deleted commits')
    expect(card.textContent).not.toContain('also')
  })

  test('a key under a card head drops the source name it would repeat', () => {
    renderDrawer()
    const card = document.getElementById('trufflehog-keys-jenkins')!
    expect(card.textContent).toContain('Username')
    expect(card.textContent).not.toContain('Jenkins Username')
  })

  // Shortening is for the eye only: 'Password' on its own names nothing.
  test('the shortened label still reaches a screen reader in full', () => {
    renderDrawer()
    expect(screen.getByLabelText('Jenkins Password')).toBeDefined()
    expect(screen.getByLabelText('Elasticsearch Service Token')).toBeDefined()
  })

  test('a key weaker than its card head says so, and the rest stay quiet', () => {
    renderDrawer()
    const s3 = document.getElementById('trufflehog-keys-s3')!
    // Access key and secret inherit the card's "Sometimes required"; only the
    // STS session token is optional, so only it is chipped. Counted as chips,
    // not as text: the session token's own hint opens with the word too.
    expect(s3.querySelectorAll('[class*="chipOptional"]').length).toBe(1)
    expect(s3.querySelectorAll('[class*="chipConditional"]').length).toBe(1)
  })

  test('a key carries its own description, not just a label', () => {
    renderDrawer()
    expect(screen.getByText(/only 60 requests\/hour/)).toBeDefined()
  })

  test('typing reports the settings column, not the label', () => {
    const onChange = renderDrawer()
    fireEvent.change(screen.getByLabelText('GitHub Token'), { target: { value: 'ghp_new' } })
    expect(onChange).toHaveBeenCalledWith(GITHUB, 'ghp_new')
  })
})

/**
 * The GitHub drawer. What it must not do is imply the two github.com tokens are
 * interchangeable: Secret Hunt blocks without its own, Supply Chain only needs
 * one for a private repo, and the Enterprise PAT is for a different server.
 */
describe('CredentialDrawer: GitHub & Supply Chain', () => {
  function renderGithub(values: Record<string, string> = {}, onChange = vi.fn()) {
    render(
      <CredentialDrawer
        id="github-keys"
        title="GitHub &amp; Supply Chain"
        intro="One token per consumer."
        groups={githubKeyGroups()}
        value={name => values[name] ?? ''}
        isSet={name => !!values[name]}
        visible={() => false}
        onToggleVisibility={vi.fn()}
        onChange={onChange}
      />,
    )
    return onChange
  }

  const githubTrigger = () =>
    document.querySelector('[aria-controls="github-keys-panel"]') as HTMLButtonElement

  test('Secret Hunt and Supply Chain are separate keys, not one shared box', () => {
    renderGithub()
    const hunt = screen.getByLabelText('GitHub Access Token')
    const supply = screen.getByLabelText('Supply Chain GitHub Token')
    expect(hunt).not.toBe(supply)
    expect(document.getElementById('github-keys-github-secret-hunt')).toBeDefined()
    expect(document.getElementById('github-keys-supply-chain')).toBeDefined()
  })

  test('the GitHub Access Token row names the features that use it without requiring it', () => {
    renderGithub()
    const row = document.getElementById('github-keys-github-secret-hunt')!
    expect(row.textContent).toContain('GitHub Access Token')
    expect(row.textContent).toContain('+ Tradecraft Lookup, Workspace URL import')
    expect(row.textContent).toContain('Required for GitHub Secret Hunt')
  })

  test('typing one token does not write the other', () => {
    const onChange = renderGithub()
    fireEvent.change(screen.getByLabelText('Supply Chain GitHub Token'), { target: { value: 'ghp_sc' } })
    expect(onChange).toHaveBeenCalledTimes(1)
    expect(onChange).toHaveBeenCalledWith('supplyChainGithubToken', 'ghp_sc')
  })

  test('only Secret Hunt blocks: it is the one that cannot run unauthenticated', () => {
    renderGithub()
    expect(githubTrigger().textContent).toContain('1 required missing')
    expect(document.getElementById('github-keys-supply-chain')!.textContent)
      .toContain('Sometimes required')
  })

  test('the Enterprise host and its PAT are one card, not two loose settings', () => {
    renderGithub({ githubAccessToken: 'x' })
    fireEvent.click(githubTrigger())
    const card = document.getElementById('github-keys-github-enterprise')!
    expect(card.className).toMatch(/cardGroup/)
    expect(card.querySelectorAll('input').length).toBe(2)
  })

  // A hostname is the allowlist the operator has to be able to read back.
  test('the Enterprise host is not masked and has no reveal toggle', () => {
    renderGithub({ githubAccessToken: 'x' })
    fireEvent.click(githubTrigger())
    const host = screen.getByLabelText('GitHub Enterprise Host') as HTMLInputElement
    expect(host.type).toBe('text')
    expect(host.placeholder).toBe('ghe.example.com')
    const token = screen.getByLabelText('GitHub Enterprise Token') as HTMLInputElement
    expect(token.type).toBe('password')
  })
})
