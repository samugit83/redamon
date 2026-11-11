/**
 * The inline Global Settings credential editor.
 *
 * What this guards beyond "it renders": the shortcut writes a USER-level key
 * from inside a project form, so the two things it must never do are imply the
 * value is project-scoped, and imply it can show a stored secret. The API masks
 * secrets on read, so a box pre-filled with the mask would send '••••••••abcd'
 * back as the new token the moment the user pressed Save.
 *
 * Run: npx vitest run src/components/settings/CredentialShortcut.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui/AlertModal'
import { CredentialShortcut } from './CredentialShortcut'
import type { CredentialKeysApi } from '@/hooks/useCredentialKeys'

afterEach(() => cleanup())

function fakeKeys(overrides: Partial<CredentialKeysApi> = {}): CredentialKeysApi {
  return {
    loading: false,
    isSet: () => false,
    masked: () => '',
    save: vi.fn().mockResolvedValue(true),
    saving: null,
    error: '',
    refresh: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  }
}

const KEY = 'trufflehogGithubToken'
/** Every save says how to answer a re-entry refusal (a re-pointed endpoint, review of 1.6). */
const REENTRY_OPTIONS = { onSecretReentry: expect.any(Function) }
const LABEL = 'Secret Multiscanner GitHub Token'

describe('CredentialShortcut', () => {
  test('labels the key and says the value is global, not per-project', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys()} />)
    expect(screen.getByLabelText(LABEL)).toBeDefined()
    // Without this, an inline field inside a project form reads as a project
    // setting while it is in fact shared by every project the user owns.
    expect(screen.getByText('Global setting')).toBeDefined()
  })

  test('an unset mandatory key reads as Required', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys()} />)
    expect(screen.getByText('Required')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDefined()
  })

  test('an unset optional key reads as Optional, not Required', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys()} optional />)
    expect(screen.getByText('Optional')).toBeDefined()
    expect(screen.queryByText('Required')).toBeNull()
  })

  test('a stored secret is never put in the box, only offered as a placeholder', () => {
    const keys = fakeKeys({ isSet: () => true, masked: () => '••••••••cdef' })
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    const input = screen.getByLabelText(LABEL) as HTMLInputElement
    // Editable text would be sent back verbatim on the next save.
    expect(input.value).toBe('')
    expect(input.placeholder).toBe('••••••••cdef')
    expect(screen.getByText('Set')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Replace' })).toBeDefined()
  })

  test('Save is inert until something is typed', () => {
    const keys = fakeKeys()
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    const button = screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    fireEvent.change(screen.getByLabelText(LABEL), { target: { value: 'ghp_abc' } })
    expect(button.disabled).toBe(false)
  })

  test('whitespace alone does not enable Save', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys()} />)
    fireEvent.change(screen.getByLabelText(LABEL), { target: { value: '   ' } })
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
  })

  test('saving sends the trimmed value under the right settings key', async () => {
    const keys = fakeKeys()
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    fireEvent.change(screen.getByLabelText(LABEL), { target: { value: '  ghp_abc  ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(keys.save).toHaveBeenCalledWith(KEY, 'ghp_abc', REENTRY_OPTIONS))
  })

  test('Enter saves without submitting the surrounding form', async () => {
    const keys = fakeKeys()
    const onSubmit = vi.fn(e => e.preventDefault())
    render(
      <form onSubmit={onSubmit}>
        <CredentialShortcut settingsKey={KEY} keys={keys} />
      </form>,
    )
    const input = screen.getByLabelText(LABEL)
    fireEvent.change(input, { target: { value: 'ghp_abc' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(keys.save).toHaveBeenCalledWith(KEY, 'ghp_abc', REENTRY_OPTIONS))
    // The shortcut lives inside the project form; Enter must not save the project.
    expect(onSubmit).not.toHaveBeenCalled()
  })

  test('the box is cleared after a successful save', async () => {
    const keys = fakeKeys()
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    const input = screen.getByLabelText(LABEL) as HTMLInputElement
    fireEvent.change(input, { target: { value: 'ghp_abc' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(input.value).toBe(''))
    expect(screen.getByText('Saved to Global Settings.')).toBeDefined()
  })

  test('a failed save leaves the typed value in place to retry', async () => {
    const keys = fakeKeys({ save: vi.fn().mockResolvedValue(false) })
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    const input = screen.getByLabelText(LABEL) as HTMLInputElement
    fireEvent.change(input, { target: { value: 'ghp_abc' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(keys.save).toHaveBeenCalled())
    expect(input.value).toBe('ghp_abc')
    expect(screen.queryByText('Saved to Global Settings.')).toBeNull()
  })

  test('a secret is typed behind a password field until revealed', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys()} />)
    const input = screen.getByLabelText(LABEL) as HTMLInputElement
    expect(input.type).toBe('password')
    fireEvent.click(screen.getByRole('button', { name: 'Show the value' }))
    expect((screen.getByLabelText(LABEL) as HTMLInputElement).type).toBe('text')
  })

  test('a non-secret value has no reveal toggle and stays readable', () => {
    render(<CredentialShortcut settingsKey="githubEnterpriseHost" keys={fakeKeys()} />)
    const input = screen.getByLabelText('GitHub Enterprise Host') as HTMLInputElement
    // The host is the Supply Chain allowlist; masking it hides what is allowed.
    expect(input.type).toBe('text')
    expect(screen.queryByRole('button', { name: 'Show the value' })).toBeNull()
  })

  test('the input is disabled while its own save is in flight', () => {
    const keys = fakeKeys({ saving: KEY })
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    expect((screen.getByLabelText(LABEL) as HTMLInputElement).disabled).toBe(true)
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeDefined()
  })

  test('another key being saved does not disable this one', () => {
    const keys = fakeKeys({ saving: 'githubAccessToken' })
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    expect((screen.getByLabelText(LABEL) as HTMLInputElement).disabled).toBe(false)
  })

  test('compact drops the hint but keeps the control usable', () => {
    const { container } = render(
      <CredentialShortcut settingsKey={KEY} keys={fakeKeys()} compact />,
    )
    expect(container.textContent).not.toContain('unauthenticated GitHub allows only 60')
    expect(screen.getByLabelText(LABEL)).toBeDefined()
  })

  test('an unknown key renders nothing rather than an unlabelled box', () => {
    const { container } = render(
      <CredentialShortcut settingsKey="notARealKey" keys={fakeKeys()} />,
    )
    expect(container.innerHTML).toBe('')
  })

  test('a failed read says why, so an unset badge is not taken at its word', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys({ loadError: "Couldn't read your saved keys (P1001 · HTTP 500)" })} />)
    expect(screen.getByRole('alert').textContent)
      .toBe("Couldn't read your saved keys (P1001 · HTTP 500), so this key may already be set.")
  })

  test('a key that did load as set shows no read error', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys({ isSet: () => true, loadError: 'stale' })} />)
    expect(screen.queryByRole('alert')).toBeNull()
  })

  describe('a new GitHub Enterprise host with a stored token (re-entry, review of 1.6)', () => {
    const REENTRY = {
      field: 'githubEnterpriseToken', fields: ['githubEnterpriseToken'], endpoint: 'githubEnterpriseHost',
      message: 'The GitHub Enterprise host changed: type the GitHub Enterprise token again, or clear it.',
    }
    /** A save that is refused once and hands the widget's answer back, as the hook does. */
    function refusingKeys() {
      const answers: (Record<string, string> | null)[] = []
      const save = vi.fn(async (_n: string, _v: string, opts?: { onSecretReentry?: (r: typeof REENTRY) => Promise<Record<string, string> | null> }) => {
        const secrets = await opts!.onSecretReentry!(REENTRY)
        answers.push(secrets)
        return secrets !== null
      })
      return { keys: fakeKeys({ save: save as CredentialKeysApi['save'] }), answers }
    }
    async function saveHost(keys: CredentialKeysApi) {
      render(<AlertProvider><CredentialShortcut settingsKey="githubEnterpriseHost" keys={keys} optional /></AlertProvider>)
      fireEvent.change(screen.getByLabelText('GitHub Enterprise Host'), { target: { value: 'ghe2.example.com' } })
      fireEvent.click(screen.getByRole('button', { name: 'Save' }))
      return screen.findByRole('dialog')
    }

    test('the dialog says why and asks for the token; typed, it goes with the same save', async () => {
      const { keys, answers } = refusingKeys()
      const dialog = await saveHost(keys)
      expect(dialog).toHaveTextContent('type the GitHub Enterprise token again')
      fireEvent.change(within(dialog).getByLabelText('GitHub Enterprise Token'), { target: { value: '  ghe_typed  ' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
      await waitFor(() => expect(answers).toEqual([{ githubEnterpriseToken: 'ghe_typed' }]))
      expect(await screen.findByText('Saved to Global Settings.')).toBeDefined()
    })

    test('left empty, the stored token is cleared in the same save', async () => {
      const { keys, answers } = refusingKeys()
      const dialog = await saveHost(keys)
      fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
      await waitFor(() => expect(answers).toEqual([{ githubEnterpriseToken: '' }]))
    })

    test('cancelled, nothing is saved and the typed host stays to retry', async () => {
      const { keys, answers } = refusingKeys()
      const dialog = await saveHost(keys)
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
      await waitFor(() => expect(answers).toEqual([null]))
      expect((screen.getByLabelText('GitHub Enterprise Host') as HTMLInputElement).value).toBe('ghe2.example.com')
    })

    test('outside the app shell (no alert provider) the refusal is only reported', async () => {
      const { keys, answers } = refusingKeys()
      render(<CredentialShortcut settingsKey="githubEnterpriseHost" keys={keys} optional />)
      fireEvent.change(screen.getByLabelText('GitHub Enterprise Host'), { target: { value: 'ghe2.example.com' } })
      fireEvent.click(screen.getByRole('button', { name: 'Save' }))
      await waitFor(() => expect(answers).toEqual([null]))
    })
  })
})
