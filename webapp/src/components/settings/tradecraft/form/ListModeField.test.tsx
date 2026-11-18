/** Lists add to or replace the account's (§6.1, R-132). */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { settingDef } from '@/lib/tradecraft/settingsSpec'
import { ListModeField } from './ListModeField'
import { Harness, latest } from '../__testing__/formHarness'
import { inheritedOf } from './OverrideList'

afterEach(cleanup)

function field(key: string, initial: Record<string, unknown> = {}) {
  const def = settingDef(key)!
  return render(
    <Harness initial={initial}>
      {ctx => <ListModeField def={def} inherited={inheritedOf(ctx, def)} value={ctx.overrides[key]} onChange={v => ctx.setOverride(key, v)} userId="user-1" />}
    </Harness>,
  )
}

describe('ListModeField', () => {
  test('list_mode: add to mine by default, replace on request, items edited', () => {
    field('knownTypes.githubFileTypes')
    expect(screen.getByText('Using your setting: .md, .txt')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Override GitHub file types' }))
    expect(latest.overrides).toEqual({ 'knownTypes.githubFileTypes': { mode: 'add', items: [] } })
    fireEvent.change(screen.getByLabelText('GitHub file types'), { target: { value: '.yml' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add to GitHub file types' }))
    expect(latest.overrides).toEqual({ 'knownTypes.githubFileTypes': { mode: 'add', items: ['.yml'] } })
    fireEvent.click(screen.getByRole('radio', { name: /Replace mine/ }))
    expect(latest.overrides).toEqual({ 'knownTypes.githubFileTypes': { mode: 'replace', items: ['.yml'] } })
    fireEvent.click(screen.getByRole('button', { name: 'Remove .yml' }))
    expect(latest.overrides).toEqual({ 'knownTypes.githubFileTypes': { mode: 'replace', items: [] } })
  })

  test('a text in list mode: the summary instructions', () => {
    field('summary.extraInstructions', { 'summary.extraInstructions': { mode: 'replace', text: 'old' } })
    expect(screen.getByRole('radio', { name: /Replace mine/ })).toBeChecked()
    fireEvent.change(screen.getByLabelText('Extra instructions'), { target: { value: 'List the classes.' } })
    expect(latest.overrides).toEqual({ 'summary.extraInstructions': { mode: 'replace', text: 'List the classes.' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Override Extra instructions' }))
    expect(latest.overrides).toEqual({})
  })
})
