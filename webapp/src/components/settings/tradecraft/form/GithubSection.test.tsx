/** GitHub repository (§6.5): its settings, and Check URL's branches and folders offered with one click. */
import { describe, test, expect, afterEach } from 'vitest'
import { screen, cleanup, fireEvent } from '@testing-library/react'
import { GithubSection } from './GithubSection'
import { latest } from '../__testing__/formHarness'
import { open, renderSection, shownKeys, statusOf } from '../__testing__/sectionTests'
import { SECTION_KEYS } from './sections'

afterEach(cleanup)
const GITHUB = { default_branch: 'main', branches: ['main', 'dev'], tags: ['v1.0'], top_folders: ['SQL Injection/', 'XSS Injection/'] }

describe('GithubSection', () => {
  test('collapsed with its status; open, every GitHub setting', () => {
    const { container } = renderSection(ctx => <GithubSection ctx={ctx} github={null} />, { 'type.github.branch': 'dev' })
    expect(statusOf('GitHub repository')).toBe('1 override')
    open('GitHub repository')
    expect(shownKeys(container)).toEqual(SECTION_KEYS.github)
  })

  test('Check URL\'s branches, tags and folders are one click away', () => {
    renderSection(ctx => <GithubSection ctx={ctx} github={GITHUB} />)
    open('GitHub repository')
    fireEvent.click(screen.getByRole('button', { name: 'v1.0' }))
    expect(latest.overrides['type.github.branch']).toBe('v1.0')
    fireEvent.click(screen.getByRole('button', { name: '+ SQL Injection/' }))
    expect(latest.overrides['type.github.includeFolders']).toEqual(['SQL Injection/'])
    fireEvent.click(screen.getByRole('button', { name: '− XSS Injection/' }))
    expect(latest.overrides['type.github.excludeFolders']).toEqual(['XSS Injection/'])
    expect(screen.queryByRole('button', { name: '+ SQL Injection/' })).toBeNull()
  })
})
