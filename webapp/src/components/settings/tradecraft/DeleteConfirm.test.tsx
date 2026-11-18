/**
 * The delete confirmation names everything that goes (R-196).
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup, within } from '@testing-library/react'
import { DeleteConfirm } from './DeleteConfirm'
import { RESOURCE, job } from './__testing__/resourceView'

afterEach(cleanup)
const items = () => within(screen.getByRole('list', { name: 'What is deleted' })).getAllByRole('listitem').map(li => li.textContent)

describe('DeleteConfirm', () => {
  test('lists_what_goes: stored pages, report, running job, login, token, project choices', () => {
    render(<DeleteConfirm resource={{ ...RESOURCE, storageMode: 'stored', entryCount: 3, hasLogin: true, githubTokenOverride: 'set', job: job({}) }} />)
    expect(items()).toEqual([
      'its map and the 3 stored pages',
      'its summary and its ingestion report',
      'the job running now, which is cancelled first',
      'its site login',
      'its GitHub token',
      'the choices every project made for it',
    ])
    expect(screen.getByText(/Conversations that quoted its pages keep their text/)).toBeInTheDocument()
  })

  test('a Live resource with nothing else: its map, summary, report and project choices', () => {
    render(<DeleteConfirm resource={{ ...RESOURCE, entryCount: 1 }} />)
    expect(items()).toEqual(['its map (1 entry)', 'its summary and its ingestion report', 'the choices every project made for it'])
  })
})
