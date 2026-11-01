/**
 * The file managers in the FFuf, Nuclei and JS Recon sections show why an upload
 * or a delete failed: the route's sentence with its code and HTTP status. Before,
 * a delete failed silently, an oversized body read as "Upload failed. Please try
 * again.", and a JS file's error rendered only inside the collapsed custom-files
 * panel. A create-mode form cannot upload: the routes check ownership of a saved
 * project, and a pre-generated id has none.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/sections/uploadErrors.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

import { FfufSection } from './FfufSection'
import { NucleiSection } from './NucleiSection'
import { JsReconSection } from './JsReconSection'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

type Route = (url: string, init?: RequestInit) => Response | undefined

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

let route: Route
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  route = () => undefined
  fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    return route(url, init) ?? json(200, [])
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const TOO_LARGE = { error: 'The upload is larger than 50 MB.', code: 'body_too_large', limitBytes: 50 * 1024 * 1024 }

function pick(container: HTMLElement, accept: string, file: File) {
  const input = container.querySelector(`input[type="file"][accept="${accept}"]`) as HTMLInputElement
  fireEvent.change(input, { target: { files: [file] } })
}

describe('FFuf wordlists', () => {
  const WORDLIST = { name: 'paths.txt', path: '/app/recon/wordlists/p1/paths.txt', size: 6 }
  const mount = (mode: 'create' | 'edit' = 'edit') => render(
    <FfufSection data={{ ffufEnabled: true } as never} updateField={vi.fn() as never} projectId="p1" mode={mode} />,
  )

  test('an oversized upload shows the limit and the status', async () => {
    route = (url, init) => (url === '/api/projects/p1/wordlists' && init?.method === 'POST' ? json(413, TOO_LARGE) : undefined)
    const { container } = mount()
    pick(container, '.txt,text/plain', new File(['x'], 'big.txt'))
    expect(await screen.findByText('The upload is larger than 50 MB. (body_too_large · HTTP 413)')).toBeInTheDocument()
  })

  test('a failed delete is shown, not swallowed', async () => {
    route = (url, init) => {
      if (url === '/api/projects/p1/wordlists' && !init?.method) return json(200, { wordlists: [WORDLIST] })
      if (url.startsWith('/api/projects/p1/wordlists?name=') && init?.method === 'DELETE') {
        return json(500, { error: 'Failed to delete wordlist', code: 'EACCES' })
      }
      return undefined
    }
    mount()
    fireEvent.click(await screen.findByTitle('Delete paths.txt'))
    expect(await screen.findByText('Failed to delete wordlist (EACCES · HTTP 500)')).toBeInTheDocument()
  })

  test('a create-mode form asks to save first instead of uploading to a project that does not exist yet', () => {
    const { container } = mount('create')
    expect(screen.getByText(/Save the project first; then you can upload \.txt payload lists \(max 50MB\)/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Upload \.txt/ })).toBeDisabled()
    expect(container.querySelector('input[type="file"][accept=".txt,text/plain"]')).not.toBeNull()
    expect(fetchMock.mock.calls.some(c => String(c[0]).includes('/wordlists'))).toBe(false)
  })
})

describe('Nuclei templates', () => {
  const TEMPLATE = { id: 'demo', name: 'Demo', severity: 'low', file: 'demo.yaml', path: 'demo.yaml', size: 10 }
  const mount = () => render(
    <NucleiSection data={{ nucleiEnabled: true, nucleiSeverity: [], nucleiSelectedCustomTemplates: [] } as never} updateField={vi.fn() as never} />,
  )

  test('a filesystem failure on upload shows its errno', async () => {
    route = (url, init) => (url === '/api/nuclei-templates' && init?.method === 'POST'
      ? json(500, { error: 'Failed to upload template', code: 'EROFS' }) : undefined)
    const { container } = mount()
    pick(container, '.yaml,.yml', new File(['id: demo'], 'demo.yaml'))
    expect(await screen.findByText('Failed to upload template (EROFS · HTTP 500)')).toBeInTheDocument()
  })

  test('a failed delete is shown, not swallowed', async () => {
    route = (url, init) => {
      if (url === '/api/nuclei-templates' && !init?.method) return json(200, { templates: [TEMPLATE] })
      if (url.startsWith('/api/nuclei-templates?path=') && init?.method === 'DELETE') {
        return json(500, { error: 'Failed to delete template', code: 'EACCES' })
      }
      return undefined
    }
    mount()
    fireEvent.click(await screen.findByTitle('Delete demo.yaml'))
    expect(await screen.findByText('Failed to delete template (EACCES · HTTP 500)')).toBeInTheDocument()
  })
})

describe('JS Recon files', () => {
  const mount = (mode: 'create' | 'edit' = 'edit') => render(
    <JsReconSection data={{ jsReconEnabled: true } as never} updateField={vi.fn() as never} projectId="p1" mode={mode} />,
  )

  test('a create-mode form asks to save first instead of uploading to a project that does not exist yet', () => {
    const { container } = mount('create')
    expect(screen.getByText(/Save the project first; then you can upload JS files for analysis \(max 10MB each\)/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Upload JS Files/ })).toBeNull()
    expect(screen.queryByText('Custom Extension Files')).toBeNull()
    expect(container.querySelector('input[type="file"]')).toBeNull()
    // The project's own routes; the TruffleHog availability check is not per project.
    expect(fetchMock.mock.calls.some(c => String(c[0]).includes('/api/js-recon/p1/'))).toBe(false)
  })

  test('an edit-mode form offers the uploads and no save-first hint', async () => {
    mount('edit')
    expect(screen.getByRole('button', { name: /Upload JS Files/ })).toBeInTheDocument()
    expect(screen.queryByText(/Save the project first/)).toBeNull()
    await waitFor(() => expect(fetchMock.mock.calls.some(c => String(c[0]) === '/api/js-recon/p1/upload')).toBe(true))
  })

  test('a JS upload error shows beside the upload button, with the file name', async () => {
    route = (url, init) => (url === '/api/js-recon/p1/upload' && init?.method === 'POST'
      ? json(413, { error: 'The upload is larger than 10 MB.', code: 'body_too_large', limitBytes: 10 * 1024 * 1024 })
      : undefined)
    const { container } = mount()
    pick(container, '.js,.mjs,.map,.json', new File(['var a'], 'app.js'))
    expect(await screen.findByText('app.js: The upload is larger than 10 MB. (body_too_large · HTTP 413)')).toBeInTheDocument()
  })

  test('a failed delete of an uploaded JS file is shown', async () => {
    route = (url, init) => {
      if (url === '/api/js-recon/p1/upload' && !init?.method) {
        return json(200, { files: [{ name: 'app.js', size: 5, uploaded_at: '2026-10-01T00:00:00.000Z' }] })
      }
      if (url.startsWith('/api/js-recon/p1/upload?name=') && init?.method === 'DELETE') {
        return json(500, { error: 'Failed to delete file', code: 'P1001' })
      }
      if (url === '/api/js-recon/p1/custom-files') return json(200, { files: {} })
      return undefined
    }
    mount()
    fireEvent.click(await screen.findByTitle('Delete app.js'))
    await waitFor(() => expect(screen.getByText('Failed to delete file (P1001 · HTTP 500)')).toBeInTheDocument())
  })
})
