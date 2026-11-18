/**
 * The librarian model in the accordion's header (Q10 "One value, shown in three places", T7.5):
 * read-only for the owner, "Librarian model not set" when it is missing, "The owner hasn't chosen a
 * librarian model" for anyone else; nothing with "Search only".
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { LIBRARIAN_NOT_SET, OWNER_LIBRARIAN_NOT_SET, TradecraftResourcesAccordion, librarianWarning } from './TradecraftResourcesAccordion'
import type { ProjectTradecraftView } from '@/lib/tradecraft/projectView'

let view: ProjectTradecraftView
beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(view), { status: 200 })))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
const draw = () => render(<TradecraftResourcesAccordion projectId="p1" offIds={[]} onChange={vi.fn()} />)
const V = (over: Partial<ProjectTradecraftView>): ProjectTradecraftView => ({ v2: true, viewerIsOwner: true, resources: [], counts: null, ...over })

describe('the librarian in the accordion header', () => {
  test('accordion_warning_owner_and_collaborator: the owner\'s model read-only, or a warning for each viewer', async () => {
    view = V({ librarian: { use: 'agent', set: true, model: 'openai/gpt-4o-mini' } })
    draw()
    expect(await screen.findByTestId('tradecraft-librarian')).toHaveTextContent('Librarian model: openai/gpt-4o-mini')
    expect(screen.getByTestId('tradecraft-librarian').querySelector('input, select, button')).toBeNull()
    cleanup()
    view = V({ librarian: { use: 'agent', set: false, model: null } })
    draw()
    expect(await screen.findByTestId('tradecraft-librarian')).toHaveTextContent(LIBRARIAN_NOT_SET)
    cleanup()
    view = V({ viewerIsOwner: false, librarian: { use: 'agent', set: false, model: null } })
    draw()
    expect(await screen.findByTestId('tradecraft-librarian')).toHaveTextContent(OWNER_LIBRARIAN_NOT_SET)
    expect(OWNER_LIBRARIAN_NOT_SET).toBe("The owner hasn't chosen a librarian model")
  })

  test('a collaborator sees no model name; Search only and a set model warn nobody', async () => {
    view = V({ viewerIsOwner: false, librarian: { use: 'agent', set: true, model: null } })
    draw()
    await screen.findByTestId('tradecraft-accordion')
    expect(screen.queryByTestId('tradecraft-librarian')).toBeNull()
    expect(librarianWarning(V({ librarian: { use: 'search_only', set: false, model: null } }))).toBe('')
    expect(librarianWarning(V({}))).toBe('')
    expect(librarianWarning(null)).toBe('')
  })
})
