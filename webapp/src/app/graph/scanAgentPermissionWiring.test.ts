/**
 * How the graph page wires the permission gates of step 3.16b (E2E-P3-01, UI-12) around the
 * components that test them one by one: the scan confirm dialogs open only for someone the start
 * route would let through (a deep link `?autostart=true` or `?scan=gvm` opens them without a button),
 * the agent drawer is the gated one, "Ask agent" from a node seeds no message into a refused drawer,
 * and the toolbar's agent status poll does not ask a list it is refused.
 *
 * Source-level, like otherScansStartWiring.test.ts: rendering /graph needs providers, a router and
 * live scan data, none of which is what is being checked.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/scanAgentPermissionWiring.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const pageSrc = readFileSync(join(process.cwd(), 'src/app/graph/page.tsx'), 'utf8')

function element(tag: string): string {
  const start = pageSrc.indexOf(`<${tag}\n`)
  expect(start, `<${tag}> not found in page.tsx`).toBeGreaterThan(-1)
  return pageSrc.slice(start, pageSrc.indexOf('/>', start))
}

function handler(name: string): string {
  const start = pageSrc.indexOf(`const ${name} = useCallback(`)
  expect(start, `${name} not found in page.tsx`).toBeGreaterThan(-1)
  const next = pageSrc.indexOf('\n  const ', start + 1)
  return pageSrc.slice(start, next === -1 ? undefined : next)
}

describe('graph page: scan and agent permission wiring', () => {
  test('each refusal asks the permission its route asks (route manifest)', () => {
    expect(pageSrc).toMatch(/const reconRefused = usePermissionRefused\('recon:scan', projectId\)/)
    expect(pageSrc).toMatch(/const gvmRefused = usePermissionRefused\('scan:gvm', projectId\)/)
    expect(pageSrc).toMatch(/const agentRefused = usePermissionRefused\('agent:chat', projectId\)/)
  })

  test('the recon and GVM confirm dialogs never open for someone their start refuses', () => {
    expect(element('ReconConfirmModal')).toContain('isOpen={isReconModalOpen && !reconRefused}')
    expect(element('GvmConfirmModal')).toContain('isOpen={isGvmModalOpen && !gvmRefused}')
  })

  test('the page mounts the gated agent drawer, not the chat directly', () => {
    expect(pageSrc).toContain("import { AgentDrawer } from './components/AIAssistantDrawer'")
    expect(pageSrc).not.toContain('<AIAssistantDrawer')
    expect(element('AgentDrawer')).toContain('isOpen={isAIOpen}')
  })

  test('the toolbar\'s agent status poll asks nothing without agent:chat (the conversations list asks it)', () => {
    const fetchAt = pageSrc.indexOf('fetch(`/api/conversations?projectId=')
    expect(fetchAt, 'the conversations poll moved').toBeGreaterThan(-1)
    const effect = pageSrc.slice(pageSrc.lastIndexOf('useEffect(() => {', fetchAt), pageSrc.indexOf('}, [', fetchAt) + 60)
    const guard = effect.indexOf('if (agentRefused)')
    expect(guard, 'the poll no longer checks agentRefused').toBeGreaterThan(-1)
    expect(effect.slice(guard, effect.indexOf('return', guard))).toContain('conversations: []')
    expect(effect.indexOf('setInterval')).toBeGreaterThan(effect.indexOf('return', guard))
    expect(effect).toMatch(/\}, \[projectId, userId, agentRefused\]\)/)
  })

  test('"Ask agent" from a node opens a refused drawer with no fresh session and no seeded message', () => {
    const body = handler('handleStartAgentSession')
    const guard = body.indexOf('if (agentRefused)')
    expect(guard, 'handleStartAgentSession no longer checks agentRefused').toBeGreaterThan(-1)
    const refusedBranch = body.slice(guard, body.indexOf('return', guard))
    expect(refusedBranch).toContain('setIsAIOpen(true)')
    expect(refusedBranch).not.toContain('setPendingNodeQuery')
    expect(refusedBranch).not.toContain('resetSession')
    expect(body.indexOf('setPendingNodeQuery')).toBeGreaterThan(body.indexOf('return', guard))
    expect(body).toMatch(/\}, \[[^\]]*\bagentRefused\b[^\]]*\]\)/)
  })
})
