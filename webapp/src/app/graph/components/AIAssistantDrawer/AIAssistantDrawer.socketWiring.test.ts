/**
 * Wiring guard for the agent socket in the drawer (source inspection: the
 * drawer needs a whole page of providers to render, and the behaviour behind
 * each line is unit-tested in useAgentWebSocket.test.tsx and
 * useConversationRestoration.test.tsx).
 *
 * In the "agent stuck" incident, closing the drawer to look at the graph closed
 * the socket mid-run and every event of the run until it reopened was lost.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/AIAssistantDrawer.socketWiring.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const src = readFileSync(join(__dirname, 'AIAssistantDrawer.tsx'), 'utf8')
const socketCall = src.slice(src.indexOf('useAgentWebSocket({'), src.indexOf('// ─── Send handlers'))

describe('AIAssistantDrawer agent socket wiring', () => {
  test('a run keeps the socket open even with the drawer closed', () => {
    expect(socketCall).toMatch(/enabled:\s*isOpen \|\| isLoading,/)
  })

  test('graph-view reconnects wait for the run to end', () => {
    expect(socketCall).toMatch(/runActive:\s*isLoading,/)
  })

  test('a provider rate-limit wait reaches the chat, and ends with the run', () => {
    const handlerCall = src.slice(src.indexOf('useWebSocketHandler({'), src.indexOf('useAgentWebSocket({'))
    const chatArea = src.slice(src.indexOf('<ChatArea'), src.indexOf('/>', src.indexOf('<ChatArea')))
    expect(src).toContain('useRateLimitWait(isLoading, sessionId)')
    expect(handlerCall).toMatch(/\bsetRateLimitWait,/)
    expect(chatArea).toContain('rateLimitWord={rateLimitWord}')
  })

  test('every (re)connect reconciles with the server-reported run state', () => {
    expect(socketCall).toContain('agentRunning: payload?.agent_running')
    expect(socketCall).toContain('clientRunning: isLoadingRef.current')
    // Read when the resync's DB read returns, so events that arrived meanwhile win.
    expect(socketCall).toContain('isRunActive: () => isLoadingRef.current')
  })
})
