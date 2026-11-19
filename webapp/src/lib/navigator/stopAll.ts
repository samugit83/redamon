/**
 * Every AI Navigator run ends: Root turned the switch off, or a global emergency stop. The registry
 * aborts each stream (the agent sees the disconnect) and the agent is also told to cancel them all,
 * best effort. Answers how many registry runs were aborted. Never throws.
 */
import { agentFetch } from '@/lib/agentFetch'
import { navigatorRuns } from './runRegistry'

export function stopAllNavigatorRuns(): number {
  const n = navigatorRuns().abortAll()
  void agentFetch('/navigator/stop-all', { method: 'POST' }, { timeoutMs: 5000 })
    .catch(() => console.warn('[navigator] stop-all not delivered'))
  return n
}
