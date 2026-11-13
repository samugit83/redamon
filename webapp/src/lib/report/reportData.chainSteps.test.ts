/** @vitest-environment node */
/**
 * The report's attack-chain summary counts only its own project's steps. A ChainStep was once
 * matched to its chain by `chain_id` alone, and a chain id (the agent session id) was not unique
 * across tenants before step 5.3's fix: a step another project wrote under the same id counted in
 * this report. The join now names the chain id, the chain's tenant and the report's project.
 *
 * Run: npx vitest run src/lib/report/reportData.chainSteps.test.ts
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { queryAttackChains } from './reportData'

describe('queryAttackChains in the report', () => {
  test('a chain step joins on the chain id, the tenant and the project', async () => {
    const calls: Array<[string, Record<string, unknown>]> = []
    const session = { run: vi.fn(async (cypher: string, params: Record<string, unknown>) => {
      calls.push([cypher, params])
      return { records: [] }
    }) }
    await queryAttackChains(session, 'p1')
    const [chains, params] = calls.find(([c]) => c.includes('MATCH (ac:AttackChain'))!
    expect(chains).toContain('OPTIONAL MATCH (step:ChainStep {chain_id: ac.chain_id, user_id: ac.user_id, project_id: $pid})')
    expect(chains).not.toMatch(/ChainStep \{chain_id: ac\.chain_id\}/)
    expect(params).toEqual({ pid: 'p1' })
  })
})
