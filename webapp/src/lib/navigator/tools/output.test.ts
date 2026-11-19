/**
 * What a tool result may carry to the model (plan §7.10, §10.2 rows 8 and 27): chain-step content
 * stripped below Raw data & files, owner-only and credential fields never returned, secret shapes
 * masked unless the RoE allows full access, and the size caps.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {}, prisma: {} }))

import { shapeToolResult } from './output'
import { SHARE_SECRET_FIELDS } from '@/lib/authz/projectReadView'
import { STEP_CONTENT_PROPS } from '@/lib/authz/stepContent'
import type { ProjectAccess } from '@/lib/authz/projectAccess'
import { ROWS_MAX, TOOL_RESULT_MAX_BYTES } from '../constants'

const readShare: ProjectAccess = { project: { id: 'P1', userId: 'owner' }, level: 'read', toggles: { rawData: false }, via: 'share' }
const rawShare: ProjectAccess = { ...readShare, toggles: { rawData: true } }
const owner: ProjectAccess = { project: { id: 'P1', userId: 'owner' }, level: 'owner', toggles: { rawData: true }, via: 'owner' }

const AWS = 'AKIAIOSFODNN7EXAMPLE'

describe('shapeToolResult', () => {
  test('a ChainStep loses its step content for a Read share without Raw data, keeps it with', () => {
    const step = { labels: ['ChainStep'], properties: Object.fromEntries(STEP_CONTENT_PROPS.map((p) => [p, 'secret thought'])) }
    const read = shapeToolResult({ records: [{ n: step }] }, { access: readShare, mask: false }).result as { records: Array<{ n: { properties: Record<string, unknown> } }> }
    for (const p of STEP_CONTENT_PROPS) expect(read.records[0].n.properties[p]).toBeUndefined()
    const raw = shapeToolResult({ records: [{ n: step }] }, { access: rawShare, mask: false }).result as typeof read
    expect(raw.records[0].n.properties[STEP_CONTENT_PROPS[0]]).toBe('secret thought')
  })

  test('owner-only and credential fields never come back, even to the owner', () => {
    const row: Record<string, unknown> = { name: 'p', password: 'x', tokenHash: 'y' }
    for (const f of SHARE_SECRET_FIELDS) row[f] = `value-of-${f}`
    const out = JSON.stringify(shapeToolResult({ project: row }, { access: owner, mask: false }).result)
    for (const f of [...SHARE_SECRET_FIELDS, 'password', 'tokenHash']) expect(out).not.toContain(`"${f}"`)
    expect(out).toContain('"name"')
  })

  test('secret shapes are masked unless the RoE allows full access', () => {
    const masked = JSON.stringify(shapeToolResult({ content: `key=${AWS}` }, { access: owner, mask: true }).result)
    expect(masked).not.toContain(AWS)
    const full = JSON.stringify(shapeToolResult({ content: `key=${AWS}` }, { access: owner, mask: false }).result)
    expect(full).toContain(AWS)
  })

  test('rows and bytes are capped with truncated and a hint', () => {
    const rows = shapeToolResult({ rows: Array.from({ length: ROWS_MAX + 50 }, (_, i) => i) }, { access: owner, mask: false })
    expect(rows.truncated).toBe(true)
    expect((rows.result as { rows: number[]; hint: string }).rows).toHaveLength(ROWS_MAX)
    const big = shapeToolResult({ rows: Array.from({ length: 150 }, () => 'x'.repeat(1000)) }, { access: owner, mask: false })
    expect(JSON.stringify(big.result).length).toBeLessThanOrEqual(TOOL_RESULT_MAX_BYTES + 200)
    expect(big.truncated).toBe(true)
  })
})
