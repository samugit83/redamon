/**
 * stripStepContent (step 4.7, SH-30): a reader below R* gets each ChainStep's structure without its
 * content; the owner, a share with Raw data & files and break-glass get the nodes untouched; other
 * labels are never changed, and the input is never mutated (a cached graph serves the next reader).
 *
 * Step 4.9: the copies of step content on ChainFailure (error_message, lesson_learned) and
 * ChainDecision (reason) go with it; the export's and the MCP tools' `labels` shape is read like the
 * render shape's `type`; a node with nothing to strip keeps its identity, and the array too when no
 * node changed (graphReadView keeps the ETag then). The 4.9 review added an exploit_success
 * ChainFinding's console commands and cracked password, and an AttackChain's final outcome.
 *
 * RAW_DATA_GRAPH_PROPS and RAW_DATA_GRAPH_PROPS_BY_LABEL pin today's answer to OQ-R7 (option b: the
 * recon-found secret values stay visible at Read). OQ_R7_OPTION_A, run through withoutRawProps,
 * proves option (a) is setting them: the display-only keys on any node and, label-aware, a Secret
 * node's matched_text.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  OQ_R7_OPTION_A, RAW_DATA_GRAPH_PROPS, RAW_DATA_GRAPH_PROPS_BY_LABEL, STEP_CONTENT_BY_LABEL, STEP_CONTENT_PROPS,
  readsStepContent, stripStepContent, withoutRawProps,
} from './stepContent'
import { DISPLAY_ONLY_PROPS, SECRET_VALUE_PROPS, isSecretValueProp } from '@/lib/secrets/secretProps'
import type { ProjectAccess } from './projectAccess'

const access = (level: string, rawData: boolean, via = 'share') =>
  Object.freeze({ project: { id: 'P', userId: 'alice' }, level, toggles: Object.freeze({ rawData }), via }) as unknown as ProjectAccess

const step = () => ({
  id: '7', name: 'Step 2\nnmap', type: 'ChainStep',
  properties: {
    step_id: 's-1', chain_id: 'c-1', iteration: 2, phase: 'informational', tool_name: 'nmap', success: false, duration_ms: 12,
    agent_id: 'root', agent_name: 'root', user_id: 'alice', project_id: 'P',
    thought: 'scan the host', reasoning: 'ports first', output_summary: '22/tcp open', output_analysis: 'ssh exposed',
    tool_args_summary: 'nmap -p- --script-args creds=admin:hunter2 host', error_message: 'stderr: denied',
  },
})
const finding = () => ({ id: '8', name: 'Finding', type: 'ChainFinding', properties: { title: 'open ssh', severity: 'low', thought: 'kept: not a step' } })

describe('stripStepContent', () => {
  test('a read share without Raw data: ChainStep keeps its structure, loses every content property', () => {
    const nodes = [step(), finding()]
    const out = stripStepContent(nodes, access('read', false))
    for (const key of STEP_CONTENT_PROPS) expect(out[0].properties).not.toHaveProperty(key)
    expect(out[0].properties).toEqual({
      step_id: 's-1', chain_id: 'c-1', iteration: 2, phase: 'informational', tool_name: 'nmap', success: false, duration_ms: 12,
      agent_id: 'root', agent_name: 'root', user_id: 'alice', project_id: 'P',
    })
    expect(out[0]).toMatchObject({ id: '7', name: 'Step 2\nnmap', type: 'ChainStep' })
    expect(out[1]).toEqual(finding())
  })

  test('the content list is the four the agent writes plus the command line and the error', () => {
    expect([...STEP_CONTENT_PROPS].sort()).toEqual(['error_message', 'output_analysis', 'output_summary', 'reasoning', 'thought', 'tool_args_summary'])
  })

  test('the input is never mutated', () => {
    const nodes = [step()]
    stripStepContent(nodes, access('read', false))
    expect(nodes[0]).toEqual(step())
  })

  test.each([
    ['the owner', access('owner', true, 'owner')],
    ['a share with Raw data & files', access('read', true)],
    ['break-glass', access('read', true, 'break_glass')],
  ])('%s: the same array, untouched', (_who, a) => {
    const nodes = [step(), finding()]
    expect(stripStepContent(nodes, a)).toBe(nodes)
    expect(readsStepContent(a)).toBe(true)
  })

  test.each([
    ['oversight', access('read', false, 'oversight')],
    ['no decided access', null],
    ['an unknown kind of access', access('reader', true)],
  ])('%s: stripped (fails closed)', (_who, a) => {
    const out = stripStepContent([step()], a)
    expect(out[0].properties).not.toHaveProperty('thought')
    expect(readsStepContent(a)).toBe(false)
  })
})

const failure = () => ({
  id: '9', name: 'Step 2\ntool_error', type: 'ChainFailure',
  properties: {
    failure_id: 'f-1', chain_id: 'c-1', failure_type: 'tool_error', tool_name: 'nmap', error_category: 'permission', iteration: 2,
    retry_possible: true, phase: 'informational', error_message: 'stderr: denied', lesson_learned: 'ssh exposed, retry as root',
  },
})
const decision = () => ({
  id: '10', name: 'Step 3\nphase_transition', type: 'ChainDecision',
  properties: {
    decision_id: 'd-1', chain_id: 'c-1', decision_type: 'phase_transition', from_state: 'informational', to_state: 'exploitation',
    made_by: 'user', approved: true, iteration: 3, reason: 'creds found in the banner: admin/hunter2',
  },
})
const secret = () => ({
  id: '11', name: 'key', type: 'Secret',
  properties: {
    secret_value: 'rbac-fake-secret-value', paired_secret: 'rbac-fake-pair', raw_context: 'k=rbac-fake', sample: 'rbac…', value_length: 22,
    matched_text: 'api_key = "rbac-fake-secret-value"',
  },
})

describe('stripStepContent: the copies of step content on the other chain nodes (step 4.9)', () => {
  test('a failed step\'s ChainFailure loses the error and the lesson (the step\'s output analysis), keeps its type and tool', () => {
    const [out] = stripStepContent([failure()], access('read', false))
    expect(out.properties).toEqual({
      failure_id: 'f-1', chain_id: 'c-1', failure_type: 'tool_error', tool_name: 'nmap', error_category: 'permission', iteration: 2,
      retry_possible: true, phase: 'informational',
    })
  })

  test('a ChainDecision loses the agent\'s reason, keeps the transition and who decided', () => {
    const [out] = stripStepContent([decision()], access('read', false, 'oversight'))
    expect(out.properties).toEqual({
      decision_id: 'd-1', chain_id: 'c-1', decision_type: 'phase_transition', from_state: 'informational', to_state: 'exploitation',
      made_by: 'user', approved: true, iteration: 3,
    })
  })

  test('the content map names the five chain labels and only the content each carries', () => {
    expect(Object.keys(STEP_CONTENT_BY_LABEL).sort()).toEqual(['AttackChain', 'ChainDecision', 'ChainFailure', 'ChainFinding', 'ChainStep'])
    expect(STEP_CONTENT_BY_LABEL.ChainStep).toBe(STEP_CONTENT_PROPS)
    expect([...STEP_CONTENT_BY_LABEL.ChainFailure].sort()).toEqual(['error_message', 'lesson_learned'])
    expect([...STEP_CONTENT_BY_LABEL.ChainDecision]).toEqual(['reason'])
    expect([...STEP_CONTENT_BY_LABEL.ChainFinding].sort()).toEqual(['commands_used', 'password'])
    expect([...STEP_CONTENT_BY_LABEL.AttackChain]).toEqual(['final_outcome'])
  })

  test('an exploit_success ChainFinding loses the console commands and the cracked password, keeps the finding (4.9 review)', () => {
    const exploit = {
      id: '12', name: 'Exploit success', type: 'ChainFinding',
      properties: {
        finding_id: 'cf-1', finding_type: 'exploit_success', severity: 'critical', title: 'Exploit success: cve_exploit on 10.0.0.5',
        evidence: 'session 1 opened', metasploit_module: 'exploit/unix/ftp/vsftpd_234_backdoor', payload: 'cmd/unix/interact',
        target_ip: '10.0.0.5', session_id: 1, username: 'admin',
        commands_used: ['use exploit/x', 'set PASSWORD rbac-fake-pass', 'run'], password: 'rbac-fake-pass',
      },
    }
    const [out] = stripStepContent([exploit], access('read', false))
    expect(out.properties).not.toHaveProperty('commands_used')
    expect(out.properties).not.toHaveProperty('password')
    expect(out.properties).toMatchObject({ finding_type: 'exploit_success', title: exploit.properties.title, evidence: 'session 1 opened', username: 'admin', session_id: 1 })
    expect(JSON.stringify(out)).not.toContain('rbac-fake-pass')
    expect(stripStepContent([exploit], access('read', true))[0]).toBe(exploit)
  })

  test('an AttackChain loses its final outcome (the model\'s completion reason), keeps title, objective and status (4.9 review)', () => {
    const chain = {
      id: '13', name: 'Chain', type: 'AttackChain',
      properties: { chain_id: 'c-1', title: 'rbac chain', objective: 'reach the admin panel', status: 'completed', final_outcome: 'logged in as admin with hunter2' },
    }
    const [out] = stripStepContent([chain], access('read', false, 'oversight'))
    expect(out.properties).toEqual({ chain_id: 'c-1', title: 'rbac chain', objective: 'reach the admin panel', status: 'completed' })
  })

  test('the export\'s and the MCP tools\' shape (labels, no type) is stripped like the render shape', () => {
    const exported = { labels: ['ChainStep'], properties: step().properties, _exportId: 'e-7' }
    const mcp = { _kind: 'node', nodeId: 7, labels: ['ChainFailure'], properties: failure().properties }
    const [e, m] = stripStepContent([exported, mcp], access('read', false))
    for (const key of STEP_CONTENT_PROPS) expect(e.properties).not.toHaveProperty(key)
    expect(e).toMatchObject({ labels: ['ChainStep'], _exportId: 'e-7', properties: { tool_name: 'nmap', iteration: 2 } })
    expect(m.properties).not.toHaveProperty('error_message')
    expect(m.properties).not.toHaveProperty('lesson_learned')
    expect(m).toMatchObject({ _kind: 'node', nodeId: 7 })
  })

  test('a label that only looks like a chain label, or a prototype key, strips nothing', () => {
    const nodes = [
      { type: 'chainstep', properties: { thought: 'kept' } },
      { type: 'constructor', properties: { reason: 'kept' } },
      { labels: ['toString'], properties: { reason: 'kept' } },
    ]
    expect(stripStepContent(nodes, access('read', false))).toBe(nodes)
  })

  test('below R*: a node with nothing to strip keeps its identity; no node to strip answers the same array', () => {
    const plain = [finding(), secret()]
    expect(stripStepContent(plain, access('read', false))).toBe(plain)
    const mixed = [step(), finding()]
    const out = stripStepContent(mixed, access('read', false))
    expect(out).not.toBe(mixed)
    expect(out[1]).toBe(mixed[1])
  })

  test('a node without properties (a malformed row) passes through untouched', () => {
    const odd = [{ type: 'ChainStep' }, null] as unknown as Array<{ type: string; properties: Record<string, unknown> }>
    expect(stripStepContent(odd, access('read', false))).toBe(odd)
  })
})

describe('OQ-R7: the recon-found secret values (open with the owner; built as written, option b)', () => {
  test('today no node property beyond step content is raw data: RAW_DATA_GRAPH_PROPS and its per-label map name none', () => {
    expect(RAW_DATA_GRAPH_PROPS).toEqual([])
    expect(RAW_DATA_GRAPH_PROPS_BY_LABEL).toEqual({})
    expect(Object.isFrozen(RAW_DATA_GRAPH_PROPS)).toBe(true)
    expect(Object.isFrozen(RAW_DATA_GRAPH_PROPS_BY_LABEL)).toBe(true)
  })

  test('so a reader without Raw data still reads a Secret node\'s display-only values and its full match (option b)', () => {
    const nodes = [secret()]
    expect(stripStepContent(nodes, access('read', false))).toBe(nodes)
    const [out] = stripStepContent(nodes, access('read', false, 'oversight'))
    expect(out.properties.secret_value).toBe('rbac-fake-secret-value')
    expect(out.properties.matched_text).toBe('api_key = "rbac-fake-secret-value"')
  })

  test('option (a) is OQ_R7_OPTION_A in the two constants: every display-only key on any node and a Secret\'s matched_text go, the masked fields stay', () => {
    expect(OQ_R7_OPTION_A).toEqual({ anyNode: [...DISPLAY_ONLY_PROPS], byLabel: { Secret: ['matched_text'] } })
    const [out, chain] = withoutRawProps([secret(), step()], OQ_R7_OPTION_A)
    expect(out.properties).toEqual({ sample: 'rbac…', value_length: 22 })
    for (const key of STEP_CONTENT_PROPS) expect(chain.properties).not.toHaveProperty(key)
    const unmasked = { type: 'Endpoint', properties: { masked_url: 'https://app.rbac.test/?k=***', unmasked_url: 'https://app.rbac.test/?k=rbac-fake' } }
    expect(withoutRawProps([unmasked], OQ_R7_OPTION_A)[0].properties).toEqual({ masked_url: 'https://app.rbac.test/?k=***' })
  })

  test('option (a) takes matched_text off a Secret only: on another label it is evidence text and stays (label shape too)', () => {
    const vuln = { type: 'Vulnerability', properties: { name: 'xss', matched_text: '<script>alert(1)</script>' } }
    const exported = { labels: ['Secret'], properties: { secret_type: 'aws', matched_text: 'AKIA-rbac-fake' }, _exportId: 'e-9' }
    const nodes = [vuln, exported]
    const [v, e] = withoutRawProps(nodes, OQ_R7_OPTION_A)
    expect(v).toBe(vuln)
    expect(e.properties).toEqual({ secret_type: 'aws' })
  })

  test('option (a) names every property isSecretValueProp calls a secret value, for the label it calls one on', () => {
    for (const key of SECRET_VALUE_PROPS) expect(OQ_R7_OPTION_A.anyNode).toContain(key)
    for (const [label, keys] of Object.entries(OQ_R7_OPTION_A.byLabel)) {
      for (const key of keys) expect(isSecretValueProp(key, label)).toBe(true)
    }
    expect(isSecretValueProp('matched_text', 'Secret')).toBe(true)
    expect(OQ_R7_OPTION_A.byLabel.Secret).toContain('matched_text')
  })
})
