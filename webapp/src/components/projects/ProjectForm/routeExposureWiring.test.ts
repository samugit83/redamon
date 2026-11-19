/**
 * Wiring of RouteExposure in the project form and workflow graph: group 6 with
 * the Active badge, input/output/enrich maps on existing node types only, the
 * partial-recon tool id, the graph-inputs query and the input-logic tooltip.
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'
import { SECTION_INPUT_MAP, SECTION_NODE_MAP, SECTION_ENRICH_MAP } from './nodeMapping'
import { WORKFLOW_TOOLS } from './WorkflowView/workflowDefinition'
import { INPUT_LOGIC_TOOLTIPS } from './WorkflowView/inputLogicTooltips'
import { PARTIAL_RECON_SUPPORTED_TOOLS } from '@/lib/recon-types'

const SRC = join(__dirname, '../../..')

describe('RouteExposure wiring', () => {
  const tool = WORKFLOW_TOOLS.find(t => t.id === 'RouteExposure')

  test('sits in group 6 with the Active badge and its Prisma field', () => {
    expect(tool).toMatchObject({ label: 'Route Exposure', enabledField: 'routeExposureEnabled',
                                 group: 6, badge: 'active' })
  })

  test('reads BaseURL and Endpoint, writes Vulnerability and Endpoint, enriches Endpoint', () => {
    expect(SECTION_INPUT_MAP.RouteExposure).toEqual(['BaseURL', 'Endpoint', 'Technology'])
    expect(SECTION_NODE_MAP.RouteExposure).toEqual(['Vulnerability', 'Endpoint'])
    expect(SECTION_ENRICH_MAP.RouteExposure).toEqual(['Endpoint'])
  })

  test('partial recon is supported and the graph-inputs route counts its inputs', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('RouteExposure')).toBe(true)
    const route = readFileSync(join(SRC, 'app/api/recon/[projectId]/graph-inputs/[toolId]/route.ts'), 'utf8')
    expect(route).toMatch(/RouteExposure: JS_TOOL,/)
  })

  test('the input-logic tooltip exists and names the graph nodes', () => {
    expect(INPUT_LOGIC_TOOLTIPS.RouteExposure).toBeDefined()
    const modal = readFileSync(join(__dirname, 'WorkflowView/inputLogicTooltips.tsx'), 'utf8')
    const block = modal.slice(modal.indexOf('const RouteExposure = ('), modal.indexOf('const JsRecon = ('))
    for (const name of ['BaseURL', 'Endpoint', 'Vulnerability', 'HAS_VULNERABILITY', 'HAS_ENDPOINT', 'anon_status']) {
      expect(block).toContain(name)
    }
    expect(block).not.toContain('—')
  })

  test('the node modal and the form both mount the section', () => {
    const nodeModal = readFileSync(join(__dirname, 'WorkflowView/WorkflowNodeModal.tsx'), 'utf8')
    expect(nodeModal).toContain("case 'RouteExposure':     return <RouteExposureSection {...baseProps} />")
    const form = readFileSync(join(__dirname, 'ProjectForm.tsx'), 'utf8')
    expect(form).toContain("setPartialReconToolId('RouteExposure')")
  })

  test('the partial modal disables Run with graph targets off and no URL', () => {
    const modal = readFileSync(join(__dirname, 'WorkflowView/PartialReconModal.tsx'), 'utf8')
    expect(modal).toContain("const routeExposureNoUrls = isRouteExposure && !includeGraphTargets && !customUrls.trim()")
    const runDisabled = modal.match(/const runDisabled = [^\n]*/)
    expect(runDisabled?.[0]).toContain('routeExposureNoUrls')
    expect(modal).toContain('disabled={runDisabled}')
  })
})
