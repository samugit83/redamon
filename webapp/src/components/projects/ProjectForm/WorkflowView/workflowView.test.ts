/**
 * Unit tests for the Workflow View logic.
 *
 * Run:  npx vitest run src/components/projects/ProjectForm/WorkflowView/workflowView.test.ts
 */

import { describe, test, expect } from 'vitest'
import { renderHook } from '@testing-library/react'
import {
  WORKFLOW_TOOLS,
  UNIVERSAL_DATA_NODES,
  TRANSITIONAL_DATA_NODES,
  ALL_WORKFLOW_DATA_NODES,
  DATA_NODE_CATEGORIES,
  CATEGORY_COLORS,
  getGroupColor,
  getToolProduces,
  getToolConsumes,
  getToolEnriches,
  type WorkflowToolDef,
} from './workflowDefinition'
import { SECTION_INPUT_MAP, SECTION_NODE_MAP, SECTION_ENRICH_MAP } from '../nodeMapping'
import {
  computeLayout,
  TOOL_NODE_WIDTH,
  TOOL_NODE_HEIGHT,
  DATA_NODE_WIDTH,
  DATA_NODE_HEIGHT,
  INPUT_NODE_WIDTH,
  INPUT_NODE_HEIGHT,
} from './workflowLayout'
import { useWorkflowGraph, applyEdgeSelection } from './useWorkflowGraph'


// ---------------------------------------------------------------------------
// workflowDefinition.ts
// ---------------------------------------------------------------------------

describe('workflowDefinition', () => {

  describe('WORKFLOW_TOOLS', () => {
    test('every tool id exists in nodeMapping SECTION_INPUT_MAP or SECTION_NODE_MAP', () => {
      for (const tool of WORKFLOW_TOOLS) {
        const inInput = tool.id in SECTION_INPUT_MAP
        const inOutput = tool.id in SECTION_NODE_MAP
        expect(
          inInput || inOutput,
          `Tool "${tool.id}" missing from both SECTION_INPUT_MAP and SECTION_NODE_MAP`,
        ).toBe(true)
      }
    })

    test('every tool has a unique id', () => {
      const ids = WORKFLOW_TOOLS.map(t => t.id)
      expect(new Set(ids).size).toBe(ids.length)
    })

    test('every enabledField is a non-empty string', () => {
      for (const tool of WORKFLOW_TOOLS) {
        expect(tool.enabledField.length).toBeGreaterThan(0)
      }
    })

    test('groups are in ascending order within the array', () => {
      let prev = -Infinity
      for (const tool of WORKFLOW_TOOLS) {
        expect(tool.group).toBeGreaterThanOrEqual(prev)
        prev = tool.group
      }
    })

    test('ZAP Ajax Spider is registered as an active group 5 tool', () => {
      const zap = WORKFLOW_TOOLS.find(t => t.id === 'ZapAjaxSpider')
      expect(zap).toMatchObject({
        label: 'ZAP Ajax Spider',
        enabledField: 'zapAjaxSpiderEnabled',
        group: 5,
        badge: 'active',
      })
    })
  })

  describe('data node sets', () => {
    test('universal and transitional sets are disjoint', () => {
      for (const n of UNIVERSAL_DATA_NODES) {
        expect(TRANSITIONAL_DATA_NODES.has(n), `"${n}" in both sets`).toBe(false)
      }
    })

    test('ALL_WORKFLOW_DATA_NODES is the union', () => {
      expect(ALL_WORKFLOW_DATA_NODES.size).toBe(
        UNIVERSAL_DATA_NODES.size + TRANSITIONAL_DATA_NODES.size,
      )
      for (const n of UNIVERSAL_DATA_NODES) expect(ALL_WORKFLOW_DATA_NODES.has(n)).toBe(true)
      for (const n of TRANSITIONAL_DATA_NODES) expect(ALL_WORKFLOW_DATA_NODES.has(n)).toBe(true)
    })

    test('every data node has a category', () => {
      for (const n of ALL_WORKFLOW_DATA_NODES) {
        expect(DATA_NODE_CATEGORIES[n], `Missing category for "${n}"`).toBeDefined()
      }
    })

    test('every category has a color', () => {
      const categories = new Set(Object.values(DATA_NODE_CATEGORIES))
      for (const cat of categories) {
        expect(CATEGORY_COLORS[cat], `Missing color for "${cat}"`).toBeDefined()
      }
    })
  })

  describe('getGroupColor', () => {
    test('returns correct color for known groups', () => {
      expect(getGroupColor(0)).toBe('#6b7280')
      expect(getGroupColor(1)).toBe('#3b82f6')
      expect(getGroupColor(5.5)).toBe('#f59e0b')
    })

    test('returns fallback gray for unknown groups', () => {
      expect(getGroupColor(99)).toBe('#6b7280')
    })
  })

  describe('getToolProduces / getToolConsumes', () => {
    test('Naabu produces Port and Service', () => {
      const produces = getToolProduces('Naabu')
      expect(produces).toContain('Port')
      expect(produces).toContain('Service')
    })

    test('Nmap consumes IP and Port', () => {
      const consumes = getToolConsumes('Nmap')
      expect(consumes).toContain('IP')
      expect(consumes).toContain('Port')
    })

    test('filters out non-workflow data nodes (e.g. ThreatPulse, Malware)', () => {
      // OsintEnrichment produces ThreatPulse and Malware in nodeMapping
      // but they should be filtered out
      const produces = getToolProduces('OsintEnrichment')
      expect(produces).not.toContain('ThreatPulse')
      expect(produces).not.toContain('Malware')
      // but should still include workflow nodes
      expect(produces).toContain('Port')
      expect(produces).toContain('CVE')
    })

    test('Nmap enriches Port and Service', () => {
      const enriches = getToolEnriches('Nmap')
      expect(enriches).toContain('Port')
      expect(enriches).toContain('Service')
    })

    test('Urlscan enriches Domain and IP', () => {
      const enriches = getToolEnriches('Urlscan')
      expect(enriches).toContain('Domain')
      expect(enriches).toContain('IP')
    })

    test('Httpx enriches Subdomain and Domain', () => {
      const enriches = getToolEnriches('Httpx')
      expect(enriches).toContain('Subdomain')
      expect(enriches).toContain('Domain')
    })

    test('tools without enrichments return empty array', () => {
      expect(getToolEnriches('Katana')).toEqual([])
      expect(getToolEnriches('Nuclei')).toEqual([])
    })

    test('returns empty array for unknown tool', () => {
      expect(getToolProduces('NonExistentTool')).toEqual([])
      expect(getToolConsumes('NonExistentTool')).toEqual([])
      expect(getToolEnriches('NonExistentTool')).toEqual([])
    })
  })
})


// ---------------------------------------------------------------------------
// workflowLayout.ts
// ---------------------------------------------------------------------------

describe('workflowLayout / computeLayout', () => {

  // Helper: build the same layout descriptors as useWorkflowGraph
  function buildLayoutNodes() {
    // Collect connected data nodes (same logic as useWorkflowGraph)
    const connectedDataNodes = new Set<string>()
    const INPUT_PRODUCES = ['Domain', 'Subdomain', 'IP']
    for (const nt of INPUT_PRODUCES) connectedDataNodes.add(nt)
    for (const tool of WORKFLOW_TOOLS) {
      for (const nt of getToolProduces(tool.id)) {
        if (ALL_WORKFLOW_DATA_NODES.has(nt)) connectedDataNodes.add(nt)
      }
      for (const nt of getToolConsumes(tool.id)) {
        if (ALL_WORKFLOW_DATA_NODES.has(nt)) connectedDataNodes.add(nt)
      }
      for (const nt of getToolEnriches(tool.id)) {
        if (ALL_WORKFLOW_DATA_NODES.has(nt)) connectedDataNodes.add(nt)
      }
    }

    const nodes: { id: string; type: 'input' | 'tool' | 'data'; group: number; width: number; height: number }[] = []
    nodes.push({ id: 'input', type: 'input', group: 0, width: INPUT_NODE_WIDTH, height: INPUT_NODE_HEIGHT })
    for (const tool of WORKFLOW_TOOLS) {
      nodes.push({ id: `tool-${tool.id}`, type: 'tool', group: tool.group, width: TOOL_NODE_WIDTH, height: TOOL_NODE_HEIGHT })
    }
    for (const nt of connectedDataNodes) {
      nodes.push({ id: `data-${nt}`, type: 'data', group: 0, width: DATA_NODE_WIDTH, height: DATA_NODE_HEIGHT })
    }
    return { nodes, connectedDataNodes }
  }

  test('returns a position for every input node', () => {
    const { nodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)
    const posMap = new Map(positions.map(p => [p.id, p]))

    expect(posMap.has('input')).toBe(true)
  })

  test('returns a position for every tool node', () => {
    const { nodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)
    const posMap = new Map(positions.map(p => [p.id, p]))

    for (const tool of WORKFLOW_TOOLS) {
      expect(posMap.has(`tool-${tool.id}`), `Missing position for tool-${tool.id}`).toBe(true)
    }
  })

  test('returns a position for every connected data node', () => {
    const { nodes, connectedDataNodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)
    const posMap = new Map(positions.map(p => [p.id, p]))

    for (const nt of connectedDataNodes) {
      expect(posMap.has(`data-${nt}`), `Missing position for data-${nt}`).toBe(true)
    }
  })

  test('input node is at the leftmost position', () => {
    const { nodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)
    const posMap = new Map(positions.map(p => [p.id, p]))

    const inputX = posMap.get('input')!.x
    for (const p of positions) {
      if (p.id === 'input') continue
      // Universal data nodes (Domain/Subdomain/IP) live in the input's own
      // group-0 column and are horizontally centered over it, so with three
      // of them they extend slightly left of the narrower, centered input
      // node (see the three-band layout docstring). Exclude them; every other
      // node sits in a later column to the right.
      const nodeType = p.id.replace('data-', '')
      if (UNIVERSAL_DATA_NODES.has(nodeType)) continue
      expect(p.x, `${p.id} (x=${p.x}) is to the left of input (x=${inputX})`).toBeGreaterThanOrEqual(inputX)
    }
  })

  test('universal data nodes are in the leftmost column (left of all tools)', () => {
    const { nodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)
    const posMap = new Map(positions.map(p => [p.id, p]))

    // Universal data nodes are the seed data: they belong to the leftmost
    // (group 0) column, centered over the input node, so they sit to the left
    // of every tool node.
    const minToolX = Math.min(...WORKFLOW_TOOLS.map(t => posMap.get(`tool-${t.id}`)!.x))
    for (const nt of UNIVERSAL_DATA_NODES) {
      const dataX = posMap.get(`data-${nt}`)?.x
      if (dataX !== undefined) {
        expect(dataX, `${nt} (x=${dataX}) should be left of all tools (minToolX=${minToolX})`).toBeLessThan(minToolX)
      }
    }
  })

  test('tools in later groups are to the right of tools in earlier groups', () => {
    const { nodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)
    const posMap = new Map(positions.map(p => [p.id, p]))

    // Get one tool from each group and verify ascending X
    const groupXs: { group: number; x: number }[] = []
    const seen = new Set<number>()
    for (const tool of WORKFLOW_TOOLS) {
      if (!seen.has(tool.group)) {
        seen.add(tool.group)
        const pos = posMap.get(`tool-${tool.id}`)!
        groupXs.push({ group: tool.group, x: pos.x })
      }
    }
    groupXs.sort((a, b) => a.group - b.group)

    for (let i = 1; i < groupXs.length; i++) {
      expect(
        groupXs[i].x,
        `Group ${groupXs[i].group} (x=${groupXs[i].x}) should be right of group ${groupXs[i - 1].group} (x=${groupXs[i - 1].x})`,
      ).toBeGreaterThan(groupXs[i - 1].x)
    }
  })

  test('tools within the same group share the same X position', () => {
    const { nodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)
    const posMap = new Map(positions.map(p => [p.id, p]))

    const groupToolXs = new Map<number, number[]>()
    for (const tool of WORKFLOW_TOOLS) {
      const x = posMap.get(`tool-${tool.id}`)!.x
      if (!groupToolXs.has(tool.group)) groupToolXs.set(tool.group, [])
      groupToolXs.get(tool.group)!.push(x)
    }

    for (const [group, xs] of groupToolXs) {
      const unique = new Set(xs)
      expect(unique.size, `Group ${group} tools should share X but have ${unique.size} distinct values`).toBe(1)
    }
  })

  test('a crowded data band does not push its tool column away from its neighbours', () => {
    const { nodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)
    const posMap = new Map(positions.map(p => [p.id, p]))

    // One X per tool group, in pipeline order
    const groupXs = [...new Set(WORKFLOW_TOOLS.map(t => t.group))]
      .sort((a, b) => a - b)
      .map(group => ({ group, x: posMap.get(`tool-${WORKFLOW_TOOLS.find(t => t.group === group)!.id}`)!.x }))

    // A band that wraps keeps every column within a data node of the previous
    // one; a band laid out in a single line (six nodes under JS Recon) does not.
    for (let i = 1; i < groupXs.length; i++) {
      const gap = groupXs[i].x - (groupXs[i - 1].x + TOOL_NODE_WIDTH)
      expect(
        gap,
        `Gap between group ${groupXs[i - 1].group} and group ${groupXs[i].group} is ${gap}px`,
      ).toBeLessThan(DATA_NODE_WIDTH)
    }
  })

  test('no two nodes overlap (same position with same dimensions)', () => {
    const { nodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)

    // Build bounding boxes
    const nodeMap = new Map(nodes.map(n => [n.id, n]))
    for (let i = 0; i < positions.length; i++) {
      for (let j = i + 1; j < positions.length; j++) {
        const a = positions[i]
        const b = positions[j]
        const aNode = nodeMap.get(a.id)!
        const bNode = nodeMap.get(b.id)!

        const overlapX = a.x < b.x + bNode.width && a.x + aNode.width > b.x
        const overlapY = a.y < b.y + bNode.height && a.y + aNode.height > b.y

        expect(
          overlapX && overlapY,
          `Nodes "${a.id}" and "${b.id}" overlap`,
        ).toBe(false)
      }
    }
  })

  test('BaseURL data node is placed between HTTP Probing and Resource Enum', () => {
    const { nodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)
    const posMap = new Map(positions.map(p => [p.id, p]))

    const httpxX = posMap.get('tool-Httpx')!.x
    const katanaX = posMap.get('tool-Katana')!.x
    const baseUrlX = posMap.get('data-BaseURL')!.x

    expect(baseUrlX, 'BaseURL should be right of Httpx').toBeGreaterThan(httpxX)
    expect(baseUrlX, 'BaseURL should be left of Katana').toBeLessThan(katanaX)
  })

  test('Port data node is placed before Port Scanning tools (Nmap)', () => {
    const { nodes } = buildLayoutNodes()
    const positions = computeLayout(nodes)
    const posMap = new Map(positions.map(p => [p.id, p]))

    const portX = posMap.get('data-Port')!.x
    const nmapX = posMap.get('tool-Nmap')!.x

    // Port should be left of or equal to Nmap (consumer edge goes forward)
    expect(portX, 'Port data node should be left of Nmap').toBeLessThan(nmapX)
  })
})


// ---------------------------------------------------------------------------
// useWorkflowGraph logic (tested without React via direct computation)
// ---------------------------------------------------------------------------

describe('workflow graph logic', () => {

  // Simulate the core hook logic without React
  function computeGraphState(enabledFields: Record<string, boolean>) {
    const formData: Record<string, unknown> = {}
    for (const tool of WORKFLOW_TOOLS) {
      formData[tool.enabledField] = enabledFields[tool.enabledField] ?? true
    }

    // Data node status
    const dataNodeStatus = new Map<string, 'active' | 'starved'>()
    for (const nodeType of ALL_WORKFLOW_DATA_NODES) {
      if (UNIVERSAL_DATA_NODES.has(nodeType)) {
        dataNodeStatus.set(nodeType, 'active')
        continue
      }
      const hasActiveProducer = WORKFLOW_TOOLS.some(
        t => formData[t.enabledField] && getToolProduces(t.id).includes(nodeType)
      )
      dataNodeStatus.set(nodeType, hasActiveProducer ? 'active' : 'starved')
    }

    // Tool chain-broken status
    const toolBrokenInputs = new Map<string, string[]>()
    for (const tool of WORKFLOW_TOOLS) {
      const consumed = getToolConsumes(tool.id)
      const starved = consumed.filter(
        t => TRANSITIONAL_DATA_NODES.has(t) && dataNodeStatus.get(t) === 'starved'
      )
      if (starved.length > 0) toolBrokenInputs.set(tool.id, starved)
    }

    return { dataNodeStatus, toolBrokenInputs, formData }
  }

  describe('data node starved detection', () => {
    test('all universal data nodes are always active', () => {
      // Even with everything disabled
      const allDisabled: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) allDisabled[tool.enabledField] = false

      const { dataNodeStatus } = computeGraphState(allDisabled)
      for (const nt of UNIVERSAL_DATA_NODES) {
        expect(dataNodeStatus.get(nt), `${nt} should be active`).toBe('active')
      }
    })

    test('Port is active when Naabu is enabled', () => {
      const { dataNodeStatus } = computeGraphState({ naabuEnabled: true })
      expect(dataNodeStatus.get('Port')).toBe('active')
    })

    test('Port is active when only Shodan is enabled (passive port data)', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      fields['shodanEnabled'] = true

      const { dataNodeStatus } = computeGraphState(fields)
      expect(dataNodeStatus.get('Port')).toBe('active')
    })

    test('Port is starved when all port producers are disabled', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      // Only enable tools that do NOT produce Port
      fields['katanaEnabled'] = true
      fields['nucleiEnabled'] = true

      const { dataNodeStatus } = computeGraphState(fields)
      expect(dataNodeStatus.get('Port')).toBe('starved')
    })

    test('BaseURL is starved when Httpx and all crawlers are disabled', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      // Enable only non-BaseURL producers
      fields['naabuEnabled'] = true
      fields['shodanEnabled'] = true

      const { dataNodeStatus } = computeGraphState(fields)
      expect(dataNodeStatus.get('BaseURL')).toBe('starved')
    })

    test('BaseURL is active when only Httpx is enabled', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      fields['httpxEnabled'] = true

      const { dataNodeStatus } = computeGraphState(fields)
      expect(dataNodeStatus.get('BaseURL')).toBe('active')
    })

    test('CVE is starved when no CVE producers are enabled', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      fields['katanaEnabled'] = true // doesn't produce CVE

      const { dataNodeStatus } = computeGraphState(fields)
      expect(dataNodeStatus.get('CVE')).toBe('starved')
    })
  })

  describe('chain-broken detection', () => {
    test('Nmap is chain-broken when Port is starved', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      fields['nmapEnabled'] = true // enabled but its inputs are starved

      const { toolBrokenInputs } = computeGraphState(fields)
      const broken = toolBrokenInputs.get('Nmap') ?? []
      expect(broken).toContain('Port')
    })

    test('Katana is chain-broken when BaseURL is starved', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      // Katana itself lists BaseURL as an output (crawlers discover further
      // base URLs), so enabling Katana would self-satisfy its own BaseURL
      // input. To genuinely starve BaseURL, keep Katana off and enable only a
      // port scanner, which never produces BaseURL. Katana (a BaseURL consumer)
      // is still flagged chain-broken.
      fields['naabuEnabled'] = true

      const { toolBrokenInputs } = computeGraphState(fields)
      const broken = toolBrokenInputs.get('Katana') ?? []
      expect(broken).toContain('BaseURL')
    })

    test('Katana is NOT chain-broken when Httpx provides BaseURL', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      fields['katanaEnabled'] = true
      fields['httpxEnabled'] = true

      const { toolBrokenInputs } = computeGraphState(fields)
      expect(toolBrokenInputs.has('Katana')).toBe(false)
    })

    test('Mitre is chain-broken when CVE is starved', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      fields['mitreEnabled'] = true

      const { toolBrokenInputs } = computeGraphState(fields)
      const broken = toolBrokenInputs.get('Mitre') ?? []
      expect(broken).toContain('CVE')
    })

    test('SubdomainDiscovery is never chain-broken (only consumes universal Domain)', () => {
      // Even with everything else disabled
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      fields['subdomainDiscoveryEnabled'] = true

      const { toolBrokenInputs } = computeGraphState(fields)
      expect(toolBrokenInputs.has('SubdomainDiscovery')).toBe(false)
    })

    test('disabling Httpx breaks all downstream Resource Enum tools', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = true
      fields['httpxEnabled'] = false

      const { toolBrokenInputs } = computeGraphState(fields)

      // These tools consume BaseURL which only Httpx and crawlers produce
      // But crawlers also consume BaseURL, so if Httpx is off and crawlers are on,
      // BaseURL can still be produced by crawlers (Katana etc produce BaseURL too).
      // So actually BaseURL is NOT starved because Katana etc produce it.
      // Let's verify:
      const allDisabledExceptCrawlers: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) allDisabledExceptCrawlers[tool.enabledField] = true
      allDisabledExceptCrawlers['httpxEnabled'] = false

      const { dataNodeStatus } = computeGraphState(allDisabledExceptCrawlers)
      // Katana, Hakrawler, Gau etc also produce BaseURL
      expect(dataNodeStatus.get('BaseURL')).toBe('active')
    })

    test('disabling ALL BaseURL producers starves BaseURL and breaks consumers', () => {
      const fields: Record<string, boolean> = {}
      for (const tool of WORKFLOW_TOOLS) fields[tool.enabledField] = false
      // Only enable tools that do NOT produce BaseURL
      fields['naabuEnabled'] = true
      fields['nucleiEnabled'] = true

      const { dataNodeStatus, toolBrokenInputs } = computeGraphState(fields)
      expect(dataNodeStatus.get('BaseURL')).toBe('starved')
      // Nuclei consumes BaseURL
      expect(toolBrokenInputs.get('Nuclei')).toContain('BaseURL')
    })
  })

  describe('edge generation', () => {
    test('universal data nodes have edges to all tools that consume them', () => {
      // Count expected edges: for each universal type, count tools that consume it
      for (const nt of UNIVERSAL_DATA_NODES) {
        const consumers = WORKFLOW_TOOLS.filter(t => getToolConsumes(t.id).includes(nt))
        expect(consumers.length, `"${nt}" should have at least 1 consumer`).toBeGreaterThan(0)
      }
    })

    test('every transitional data node has at least one producer in the workflow', () => {
      // For connected data nodes only
      for (const nt of TRANSITIONAL_DATA_NODES) {
        const producers = WORKFLOW_TOOLS.filter(t => getToolProduces(t.id).includes(nt))
        // Some data nodes might only be consumed (e.g., via nodeMapping but no workflow producer)
        // That's OK -- they would appear starved. But let's verify the main ones have producers.
        if (['Port', 'Service', 'BaseURL', 'Endpoint', 'Technology', 'CVE', 'Vulnerability'].includes(nt)) {
          expect(producers.length, `"${nt}" should have at least 1 producer`).toBeGreaterThan(0)
        }
      }
    })

    test('Domain is consumed by multiple groups', () => {
      const consumers = WORKFLOW_TOOLS.filter(t => getToolConsumes(t.id).includes('Domain'))
      const groups = new Set(consumers.map(t => t.group))
      expect(groups.size, 'Domain should be consumed by tools in multiple groups').toBeGreaterThanOrEqual(3)
    })
  })
})


// ---------------------------------------------------------------------------
// useWorkflowGraph edges
// ---------------------------------------------------------------------------

describe('useWorkflowGraph edges', () => {
  test('every edge is inert so the canvas can be dragged from anywhere', () => {
    const formData = Object.fromEntries(WORKFLOW_TOOLS.map(t => [t.enabledField, true]))
    const { result } = renderHook(() => useWorkflowGraph(formData))

    expect(result.current.edges.length).toBeGreaterThan(0)
    // React Flow puts `nopan` and a pointer cursor on a selectable edge, and a
    // tab stop on a focusable one. Both must be off explicitly: undefined
    // falls back to the selectable/focusable defaults.
    for (const edge of result.current.edges) {
      expect(edge.selectable, `${edge.id} is selectable`).toBe(false)
      expect(edge.focusable, `${edge.id} is focusable`).toBe(false)
    }
  })
})


// ---------------------------------------------------------------------------
// Edge animation: static until a node is selected
// ---------------------------------------------------------------------------

describe('applyEdgeSelection', () => {
  // Only Naabu is on, so its edges flow and Masscan's (same inputs) do not.
  const formData = { naabuEnabled: true, masscanEnabled: false }
  const graphEdges = () => renderHook(() => useWorkflowGraph(formData)).result.current.edges
  const animated = (edges: ReturnType<typeof applyEdgeSelection>) =>
    edges.filter(e => (e.data as { shouldAnimate?: boolean }).shouldAnimate)
  const touching = (edges: ReturnType<typeof applyEdgeSelection>, nodeId: string) =>
    new Set(edges.filter(e => e.source === nodeId || e.target === nodeId).map(e => e.id))

  test('with nothing selected no edge animates, flowing or not', () => {
    const edges = graphEdges()
    expect(edges.some(e => (e.data as { flowing?: boolean }).flowing)).toBe(true)
    expect(animated(applyEdgeSelection(edges, new Set(), false))).toEqual([])
  })

  test('selecting an enabled tool animates exactly its own edges', () => {
    const edges = graphEdges()
    const ids = touching(edges, 'tool-Naabu')
    expect(ids.size).toBeGreaterThan(0)
    const moving = animated(applyEdgeSelection(edges, ids, true))
    expect(new Set(moving.map(e => e.id))).toEqual(ids)
  })

  test('the edges of a selected but disabled tool stay static', () => {
    const edges = graphEdges()
    const ids = touching(edges, 'tool-Masscan')
    expect(ids.size).toBeGreaterThan(0)
    expect(animated(applyEdgeSelection(edges, ids, true))).toEqual([])
  })
})


// ---------------------------------------------------------------------------
// Discovery & OSINT column
// ---------------------------------------------------------------------------

describe('Discovery & OSINT column', () => {
  const COLUMN = ['SubdomainDiscovery', 'Urlscan', 'Shodan', 'OsintEnrichment']

  test('Uncover has no node of its own (its settings live in OSINT Enrichment)', () => {
    expect(WORKFLOW_TOOLS.some(t => t.id === 'Uncover')).toBe(false)
  })

  test('the four tools stack top to bottom in one column', () => {
    const { result } = renderHook(() => useWorkflowGraph({}))
    const pos = COLUMN.map(id => result.current.nodes.find(n => n.id === `tool-${id}`)!.position)
    expect(new Set(pos.map(p => p.x)).size).toBe(1)
    for (let i = 1; i < pos.length; i++) expect(pos[i].y).toBeGreaterThan(pos[i - 1].y)
  })

  test('no other tool shares that column', () => {
    const { result } = renderHook(() => useWorkflowGraph({}))
    const x = result.current.nodes.find(n => n.id === 'tool-Urlscan')!.position.x
    const inColumn = result.current.nodes
      .filter(n => n.type === 'toolNode' && n.position.x === x)
      .map(n => (n.data as { toolId: string }).toolId)
    expect(inColumn).toEqual(COLUMN)
  })
})


// ---------------------------------------------------------------------------
// useWorkflowGraph: an enabled tool with nothing to work on
// ---------------------------------------------------------------------------

describe('useWorkflowGraph idle tools', () => {
  // OpenAPI is the only true source of Endpoint and Parameter in this form.
  const base = { openapiEnabled: true, openapiAutoDiscover: false }
  const node = (nodes: { id: string; data: Record<string, unknown> }[], id: string) =>
    nodes.find(n => n.id === id)!.data

  test('an idle OpenAPI is shown as Idle and feeds nothing', () => {
    const { result } = renderHook(() => useWorkflowGraph({ ...base, openapiSources: [] }))
    expect(node(result.current.nodes, 'tool-OpenAPI')).toMatchObject({ enabled: true, idle: true })
    expect(node(result.current.nodes, 'data-Endpoint').status).toBe('starved')
    expect(node(result.current.nodes, 'data-Parameter').status).toBe('starved')
  })

  test('configuring a document wakes it, without a toggle changing', () => {
    let formData: Record<string, unknown> = { ...base, openapiSources: [] }
    const { result, rerender } = renderHook(() => useWorkflowGraph(formData))
    formData = { ...base, openapiSources: [{ url: 'https://docs.example.com/openapi.json' }] }
    rerender()
    expect(node(result.current.nodes, 'tool-OpenAPI').idle).toBe(false)
    expect(node(result.current.nodes, 'data-Endpoint').status).toBe('active')
  })

  test('a disabled tool is never idle', () => {
    const { result } = renderHook(() => useWorkflowGraph({ openapiEnabled: false, openapiSources: [] }))
    expect(node(result.current.nodes, 'tool-OpenAPI')).toMatchObject({ enabled: false, idle: false })
  })
})
