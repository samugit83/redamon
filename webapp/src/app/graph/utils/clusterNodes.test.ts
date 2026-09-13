/** @vitest-environment node */
/**
 * Strategy row 5 (L1): a wildcard certificate's COVERS_HOST fan-out must collapse.
 *
 * One wildcard certificate can name every subdomain it covers, turning the
 * Certificate into a high-degree hub. /graph degrades on the first such cert
 * unless COVERS_HOST is registered in STRUCTURAL_EDGE_TYPES.
 *
 * ISOLATION NOTE. A Subdomain hanging off a cert by a single edge is a degree-1
 * leaf, and Pass 1 collapses those whatever the edge is called -- a test built
 * that way passes even with COVERS_HOST unregistered, so it proves nothing.
 * STRUCTURAL_EDGE_TYPES only decides Pass 2, which needs a node of degree > 1
 * whose edges are ALL structural. Every fixture here therefore gives each
 * Subdomain a second (outgoing) structural edge, so Pass 1 cannot claim it and
 * only the COVERS_HOST registration can produce the collapse.
 *
 * Run: npx vitest run src/app/graph/utils/clusterNodes.test.ts
 */
import { describe, test, expect } from 'vitest'
import { clusterGraphData } from './clusterNodes'
import type { GraphData, GraphNode, GraphLink } from '../types'

function node(id: string, type: string): GraphNode {
  return { id, name: id, type, properties: {} }
}

/**
 * Certificate --covers--> Sub_i --HAS_DNS_RECORD--> Rec_i
 * Each Sub_i has degree 2, so it is not a Pass-1 leaf. One DNSRecord per
 * Subdomain keeps that group under threshold so it cannot collapse either.
 */
function wildcardCertGraph(n: number, coversEdge = 'COVERS_HOST'): GraphData {
  const nodes: GraphNode[] = [node('cert', 'Certificate')]
  const links: GraphLink[] = []
  for (let i = 0; i < n; i++) {
    nodes.push(node(`sub${i}`, 'Subdomain'), node(`rec${i}`, 'DNSRecord'))
    links.push({ source: 'cert', target: `sub${i}`, type: coversEdge })
    links.push({ source: `sub${i}`, target: `rec${i}`, type: 'HAS_DNS_RECORD' })
  }
  return { nodes, links, projectId: 'p1' }
}

describe('clusterGraphData — COVERS_HOST fan-out', () => {
  test('a wildcard certificate covering many hosts collapses into a cluster', () => {
    const before = wildcardCertGraph(40)
    const after = clusterGraphData(before, 5)

    const cluster = after.nodes.find(nd => nd.isCluster && nd.clusterChildType === 'Subdomain')
    expect(cluster, 'COVERS_HOST fan-out did not collapse').toBeDefined()
    expect(after.nodes.length).toBeLessThan(before.nodes.length)
  })

  test('control: the SAME shape with an unregistered edge type does NOT collapse', () => {
    // This is what makes the test above meaningful. If COVERS_HOST were dropped
    // from STRUCTURAL_EDGE_TYPES the first test would look like this one.
    const before = wildcardCertGraph(40, 'SOME_SEMANTIC_EDGE')
    const after = clusterGraphData(before, 5)
    const cluster = after.nodes.find(nd => nd.isCluster && nd.clusterChildType === 'Subdomain')
    expect(cluster, 'a non-structural edge must not be collapsed').toBeUndefined()
  })

  test('the collapsed subdomains are preserved as children, not dropped', () => {
    const after = clusterGraphData(wildcardCertGraph(40), 5)
    const cluster = after.nodes.find(nd => nd.isCluster && nd.clusterChildType === 'Subdomain')!
    const loose = after.nodes.filter(nd => nd.type === 'Subdomain' && !nd.isCluster).length
    expect((cluster.clusterChildren?.length ?? 0) + loose).toBe(40)
  })

  test('the certificate hub itself survives the collapse', () => {
    const after = clusterGraphData(wildcardCertGraph(40), 5)
    expect(after.nodes.some(nd => nd.id === 'cert')).toBe(true)
  })

  test('a fan-out below the threshold is left alone', () => {
    const before = wildcardCertGraph(2)
    const after = clusterGraphData(before, 20)
    expect(after.nodes.filter(nd => nd.isCluster).length).toBe(0)
  })
})
