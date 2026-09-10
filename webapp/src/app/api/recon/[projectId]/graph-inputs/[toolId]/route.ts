import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { getGraphSession } from '@/app/api/graph/neo4j'

interface RouteParams {
  params: Promise<{ projectId: string; toolId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, toolId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    // Get project to know user_id and fallback domain
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { userId: true, targetDomain: true }
    })

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    // Query Neo4j directly for graph inputs
    if (toolId === 'SubdomainDiscovery') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             RETURN d.name AS domain, count(s) AS subdomainCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomainCount = record?.get('subdomainCount')?.toNumber?.() ?? record?.get('subdomainCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: subdomainCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Naabu' || toolId === 'Masscan') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
             OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
             WITH d, collect(DISTINCT s.name) AS subdomains,
                  count(DISTINCT i) + count(DISTINCT di) AS ipCount
             RETURN d.name AS domain, subdomains, size(subdomains) AS subCount, ipCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0
          const ipCount = record?.get('ipCount')?.toNumber?.() ?? record?.get('ipCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              existing_ips_count: ipCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn(`Neo4j query failed for ${toolId} graph-inputs, falling back to settings:`, err)
      }
    }

    else if (toolId === 'Nmap') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)
             OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
             WITH d, collect(DISTINCT s.name) AS subdomains,
                  count(DISTINCT i) + count(DISTINCT di) AS ipCount,
                  count(DISTINCT p) + count(DISTINCT dp) AS portCount
             RETURN d.name AS domain, subdomains, size(subdomains) AS subCount, ipCount, portCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0
          const ipCount = record?.get('ipCount')?.toNumber?.() ?? record?.get('ipCount') ?? 0
          const portCount = record?.get('portCount')?.toNumber?.() ?? record?.get('portCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              existing_ips_count: ipCount,
              existing_ports_count: portCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Nmap graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Katana') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: 0,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Katana graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'ZapAjaxSpider') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls
             OPTIONAL MATCH (b2:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount, count(DISTINCT e) AS endpointCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0
          const endpointCount = record?.get('endpointCount')?.toNumber?.() ?? record?.get('endpointCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              existing_endpoints_count: endpointCount,
              existing_subdomains_count: 0,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for ZapAjaxSpider graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Hakrawler') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: 0,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Hakrawler graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Jsluice') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: 0,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Jsluice graph-inputs, falling back to settings:', err)
      }
    }

    // SupplyChainRecon consumes the same graph inputs as JsRecon (BaseURLs +
    // Endpoints); it re-uses the JS-recon fetch to harvest packages.
    else if (toolId === 'JsRecon' || toolId === 'SupplyChainRecon') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls
             OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
             WITH d, baseurls, count(DISTINCT e) AS endpointCount
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount, endpointCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0
          const endpointCount = record?.get('endpointCount')?.toNumber?.() ?? record?.get('endpointCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: 0,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              existing_endpoints_count: endpointCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn(`Neo4j query failed for ${toolId} graph-inputs, falling back to settings:`, err)
      }
    }

    else if (toolId === 'Gau') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             WITH d, collect(DISTINCT s.name) AS subdomains
             RETURN d.name AS domain, subdomains, size(subdomains) AS subCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Gau graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'ParamSpider') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             WITH d, collect(DISTINCT s.name) AS subdomains
             RETURN d.name AS domain, subdomains, size(subdomains) AS subCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for ParamSpider graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Arjun') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (b)-[:HAS_ENDPOINT]->(e:Endpoint {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls, count(DISTINCT e) AS endpointCount
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount, endpointCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0
          const endpointCount = record?.get('endpointCount')?.toNumber?.() ?? record?.get('endpointCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: 0,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              existing_endpoints_count: endpointCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Arjun graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'EndpointAiClassifier') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (p:Parameter {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (e2:Endpoint {user_id: $uid, project_id: $pid})
               WHERE e2.ai_interface_type IS NOT NULL AND e2.ai_interface_type <> 'non-llm'
             RETURN d.name AS domain,
                    count(DISTINCT e) AS endpointCount,
                    count(DISTINCT p) AS parameterCount,
                    count(DISTINCT e2) AS alreadyClassifiedCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const endpointCount = record?.get('endpointCount')?.toNumber?.() ?? record?.get('endpointCount') ?? 0
          const parameterCount = record?.get('parameterCount')?.toNumber?.() ?? record?.get('parameterCount') ?? 0
          const alreadyClassifiedCount = record?.get('alreadyClassifiedCount')?.toNumber?.() ?? record?.get('alreadyClassifiedCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_endpoints_count: endpointCount,
              existing_parameters_count: parameterCount,
              already_ai_classified_count: alreadyClassifiedCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for EndpointAiClassifier graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Ffuf') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: 0,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Ffuf graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Kiterunner') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: 0,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Kiterunner graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'SecurityChecks') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
             OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
             WITH d, collect(DISTINCT s.name) AS subdomains,
                  count(DISTINCT i) + count(DISTINCT di) AS ipCount
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, subdomains, ipCount, collect(DISTINCT b.url) AS baseurls
             RETURN d.name AS domain, subdomains, size(subdomains) AS subCount, ipCount, baseurls, size(baseurls) AS baseurlCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0
          const ipCount = record?.get('ipCount')?.toNumber?.() ?? record?.get('ipCount') ?? 0
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              existing_ips_count: ipCount,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for SecurityChecks graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Httpx') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             WITH d, collect(DISTINCT s.name) AS subdomains
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)
             OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
             OPTIONAL MATCH (p)-[:HAS_SERVICE]->(:Service)-[:SERVES_URL]->(bu:BaseURL)
             OPTIONAL MATCH (dp)-[:HAS_SERVICE]->(:Service)-[:SERVES_URL]->(dbu:BaseURL)
             WITH d, subdomains,
                  count(DISTINCT i) + count(DISTINCT di) AS ipCount,
                  count(DISTINCT p) + count(DISTINCT dp) AS portCount,
                  count(DISTINCT bu) + count(DISTINCT dbu) AS baseurlCount
             RETURN d.name AS domain, subdomains, size(subdomains) AS subCount, ipCount, portCount, baseurlCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0
          const ipCount = record?.get('ipCount')?.toNumber?.() ?? record?.get('ipCount') ?? 0
          const portCount = record?.get('portCount')?.toNumber?.() ?? record?.get('portCount') ?? 0
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              existing_ips_count: ipCount,
              existing_ports_count: portCount,
              existing_baseurls_count: baseurlCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Httpx graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Nuclei') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             WITH d, count(DISTINCT s) AS subCount
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, subCount, collect(DISTINCT b.url) AS baseurls
             OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
             WITH d, subCount, baseurls, count(DISTINCT e) AS endpointCount
             RETURN d.name AS domain, subCount, baseurls, size(baseurls) AS baseurlCount, endpointCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0
          const endpointCount = record?.get('endpointCount')?.toNumber?.() ?? record?.get('endpointCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: subCount,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              existing_endpoints_count: endpointCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Nuclei graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'GraphqlScan') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls
             OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
             WITH d, baseurls, count(DISTINCT e) AS endpointCount,
                  count(DISTINCT CASE WHEN e.is_graphql = true THEN e END) AS graphqlEndpointCount
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount, endpointCount, graphqlEndpointCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0
          const endpointCount = record?.get('endpointCount')?.toNumber?.() ?? record?.get('endpointCount') ?? 0
          const graphqlEndpointCount = record?.get('graphqlEndpointCount')?.toNumber?.() ?? record?.get('graphqlEndpointCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: 0,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              existing_endpoints_count: endpointCount,
              existing_graphql_endpoints_count: graphqlEndpointCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for GraphqlScan graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'WebCachePoison') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls
             OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
             WITH d, baseurls, count(DISTINCT e) AS endpointCount
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount, endpointCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0
          const endpointCount = record?.get('endpointCount')?.toNumber?.() ?? record?.get('endpointCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: 0,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              existing_endpoints_count: endpointCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for WebCachePoison graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Shodan') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
             OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
             WITH d, collect(DISTINCT s.name) AS subdomains,
                  count(DISTINCT i) + count(DISTINCT di) AS ipCount
             RETURN d.name AS domain, subdomains, size(subdomains) AS subCount, ipCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0
          const ipCount = record?.get('ipCount')?.toNumber?.() ?? record?.get('ipCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              existing_ips_count: ipCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Shodan graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Urlscan') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             RETURN d.name AS domain, count(s) AS subdomainCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomainCount = record?.get('subdomainCount')?.toNumber?.() ?? record?.get('subdomainCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: subdomainCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Urlscan graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Uncover') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             RETURN d.name AS domain, count(s) AS subdomainCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomainCount = record?.get('subdomainCount')?.toNumber?.() ?? record?.get('subdomainCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: subdomainCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for Uncover graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'OsintEnrichment') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
             OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
             WITH d, collect(DISTINCT s.name) AS subdomains,
                  count(DISTINCT i) + count(DISTINCT di) AS ipCount
             RETURN d.name AS domain, subdomains, size(subdomains) AS subCount, ipCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0
          const ipCount = record?.get('ipCount')?.toNumber?.() ?? record?.get('ipCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              existing_ips_count: ipCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for OsintEnrichment graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'VhostSni') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
             OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
             OPTIONAL MATCH (s)-[:HAS_BASEURL]->(bu:BaseURL)
             OPTIONAL MATCH (ed:ExternalDomain {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT s.name) AS subdomains,
                  count(DISTINCT i) AS ipCount,
                  count(DISTINCT p) AS portCount,
                  count(DISTINCT bu) AS baseurlCount,
                  count(DISTINCT ed) AS externalCount
             RETURN d.name AS domain, subdomains,
                    size(subdomains) AS subCount,
                    ipCount, portCount, baseurlCount, externalCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0
          const ipCount = record?.get('ipCount')?.toNumber?.() ?? record?.get('ipCount') ?? 0
          const portCount = record?.get('portCount')?.toNumber?.() ?? record?.get('portCount') ?? 0
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0
          const externalCount = record?.get('externalCount')?.toNumber?.() ?? record?.get('externalCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              existing_ips_count: ipCount,
              existing_ports_count: portCount,
              existing_baseurls_count: baseurlCount,
              existing_external_domains_count: externalCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for VhostSni graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'SubdomainTakeover') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             OPTIONAL MATCH (s)-[:HAS_BASEURL]->(bu:BaseURL)
             WITH d, collect(DISTINCT s.name) AS subdomains,
                  count(DISTINCT bu) AS baseurlCount
             RETURN d.name AS domain, subdomains,
                    size(subdomains) AS subCount, baseurlCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              existing_baseurls_count: baseurlCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for SubdomainTakeover graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'AiSurfaceRecon') {
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             WITH d
             OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
             WITH d, collect(DISTINCT b.url) AS baseurls
             OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
             WITH d, baseurls,
                  count(DISTINCT CASE WHEN (e.ai_interface_type IS NOT NULL AND e.ai_interface_type <> 'non-llm') OR e.is_ai_framework_detected = true THEN e END) AS aiEndpoints,
                  count(DISTINCT CASE WHEN e.ai_interface_type = 'mcp' THEN e END) AS mcpEndpoints
             OPTIONAL MATCH (svc)-[:HAS_TECHNOLOGY|USES_TECHNOLOGY]->(t:Technology {category: 'ai-vector-db', user_id: $uid, project_id: $pid})
             RETURN d.name AS domain, baseurls, size(baseurls) AS baseurlCount, aiEndpoints, mcpEndpoints,
                    count(DISTINCT svc) AS vectorDbServices`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const baseurls: string[] = record?.get('baseurls') || []
          const baseurlCount = record?.get('baseurlCount')?.toNumber?.() ?? record?.get('baseurlCount') ?? 0
          const aiEndpoints = record?.get('aiEndpoints')?.toNumber?.() ?? record?.get('aiEndpoints') ?? 0
          const mcpEndpoints = record?.get('mcpEndpoints')?.toNumber?.() ?? record?.get('mcpEndpoints') ?? 0
          const vectorDbServices = record?.get('vectorDbServices')?.toNumber?.() ?? record?.get('vectorDbServices') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: 0,
              existing_baseurls: baseurls,
              existing_baseurls_count: baseurlCount,
              existing_ai_endpoints_count: aiEndpoints,
              existing_mcp_endpoints_count: mcpEndpoints,
              existing_vector_db_services_count: vectorDbServices,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for AiSurfaceRecon graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'OriginDiscovery') {
      // Origin Discovery needs CDN-FRONTED hosts (from a prior HTTP probe), not
      // just any subdomain. Return frontedCount so the modal can block a run with
      // nothing to unmask (G7). Fronted = resolves to a CDN IP, or its BaseURL is
      // CDN-flagged / carries a favicon hash.
      try {
        const session = getGraphSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             WITH d, collect(DISTINCT s.name) AS subdomains
             OPTIONAL MATCH (fs:Subdomain {user_id: $uid, project_id: $pid})
             WHERE EXISTS { (fs)-[:RESOLVES_TO]->(ci:IP) WHERE ci.is_cdn = true }
                OR EXISTS { (fs)-[:HAS_BASEURL]->(:BaseURL)-[:HAS_ENDPOINT]->(ep:Endpoint)
                            WHERE ep.is_cdn = true OR ep.favicon_hash IS NOT NULL }
             WITH d, subdomains, count(DISTINCT fs) AS frontedCount
             RETURN d.name AS domain, subdomains, size(subdomains) AS subCount, frontedCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomains: string[] = record?.get('subdomains') || []
          const subCount = record?.get('subCount')?.toNumber?.() ?? record?.get('subCount') ?? 0
          const frontedCount = record?.get('frontedCount')?.toNumber?.() ?? record?.get('frontedCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains: subdomains,
              existing_subdomains_count: subCount,
              fronted_count: frontedCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for OriginDiscovery graph-inputs, falling back to settings:', err)
      }
    }

    // Fallback: return domain from project settings
    return NextResponse.json({
      domain: project.targetDomain || null,
      existing_subdomains_count: 0,
      existing_ips_count: 0,
      existing_ports_count: 0,
      source: 'settings',
    })

  } catch (error) {
    console.error('Error getting graph inputs:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
