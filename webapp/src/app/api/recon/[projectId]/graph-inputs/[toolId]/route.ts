import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession } from '@/app/api/graph/neo4j'

interface RouteParams {
  params: Promise<{ projectId: string; toolId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, toolId } = await params

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
        const session = getSession()
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
        const session = getSession()
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
        const session = getSession()
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
        const session = getSession()
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

    else if (toolId === 'Hakrawler') {
      try {
        const session = getSession()
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
        const session = getSession()
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

    else if (toolId === 'JsRecon') {
      try {
        const session = getSession()
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
        console.warn('Neo4j query failed for JsRecon graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'Gau') {
      try {
        const session = getSession()
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
        const session = getSession()
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
        const session = getSession()
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

    else if (toolId === 'Ffuf') {
      try {
        const session = getSession()
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
        const session = getSession()
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
        const session = getSession()
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
        const session = getSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)
             OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
             OPTIONAL MATCH (p)-[:HAS_SERVICE]->(:Service)-[:SERVES_URL]->(bu:BaseURL)
             OPTIONAL MATCH (dp)-[:HAS_SERVICE]->(:Service)-[:SERVES_URL]->(dbu:BaseURL)
             WITH d, collect(DISTINCT s.name) AS subdomains,
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
        const session = getSession()
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
        console.warn('Neo4j query failed for Nuclei graph-inputs, falling back to settings:', err)
      }
    }

    else if (toolId === 'GraphqlScan') {
      try {
        const session = getSession()
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

    else if (toolId === 'Shodan') {
      try {
        const session = getSession()
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
        const session = getSession()
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
        const session = getSession()
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
        const session = getSession()
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

    else if (toolId === 'SubdomainTakeover') {
      try {
        const session = getSession()
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
