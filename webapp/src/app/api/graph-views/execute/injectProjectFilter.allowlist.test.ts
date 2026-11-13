/**
 * The saved-view filter reads a query through an allowlist (fix of the step 4.6 review findings).
 *
 * The filter decided what was a node pattern by a denylist of shapes, and Neo4j 5.26 reads more
 * shapes than it knew: a backticked name with a space, a Unicode letter, the `IS` label form, a `$`
 * inside a name, a control character Neo4j counts as whitespace or as a name character, a
 * quantifier written `{,n}` or with a Unicode dash. Each ran with no tenant filter: a read of every
 * project's graph. Now a query is read only when every character, every call and every node pattern
 * is one the filter positively knows; anything else answers 400. Every case below was checked
 * against Neo4j 5.26 (EXPLAIN) or comes from the reviewer's probe.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  findDisallowedCall, findStepContentReference, findUnscopedNodePattern, findWriteClause, hasVariableLengthPath,
  injectProjectFilter, namesMutedLabel, unreadableQuery,
} from './injectProjectFilter'

/** The route's sequence (route.ts): the query that would run, or why it is refused. */
function verdict(q: string): { run: string } | { refused: string } {
  const unreadable = unreadableQuery(q)
  if (unreadable) return { refused: `unreadable: ${unreadable}` }
  const write = findWriteClause(q)
  if (write) return { refused: `clause: ${write}` }
  if (namesMutedLabel(q)) return { refused: 'muted' }
  const call = findDisallowedCall(q)
  if (call) return { refused: `call: ${call}` }
  if (hasVariableLengthPath(q)) return { refused: 'variable-length' }
  const filtered = injectProjectFilter(q)
  const unscoped = findUnscopedNodePattern(filtered)
  if (unscoped) return { refused: `unscoped: ${unscoped}` }
  return { run: filtered }
}
const refused = (q: string) => 'refused' in verdict(q)
const ran = (q: string) => {
  const v = verdict(q)
  if ('refused' in v) throw new Error(`refused: ${q} (${v.refused})`)
  return v.run
}

describe('finding 1: a node pattern the filter does not positively read is refused', () => {
  test.each([
    ['a backticked variable that is not a plain name', 'MATCH (`x y`) RETURN `x y`'],
    ['the same at the end of a path', 'MATCH (a:Domain)-->(`b c`) RETURN `b c`'],
    ['a Unicode letter as the variable', 'MATCH (é) RETURN é'],
    ['a Unicode letter inside the variable', 'MATCH (nö:Domain) RETURN nö'],
    ['the IS label form', 'MATCH (n IS Domain) RETURN n'],
    ['the IS label form with no variable', 'MATCH (IS Domain) RETURN 1'],
    ['a $ inside a name (Neo4j reads n$ as one variable)', 'MATCH (n$) RETURN n$'],
    ['the label wildcard', 'MATCH (n:%) RETURN n'],
    ['a dynamic label', "MATCH (n:$('Domain')) RETURN n"],
    ['a parameter map', 'MATCH (n $projectId) RETURN n'],
    ['a backticked label that is not a plain name', 'MATCH (n:`my label`) RETURN n'],
    ['a quoted property key in the node map', 'MATCH (n {`a b`: 1}) RETURN n'],
    ['a map projection where a property map belongs', 'MATCH (n {.name}) RETURN n'],
  ])('%s: %s', (_why, q) => {
    expect(refused(q)).toBe(true)
  })

  test('EXISTS / COUNT / COLLECT followed by a map are node patterns to Neo4j, and are scoped', () => {
    expect(ran("MATCH (EXISTS {name: 'x'}) RETURN 1")).toContain("(EXISTS:!Muted {project_id: $projectId, name: 'x'})")
    expect(ran("MATCH (COUNT {name: 'x'}) RETURN 1")).toContain("(COUNT:!Muted {project_id: $projectId, name: 'x'})")
  })

  test('a parenthesised subquery stays an expression and its own patterns are scoped', () => {
    const q = ran('MATCH (n:Domain) WHERE (EXISTS { (n)-->(:Subdomain) }) RETURN n')
    expect(q).toContain('(n:!Muted {project_id: $projectId})-->(:Subdomain&!Muted {project_id: $projectId})')
  })

  test('an inline WHERE with no variable is scoped, as Neo4j reads (WHERE true) as a node', () => {
    expect(ran('MATCH (WHERE true) RETURN 1')).toBe('MATCH (:!Muted {project_id: $projectId} WHERE true) RETURN 1')
    expect(ran('MATCH (IS) RETURN IS')).toBe('MATCH (IS:!Muted {project_id: $projectId}) RETURN IS')
  })

  test('a backticked plain name is scoped like a bare one', () => {
    expect(ran('MATCH (n:Domain) WHERE n.x = 1 WITH n MATCH (`m`) RETURN m'))
      .toContain('MATCH (m:!Muted {project_id: $projectId}) RETURN m')
  })

  test('expressions in parentheses are left alone: IS NULL, a property, a literal, a list predicate', () => {
    expect(ran('MATCH (n:Domain) WHERE (n IS NOT NULL) AND (n.x IS NULL) AND (1 = 1) RETURN n'))
      .toBe('MATCH (n:Domain&!Muted {project_id: $projectId}) WHERE (n IS NOT NULL) AND (n.x IS NULL) AND (1 = 1) RETURN n')
    expect(ran("MATCH (n:Domain) WHERE any(x IN n.tags WHERE x = 'a') RETURN n"))
      .toBe("MATCH (n:Domain&!Muted {project_id: $projectId}) WHERE any(x IN n.tags WHERE x = 'a') RETURN n")
  })
})

describe('finding 2: control characters and non-ASCII outside string literals are refused', () => {
  test.each([
    ['U+001C after the variable (whitespace to Neo4j)', 'MATCH (n\u001c) RETURN n'],
    ['U+001F before a label', 'MATCH (n\u001f:Domain) RETURN n'],
    ['U+001C before the variable', 'MATCH (\u001cn:Domain) RETURN n'],
    ['U+0007 (a name character to Neo4j)', 'MATCH (n\u0007) RETURN n\u0007'],
    ['an apoc function behind U+001C', "MATCH (a:Domain) RETURN apoc.cypher.runFirstColumnMany\u001c('MATCH (n) RETURN n', {})"],
    ['U+0085 (C1)', 'MATCH (n\u0085) RETURN n'],
    ['U+007F', 'MATCH (n\u007f) RETURN n'],
    ['U+2028', 'MATCH (n\u2028) RETURN n'],
    ['U+2029', 'MATCH (n\u2029) RETURN n'],
    ['vertical tab', 'MATCH (n\u000b) RETURN n'],
    ['form feed', 'MATCH (n\u000c) RETURN n'],
    ['a control character inside a string literal', "MATCH (n:Domain) WHERE n.name = 'a\u0007' RETURN n"],
    ['a non-breaking space', 'MATCH (n:Domain)\u00a0RETURN n'],
    ['a Unicode dash in a relationship', 'MATCH (a:Technology)-[:HAS_CVE]\u2010{1,3}(c:CVE) RETURN a'],
    ['an em dash quantifier', 'MATCH (a:Technology)-[:HAS_CVE]\u2014+(c:CVE) RETURN a'],
  ])('%s', (_why, q) => {
    expect(unreadableQuery(q)).not.toBeNull()
    expect(refused(q)).toBe(true)
    expect(findUnscopedNodePattern(injectProjectFilter(q))).not.toBeNull()
  })

  test('the refusal says why', () => {
    expect(unreadableQuery('MATCH (n\u001c) RETURN n')).toContain('control character')
    expect(unreadableQuery('MATCH (é) RETURN é')).toContain('non-ASCII')
    expect(unreadableQuery('MATCH (n:Domain) WHERE n.x = $other RETURN n')).toContain('$projectId')
    expect(unreadableQuery('MATCH (n:Domain) RETURN n; MATCH (m) RETURN m')).toContain('one statement')
    expect(unreadableQuery('MATCH (n:Domain) RETURN n # x')).toContain("'#'")
  })

  test('tabs, newlines, Unicode inside string literals and quoted aliases are fine', () => {
    expect(ran("MATCH (n:Domain)\r\n\tWHERE n.name = 'città – ok'\nRETURN n.name AS `Città`"))
      .toBe("MATCH (n:Domain&!Muted {project_id: $projectId})\r\n\tWHERE n.name = 'città – ok'\nRETURN n.name AS `Città`")
  })

  test('a trailing semicolon is one statement', () => {
    expect(ran('MATCH (n:Domain) RETURN n;')).toBe('MATCH (n:Domain&!Muted {project_id: $projectId}) RETURN n;')
  })
})

describe('only the built-in pure functions may be called', () => {
  test.each([
    ["RETURN apoc.cypher.runFirstColumnMany('MATCH (n) RETURN n', {})", 'apoc.cypher.runFirstColumnMany'],
    ['MATCH (n:Domain) RETURN db.nameFromElementId(elementId(n))', 'db.nameFromElementId'],
    ['MATCH (n:Domain) RETURN graph.names()', 'graph.names'],
    ["MATCH (n:Domain) RETURN genai.vector.encode('x', 'OpenAI', {})", 'genai.vector.encode'],
    ['MATCH (n:Domain) RETURN myplugin(n)', 'myplugin'],
    ['MATCH (n:Domain) RETURN myplugin (n)', 'myplugin'],
    ['MATCH (n:Domain) RETURN shortestPath((n)-->(:Domain))', 'shortestPath'],
    ["MATCH (n:Domain) RETURN `apoc.cypher.runFirstColumnMany`('x', {})", 'apoc.cypher.runFirstColumnMany'],
    ["MATCH (n:Domain) RETURN `my fn`('x')", '`my fn`'],
    ['MATCH SHORTEST 2e1(n:Domain) RETURN n', '2e1'],
  ])('%s is refused', (q, name) => {
    expect(findDisallowedCall(q)).toBe(name)
    expect(refused(q)).toBe(true)
  })

  test('the built-ins a view uses are allowed, however written', () => {
    for (const q of [
      "MATCH (n:Domain) RETURN toLower(n.name), size(collect(n)), coalesce(n.x, 'y'), count(DISTINCT n)",
      'MATCH (n:Domain) RETURN date.truncate(\'day\', datetime()), duration.between(n.a, n.b), point.distance(n.p, n.q)',
      'MATCH (n:Domain) RETURN vector.similarity.cosine(n.v, n.w), none(x IN n.tags WHERE x = 1), reduce(s = 0, x IN [1] | s + x)',
      'MATCH (n:Domain) RETURN `count`(n), toString(id(n)), labels(n)[0], elementId(n)',
      'MATCH (n:Domain) RETURN count (*)',
    ]) {
      expect([q, findDisallowedCall(q)]).toEqual([q, null])
    }
  })
})

describe('finding 3: every quantified or variable-length form is refused', () => {
  test.each([
    'MATCH (a:Technology)-[:HAS_CVE]-{,3}(c:CVE) RETURN a',
    'MATCH p=(a:Technology)-[:HAS_CVE]-{,}(c:CVE) RETURN p',
    'MATCH p=(a:Technology)-[:HAS_CVE]-{ , }(c:CVE) RETURN p',
    'MATCH p=(a:Technology)-[:HAS_CVE]-{1, 2}(c:CVE) RETURN p',
    'MATCH (a:Domain) WITH a LIMIT 1 MATCH p=(c1:CVE)-[]-{,}(c2:CVE) RETURN p',
    'MATCH (a:Domain) WITH a LIMIT 1 MATCH p=(c1:CVE)-[]-{,2}(c2:CVE) RETURN p',
    'MATCH p=(a:Technology)- -+(c:CVE) RETURN p',
    'MATCH p=(a:Technology)-[:HAS_CVE]- -> +(c:CVE) RETURN p',
    'MATCH (a:Domain)-->+ (b) RETURN a',
    'MATCH (a:Domain)<- - *(b) RETURN a',
    'MATCH ((a:Domain)-->(b))+ RETURN a',
    'MATCH ((a:Domain)-->(b)){,3} RETURN a',
    'MATCH ((a:Domain)-->(b)) * RETURN a',
    'MATCH (a:Domain) (()-[r]->())+ (b) RETURN a',
    'MATCH (a:Domain)-[r *1..2]->(b) RETURN a',
    'MATCH (a:Domain)-[r:R*1..2 {tags: [1]}]->(b) RETURN a',
    "MATCH (a:Domain)<-[r * {tags: ['x', [2]]}]-(b) RETURN a",
  ])('%s', q => {
    expect(hasVariableLengthPath(q)).toBe(true)
    expect(refused(q)).toBe(true)
  })

  test('arithmetic, list slices, map projections and literals are not quantifiers', () => {
    for (const q of [
      'MATCH (a:Host) RETURN count(a) * 2, a.x - +1, (a.x + 1) * 2',
      'MATCH (n:Host) RETURN collect(n)[0..2], n{.name, .port}',
      "MATCH (n:Host) WHERE n.note = '-->+(x) {,3}' RETURN n",
    ]) {
      expect([q, hasVariableLengthPath(q)]).toEqual([q, false])
    }
  })
})

describe("finding 4: shapes the agent's validator accepts are scoped, not refused", () => {
  test('a parenthesised label expression', () => {
    expect(ran('MATCH (n:(Domain|Subdomain)) RETURN n'))
      .toBe('MATCH (n:(Domain|Subdomain)&!Muted {project_id: $projectId}) RETURN n')
  })

  test('a call inside the property map', () => {
    expect(ran("MATCH (n:Domain {name: toLower('X')}) RETURN n"))
      .toBe("MATCH (n:Domain&!Muted {project_id: $projectId, name: toLower('X')}) RETURN n")
  })

  test('an inline WHERE', () => {
    expect(ran("MATCH (n:Domain WHERE n.name = 'x') RETURN n"))
      .toBe("MATCH (n:Domain&!Muted {project_id: $projectId} WHERE n.name = 'x') RETURN n")
    expect(ran("MATCH (n:Domain {name: 'x'} WHERE n.y > 1) RETURN n"))
      .toBe("MATCH (n:Domain&!Muted {project_id: $projectId, name: 'x'} WHERE n.y > 1) RETURN n")
  })

  test('an alias named show, and labels or properties named after a clause', () => {
    expect(ran('MATCH (d:Domain) RETURN d.name AS show')).toBe('MATCH (d:Domain&!Muted {project_id: $projectId}) RETURN d.name AS show')
    expect(findWriteClause('MATCH (n:Set) RETURN n.show, n.load')).toBeNull()
  })

  test('a clause word anywhere else is still refused', () => {
    expect(findWriteClause('SHOW TRANSACTIONS')).toBe('SHOW')
    expect(findWriteClause('MATCH (d:Domain) RETURN d.name AS show ORDER BY show')).toBe('SHOW')
    expect(findWriteClause("WITH 1 AS AS LOAD CSV FROM 'http://x/' AS row RETURN row")).toBe('LOAD')
  })

  test('spaces inside a label expression and the legacy |: are read', () => {
    expect(ran('MATCH (n :Domain | Subdomain) RETURN n')).toBe('MATCH (n :Domain&!Muted|Subdomain&!Muted {project_id: $projectId}) RETURN n')
    expect(ran('MATCH (n:Domain|:Subdomain) RETURN n')).toBe('MATCH (n:Domain&!Muted|Subdomain&!Muted {project_id: $projectId}) RETURN n')
  })
})

describe("finding 5: the caller's own tenant filter still hides muted findings", () => {
  test.each([
    ['MATCH (n:Domain {project_id: $projectId}) RETURN n', 'MATCH (n:Domain&!Muted {project_id: $projectId}) RETURN n'],
    ['MATCH (n {project_id: $projectId}) RETURN n', 'MATCH (n:!Muted {project_id: $projectId}) RETURN n'],
    ["MATCH (v:Vulnerability {name: 'x', project_id: $projectId}) RETURN v", "MATCH (v:Vulnerability&!Muted {name: 'x', project_id: $projectId}) RETURN v"],
  ])('%s', (q, expected) => {
    expect(ran(q)).toBe(expected)
  })

  test('the backstop refuses a scoped pattern without the exclusion', () => {
    expect(findUnscopedNodePattern('MATCH (n:Domain {project_id: $projectId}) RETURN n')).toBe('n:Domain {project_id: $projectId}')
  })

  test('a tenant entry inside a nested value does not count as the filter', () => {
    const q = ran("MATCH (n {name: 'x' + left('', size(keys({project_id: $projectId})) - 1)}) RETURN n")
    expect(q).toContain("(n:!Muted {project_id: $projectId, name: 'x'")
  })
})

describe('finding 6: reference nodes only through a scoped node in the same path', () => {
  test.each([
    'MATCH (a:Domain) WITH count(a) AS c MATCH (x:CVE) RETURN x',
    'MATCH (a:Domain) WITH a MATCH (c:CVE) RETURN c',
    'MATCH (a:Domain), (c:CVE) RETURN c',
    'MATCH (a:Domain) MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData) RETURN m',
    'MATCH (c:CVE) RETURN c',
  ])('%s', q => {
    expect(verdict(q)).toMatchObject({ refused: expect.stringContaining('unscoped') })
  })

  test.each([
    'MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN t, c',
    'MATCH (c:CVE)<-[:HAS_KNOWN_CVE]-(t:Technology) RETURN c',
    'MATCH (t:Technology)-->(c:CVE)-[:HAS_CWE]->(m:MitreData) RETURN m',
    'MATCH (t:Technology) WHERE EXISTS { (t)-[:HAS_KNOWN_CVE]->(c:CVE) } RETURN t',
    'MATCH (t:Technology) RETURN [(t)- - >(c:CVE) | c.id] AS cves',
  ])('%s', q => {
    const run = ran(q)
    expect(run).toContain('(c:CVE)')
  })
})

describe('finding 7: below Raw data & files a view may not name step content', () => {
  test.each([
    ["MATCH (s:ChainStep) WHERE s.thought STARTS WITH 'a' RETURN s", 'thought'],
    ['MATCH (s:ChainStep) WHERE s.`reasoning` IS NOT NULL RETURN s', 'reasoning'],
    ["MATCH (s:ChainStep {output_summary: 'x'}) RETURN s", 'output_summary'],
    ['MATCH (s:ChainStep) RETURN s.OUTPUT_ANALYSIS', 'output_analysis'],
    ["MATCH (s:ChainStep) WHERE properties(s).tool_args_summary CONTAINS 'pass' RETURN s", 'tool_args_summary'],
    ['MATCH (f:ChainFailure) WHERE f.error_message = 1 OR f.lesson_learned = 1 RETURN f', 'error_message'],
    ["MATCH (d:ChainDecision) WHERE d.reason = 'x' RETURN d", 'reason'],
  ])('%s', (q, name) => {
    expect(findStepContentReference(q)).toBe(name)
  })

  test.each([
    "MATCH (s:ChainStep) WHERE s['thought'] STARTS WITH 'a' RETURN s",
    "MATCH (s:ChainStep) WHERE s['th' + 'ought'] = 'x' RETURN s",
    'MATCH (s:ChainStep) WHERE any(k IN keys(s) WHERE s[k] = 1) RETURN s',
    "MATCH (s:ChainStep) WHERE properties(s) ['x'] = 1 RETURN s",
  ])('a computed property access: %s', q => {
    expect(findStepContentReference(q)).toMatch(/computed/)
  })

  test('structure, numeric indexes, list literals and data in strings are fine', () => {
    for (const q of [
      "MATCH (s:ChainStep) WHERE s.tool_name = 'curl' AND s.phase IN ['exploitation'] RETURN s, labels(s)[0], collect(s)[0..2]",
      "MATCH (s:ChainStep) WHERE s.tool_name = 'thought' RETURN split(s.step_id, '-')[-1]",
      'MATCH (a:Domain)-[r:HAS_SUBDOMAIN]->(b) RETURN [x IN [1, 2] | x], b.name [0]',
    ]) {
      expect([q, findStepContentReference(q)]).toEqual([q, null])
    }
  })
})
