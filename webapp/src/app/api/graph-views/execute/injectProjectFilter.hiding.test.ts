/**
 * Nothing a caller types can hide code from the saved-view filter (fix of the 4.3 review finding 1,
 * and the read holes found with it in step 4.6).
 *
 * The checks stripped `//` comments before string literals, so `'http://x'` turned the rest of its
 * line into a "comment": a write clause, an apoc call, a `[*]` hop or the Muted label after it went
 * unseen. And the node-pattern scanner only knew innermost `(...)` groups of bare words, so a node it
 * could not read was neither scoped nor reported: a backticked label, a comment or a `(` inside a
 * string or a call inside the pattern, `MATCH(n)` written without a space, a parenthesised label
 * expression or an inline WHERE each ran with no tenant filter at all, a read of every project's
 * graph. Now comments go, literals are set aside and quoted names unwrapped before any check, and a
 * node pattern the scanner cannot read is refused rather than run.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  findDisallowedCall, findUnscopedNodePattern, findWriteClause, hasVariableLengthPath, injectProjectFilter,
  namesMutedLabel, unreadableQuery,
} from './injectProjectFilter'

const AFTER_URL = "MATCH (n:Host) WHERE n.url <> 'http://x' "

describe('a string holding // hides nothing after it', () => {
  test.each([
    ['DETACH DELETE n', 'DETACH'],
    ['SET n.name = 1', 'SET'],
    ['CREATE (m:Host)', 'CREATE'],
    ['MERGE (m:Host)', 'MERGE'],
    ['REMOVE n.name', 'REMOVE'],
  ])('a write clause after the string is found: %s', (tail, word) => {
    expect(findWriteClause(AFTER_URL + tail)).toBe(word)
  })

  test('an apoc call, a [*] hop and the Muted label after the string are found', () => {
    expect(findDisallowedCall(AFTER_URL + "RETURN apoc.cypher.runFirstColumnSingle('MATCH (m) RETURN m', {})"))
      .toBe('apoc.cypher.runFirstColumnSingle')
    expect(hasVariableLengthPath(AFTER_URL + 'MATCH (n)-[*]->(m:Host) RETURN m')).toBe(true)
    expect(namesMutedLabel(AFTER_URL + 'MATCH (m:Muted) RETURN m')).toBe(true)
  })

  test('the same words inside a string literal or a comment are data, not code', () => {
    expect(findWriteClause("MATCH (n:Host) WHERE n.note = 'please DELETE me // SET' RETURN n")).toBeNull()
    expect(findWriteClause('MATCH (n:Host) RETURN n // DELETE it later')).toBeNull()
    expect(findWriteClause('MATCH (n:Host) /* CREATE (m) */ RETURN n')).toBeNull()
    expect(namesMutedLabel("MATCH (n:Host) WHERE n.note = 'Muted' RETURN n")).toBe(false)
  })

  test('a property that shares a name with a clause is not a write', () => {
    expect(findWriteClause('MATCH (n:Host) RETURN n.set, n.delete, n.created_at')).toBeNull()
  })

  test('clauses that read outside the graph are refused too', () => {
    expect(findWriteClause("LOAD CSV FROM 'http://169.254.169.254/' AS row RETURN row")).toBe('LOAD')
    expect(findWriteClause('USE system SHOW USERS')).toBe('USE')
    expect(findWriteClause('SHOW DATABASES')).toBe('SHOW')
    expect(findWriteClause('MATCH (n:Host) CALL { WITH n RETURN n AS m } RETURN m')).toBe('CALL')
  })
})

describe('a node pattern the filter cannot read is refused, never run unscoped', () => {
  const scopedOrRefused = (q: string) => {
    const filtered = injectProjectFilter(q)
    return findUnscopedNodePattern(filtered) === null ? filtered : null
  }

  test('a backticked label is scoped like a bare one', () => {
    const q = scopedOrRefused('MATCH (n:`Domain`) RETURN n')
    expect(q).toContain('(n:Domain&!Muted {project_id: $projectId})')
  })

  test('a backticked name that is not a plain identifier is refused inside a node pattern', () => {
    expect(scopedOrRefused('MATCH (n:`my label`) RETURN n')).toBeNull()
  })

  test('a comment inside a node pattern is dropped, and the pattern scoped', () => {
    const q = scopedOrRefused('MATCH (n /* ( */) RETURN n')
    expect(q).not.toBeNull()
    expect(q).toContain('project_id: $projectId')
  })

  test('a ( inside a string in the property map does not hide the pattern; the string comes back as typed', () => {
    const q = scopedOrRefused("MATCH (n {name: '('}) RETURN n")
    expect(q).toBe("MATCH (n:!Muted {project_id: $projectId, name: '('}) RETURN n")
  })

  test('a call inside a node pattern\'s property map is scoped (review of 4.6, finding 4)', () => {
    expect(scopedOrRefused('MATCH (n {name: toString(1)}) RETURN n'))
      .toBe('MATCH (n:!Muted {project_id: $projectId, name: toString(1)}) RETURN n')
  })

  test('MATCH(n) without a space is a node pattern, not a function call', () => {
    expect(scopedOrRefused('MATCH(n) RETURN n')).toContain('MATCH(n:!Muted {project_id: $projectId})')
    expect(scopedOrRefused('MATCH (a:Host),(b) RETURN a, b')).toContain('(b:!Muted {project_id: $projectId})')
  })

  test('a parenthesised label expression and an inline WHERE are scoped (review of 4.6, finding 4)', () => {
    expect(scopedOrRefused('MATCH (n:(Domain|Subdomain)) RETURN n'))
      .toBe('MATCH (n:(Domain|Subdomain)&!Muted {project_id: $projectId}) RETURN n')
    expect(scopedOrRefused("MATCH (n:Domain WHERE n.name = 'x') RETURN n"))
      .toBe("MATCH (n:Domain&!Muted {project_id: $projectId} WHERE n.name = 'x') RETURN n")
  })

  test('a call written against its paren keeps its arguments: count(n), exists(n.x)', () => {
    expect(scopedOrRefused('MATCH (n:Host) RETURN count(n), exists(n.name)'))
      .toBe('MATCH (n:Host&!Muted {project_id: $projectId}) RETURN count(n), exists(n.name)')
  })

  test('a paren after a space opens a pattern, as in the Python filter: count (n) is scoped (Neo4j then refuses it), never left open', () => {
    expect(scopedOrRefused('MATCH (n:Host) RETURN count (n)')).toContain('count (n:!Muted {project_id: $projectId})')
  })

  test('path selectors open patterns too: ANY(n), SHORTEST 2 (a)', () => {
    expect(scopedOrRefused('MATCH ANY(n:Host) RETURN n')).toContain('ANY(n:Host&!Muted {project_id: $projectId})')
    expect(scopedOrRefused('MATCH SHORTEST 2 (a:Host)-[:R]->(b) RETURN b')).toContain('2 (a:Host&!Muted {project_id: $projectId})')
  })

  test('a property map naming another project_id is refused, not taken as already scoped', () => {
    expect(scopedOrRefused("MATCH (n:Domain {project_id: 'P-someone-else'}) RETURN n")).toBeNull()
    expect(scopedOrRefused("MATCH (n:Domain {project_id: $projectId, project_id: 'P-x'}) RETURN n")).toBeNull()
    // The exact filter is kept, and the mute exclusion still added (review of 4.6, finding 5).
    expect(scopedOrRefused('MATCH (n:Domain {project_id: $projectId}) RETURN n')).toBe('MATCH (n:Domain&!Muted {project_id: $projectId}) RETURN n')
  })

  test('a quantified relationship is refused like a [*] hop: its nodes are never written', () => {
    expect(hasVariableLengthPath('MATCH (a:Host)-[:R]->+(b:Host) RETURN b')).toBe(true)
    expect(hasVariableLengthPath('MATCH (a:Host)-->*(b:Host) RETURN b')).toBe(true)
    expect(hasVariableLengthPath('MATCH (a:Host)<--+(b:Host) RETURN b')).toBe(true)
    expect(hasVariableLengthPath('MATCH (a:Host) RETURN count(a) * 2, a.x - +1')).toBe(false)
  })

  test('a node pattern inside a string literal is data: left as typed', () => {
    const q = scopedOrRefused("MATCH (n:Host) WHERE n.note = 'MATCH (m) RETURN m' RETURN n")
    expect(q).toBe("MATCH (n:Host&!Muted {project_id: $projectId}) WHERE n.note = 'MATCH (m) RETURN m' RETURN n")
  })

  test('escaped quotes and doubled backticks are read as part of their literal', () => {
    const q = scopedOrRefused("MATCH (n:Host) WHERE n.note = 'it\\'s (fine)' RETURN n.`a``b`")
    expect(q).toBe("MATCH (n:Host&!Muted {project_id: $projectId}) WHERE n.note = 'it\\'s (fine)' RETURN n.`a``b`")
  })
})

describe('a query the filter cannot read at all is refused', () => {
  test.each([
    ["MATCH (n:Host) WHERE n.name = 'open RETURN n", 'string'],
    ['MATCH (n:Host) RETURN n /* open', 'comment'],
    ['MATCH (n:Host) RETURN n.`open', 'quoted name'],
    ['MATCH (n:Host RETURN n', 'parentheses'],
    ['MATCH (n:Host) RETURN n)', 'parentheses'],
    ["MATCH (n:Host) WHERE n.x = '\u0001' RETURN n", 'control character'],
  ])('%s', (q, why) => {
    expect(unreadableQuery(q)).toContain(why)
    expect(findUnscopedNodePattern(injectProjectFilter(q))).not.toBeNull()
  })

  test('an ordinary read is readable', () => {
    expect(unreadableQuery("MATCH (d:Domain)<-[:BELONGS_TO]-(s:Subdomain) WHERE s.name ENDS WITH '.test' RETURN d, s")).toBeNull()
  })
})
