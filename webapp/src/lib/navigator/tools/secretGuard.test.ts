/**
 * Secret values under the RoE (plan §10.2 rows 8 and 27): a query may not name a secret-valued
 * property nor read one by a computed key, and a result never carries one, at any depth.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { SECRET_VALUE_KEYS, SECRET_WITHHELD, cypherEscapeRefusal, cypherSecretRefusal, maskSecretValues } from './secretGuard'

describe('cypherSecretRefusal', () => {
  test.each([
    'MATCH (s:Secret) RETURN s.matched_text AS x LIMIT 5',
    'MATCH (s:Secret) RETURN s.MATCHED_TEXT LIMIT 5',
    'MATCH (s:Secret) RETURN s.`matched_text` LIMIT 5',
    "MATCH (s:Secret) RETURN s['matched_text'] LIMIT 5",
    'MATCH (s:Secret) RETURN s{.matched_text} LIMIT 5',
    'MATCH (v:Vulnerability) RETURN v.secret_value LIMIT 5',
    'MATCH (e:Endpoint) RETURN e.unmasked_url LIMIT 5',
    'MATCH (s:Secret) WHERE s.raw_context IS NOT NULL RETURN count(s)',
  ])('names a secret property: %s', (q) => {
    expect(cypherSecretRefusal(q)).toMatch(/may not read matched_text|may not read .*secret_value/)
  })

  test.each([
    'MATCH (s:Secret) RETURN [k IN keys(s) | s[k]] LIMIT 5',
    'MATCH (s:Secret) RETURN s [k] LIMIT 5',
    "MATCH (s:Secret) RETURN s['matc' + 'hed_text'] LIMIT 5",
    'MATCH (s:Secret) RETURN properties(s)[k] LIMIT 5',
    'MATCH (s:Secret) RETURN s[keys(s)[0]] LIMIT 5',
    'MATCH (s:Secret) RETURN reduce(a = "", k IN keys(s) | a + s[k]) LIMIT 5',
    'MATCH (s:Secret) WITH s, keys(s) AS ks RETURN s[ks[2]] LIMIT 5',
    // Neo4j takes most keywords as variable names: a keyword before `[` is not always a list.
    'MATCH (s:Secret) WITH s, properties(s) AS limit RETURN [k IN keys(s) | limit[k]] AS v LIMIT 5',
    'MATCH (s:Secret) WITH s, properties(s) AS order RETURN [k IN keys(s) | order [k]] AS v LIMIT 5',
    'MATCH (s:Secret) WITH s, properties(s) AS limit RETURN [k IN keys(s) | limit[[k][0]]] AS v LIMIT 5',
    "MATCH (s:Secret) WITH s, properties(s) AS limit RETURN limit['matc' + 'hed_text'] LIMIT 5",
    "MATCH (s:Secret) WITH s, properties(s) AS limit RETURN [k IN keys(s) | limit[coalesce(k, 'x')]] LIMIT 5",
  ])('reads a property by a computed key: %s', (q) => {
    expect(cypherSecretRefusal(q)).toMatch(/computed key/)
  })

  // The AI Navigator security review read secret values with each of these through the real tool
  // callback, with the RoE at no_access.
  test.each([
    'MATCH (s:Secret) RETURN [k IN keys(s) | properties(s)/**/[k]] AS v LIMIT 5',
    'MATCH (s:Secret) RETURN [k IN keys(s) | properties(s) //,\n[k]] AS v LIMIT 5',
    'MATCH (s:Secret) RETURN s /* c */ .matched_text LIMIT 5',
  ])('a comment, which can sit between an expression and its subscript: %s', (q) => {
    expect(cypherSecretRefusal(q)).toMatch(/comment/)
  })

  test.each([
    'MATCH (s:Secret) RETURN s.\\u006datched_text AS v LIMIT 5',
    'MATCH (s:Secret) RETURN s.`\\u0073ecret_value` AS v LIMIT 5',
    'MATCH (s:Secret) RETURN s.secret\\u005fvalue AS v LIMIT 5',
    "MATCH (s:Secret) WITH s, properties(s) AS limit RETURN limit['\\u006datched_text'] LIMIT 5",
  ])('a \\uXXXX escape, which Neo4j decodes before it reads a name: %s', (q) => {
    expect(cypherSecretRefusal(q)).toMatch(/escape/)
  })

  test('an escape is refused whatever the RoE; nothing else is', () => {
    expect(cypherEscapeRefusal("MATCH (s:Subdomain) RETURN 'x\\u0027 AS n UNION MATCH (m:Subdomain) RETURN m.name AS n //' AS n"))
      .toMatch(/escape/)
    expect(cypherEscapeRefusal('MATCH (s:Secret) RETURN s.matched_text, properties(s)/**/[k] LIMIT 5')).toBeNull()
  })

  test.each([
    'MATCH (s:Secret) RETURN id(s) AS nodeId, s.secret_type, s.severity, s.source, s.source_url LIMIT 50',
    'MATCH (s:Secret) RETURN keys(s) LIMIT 5',
    'MATCH (i:IP) WHERE i.address IN [\'192.0.2.10\', \'192.0.2.20\'] RETURN i LIMIT 10',
    'MATCH (p:Port) WITH collect(p.number) AS ports RETURN ports[0], ports[-1], ports[1..3], ports[..2] LIMIT 1',
    'MATCH (s:Subdomain) RETURN [x IN collect(s.name) WHERE x CONTAINS "api" | x][0] LIMIT 1',
    'MATCH (s:Subdomain) WITH collect(s) AS subs RETURN [n IN subs | n.name] LIMIT 1',
    'MATCH (p:Port) WITH collect(p) AS ps UNWIND [1, 2] AS i RETURN ps[$i] LIMIT 1',
    'MATCH (s:Secret) RETURN s{.secret_type, .severity} LIMIT 5',
    "MATCH (s:Subdomain) WHERE s.name IN ['a.example.test'] RETURN s.name LIMIT 5",
    'MATCH (p:Port) WHERE p.number IN [] RETURN p LIMIT 5',
    'UNWIND [[1, 2], [3, 4]] AS pair MATCH (p:Port) WHERE p.number IN pair RETURN p LIMIT 5',
    'MATCH (s:Subdomain) RETURN [(s)-[:RESOLVES_TO]->(i:IP) | i.address] AS ips LIMIT 5',
    'MATCH (p:Port) RETURN CASE WHEN p.number > 1024 THEN [p.number, 0] ELSE [] END AS x LIMIT 5',
    "MATCH (e:Endpoint) WHERE e.url STARTS WITH 'https://' AND e.path CONTAINS '[id]' RETURN e.url LIMIT 5",
  ])('an ordinary query passes: %s', (q) => {
    expect(cypherSecretRefusal(q)).toBeNull()
  })
})

describe('maskSecretValues', () => {
  test('a node\'s secret properties, a bare map\'s and a nested one\'s are withheld; the rest is kept', () => {
    const out = maskSecretValues({
      records: [
        { s: { _kind: 'node', labels: ['Secret'], properties: { secret_type: 'AWS Secret Key', matched_text: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' } } },
        { m: { matched_text: 'x', paired_secret: 'y', inner: [{ unmasked_url: 'https://u:p@h.example' }] } },
      ],
    })
    const text = JSON.stringify(out)
    expect(text).not.toMatch(/wJalr|"x"|"y"|u:p@/)
    expect(text).toContain('AWS Secret Key')
    expect(text.split(SECRET_WITHHELD.replace(/"/g, '\\"')).length - 1).toBe(4)
  })

  test('a missing value stays missing (null is not a withheld secret)', () => {
    expect(maskSecretValues({ secret_value: null, matched_text: undefined })).toEqual({ secret_value: null, matched_text: undefined })
  })

  test('the keys cover every display-only property and the Secret match', () => {
    for (const k of ['secret_value', 'paired_secret', 'secret_values', 'unmasked_url', 'raw_context', 'matched_text']) {
      expect(SECRET_VALUE_KEYS.has(k)).toBe(true)
    }
  })
})
