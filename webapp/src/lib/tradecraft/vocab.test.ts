/**
 * The vocabulary's topic list must stay the agent's attack skills plus the OQ-7 areas, so
 * the Intent Router's choice always maps to a topic (phase 1 "Settings").
 *
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import {
  KIND_ALIASES, KIND_KEYWORDS, KIND_PREFERENCE_BY_PHASE, KINDS, RECIPES, SYNONYMS, TECHNOLOGIES, TOPIC_KEYWORDS, TOPICS,
  kindIds, resolveKind, skillTopicIds, topicIds,
} from './vocab'

function knownAttackPaths(): string[] {
  const src = readFileSync(join(__dirname, '../../../../agentic/state.py'), 'utf8')
  const m = src.match(/^KNOWN_ATTACK_PATHS\s*=\s*\{([^}]*)\}/m)
  if (!m) throw new Error('KNOWN_ATTACK_PATHS not found in agentic/state.py')
  return [...m[1].matchAll(/"([a-z_]+)"/g)].map(x => x[1]).sort()
}

describe('vocab', () => {
  test('the 14 skill topics equal KNOWN_ATTACK_PATHS', () => {
    expect(skillTopicIds().sort()).toEqual(knownAttackPaths())
    expect(skillTopicIds()).toHaveLength(14)
  })

  test('topics: unique ids, the OQ-7 areas, keywords for every topic and only for topics', () => {
    const ids = topicIds()
    expect(new Set(ids).size).toBe(ids.length)
    expect(TOPICS.filter(t => t.source === 'area').map(t => t.id)).toEqual(
      ['active_directory', 'cloud', 'privilege_escalation', 'mobile', 'wireless', 'containers', 'network_services'])
    expect(Object.keys(TOPIC_KEYWORDS).sort()).toEqual([...ids].sort())
    for (const [topic, words] of Object.entries(TOPIC_KEYWORDS)) {
      expect(words.length, topic).toBeGreaterThan(0)
      for (const w of words) expect(w, topic).toBe(w.toLowerCase())
    }
  })

  test('kinds: the eight §6.14 content types (OQ-21), with aliases and phase preferences that resolve', () => {
    expect(kindIds()).toEqual(['payloads', 'bypasses', 'techniques', 'tool_commands', 'poc', 'writeups', 'theory', 'detection'])
    expect(KINDS.find(k => k.id === 'techniques')!.mapLabel).toBe('methodology')
    expect(resolveKind('misconfigurations')).toBe('techniques')
    expect(resolveKind('Methodology')).toBe('techniques')
    expect(resolveKind('unknown')).toBeUndefined()
    for (const target of Object.values(KIND_ALIASES)) expect(kindIds()).toContain(target)
    expect(Object.keys(KIND_KEYWORDS).sort()).toEqual([...kindIds()].sort())
    expect(KIND_PREFERENCE_BY_PHASE).toEqual({
      informational: ['techniques'], exploitation: ['payloads', 'poc'], post_exploitation: ['tool_commands'],
    })
  })

  test('ten_recipes: the 10 built-in recipes of §6.14, naming only known topics and kinds', () => {
    expect(RECIPES.map(r => r.label)).toEqual([
      'Web payload library', 'SQL injection deep dive', 'Exploit code only', 'Active Directory attack paths',
      'Linux and Windows privilege escalation', 'Cloud attacks', 'Bypass and evasion', 'Tool cheat sheets', 'CVE write-ups',
      'Everything offensive, no defense',
    ])
    expect(new Set(RECIPES.map(r => r.id)).size).toBe(10)
    for (const r of RECIPES) {
      for (const t of r.topics) expect(topicIds(), r.id).toContain(t)
      for (const k of r.kinds) expect(kindIds(), r.id).toContain(k)
    }
    expect(RECIPES.find(r => r.id === 'web_payload_library')).toMatchObject({
      topics: ['sql_injection', 'xss', 'ssrf', 'xxe'], kinds: ['payloads', 'bypasses'],
    })
    expect(RECIPES.find(r => r.id === 'offensive_no_defense')!.kinds).not.toContain('detection')
  })

  test("synonyms: Q4's acronyms, lowercase and unique", () => {
    const terms = SYNONYMS.map(s => s.term)
    expect(new Set(terms).size).toBe(terms.length)
    for (const s of SYNONYMS) {
      expect(s.term).toBe(s.term.toLowerCase())
      expect(s.expansions.length).toBeGreaterThan(0)
    }
    for (const acronym of ['sqli', 'lfi', 'rfi', 'ssti', 'xxe', 'ssrf', 'idor', 'adcs', 'waf', 'rce']) expect(terms).toContain(acronym)
  })

  test('technologies: names only, unique ids, known categories', () => {
    const ids = TECHNOLOGIES.map(t => t.id)
    expect(new Set(ids).size).toBe(ids.length)
    const categories = new Set(['web_server', 'framework', 'cms', 'database', 'cloud', 'directory', 'tool'])
    for (const t of TECHNOLOGIES) {
      expect(categories.has(t.category), t.id).toBe(true)
      expect(t.name.length, t.id).toBeGreaterThan(0)
    }
    expect(ids).toEqual(expect.arrayContaining(['postgresql', 'nginx', 'wordpress', 'kerberos', 'sqlmap', 'bloodhound']))
  })
})
