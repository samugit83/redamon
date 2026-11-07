/**
 * T7, T8, T42, T43: every cross-surface identifier a tool claims resolves.
 *
 * Adding a tool to the recon pipeline means touching a container image list, a
 * runtime image allowlist, a dispatch table, a partial-recon module and a
 * ProjectForm section. Each of those was a separate hand-maintained list, and
 * the failure when one is missed is quiet in a particular way: the scan runs,
 * that tool does not, and no result field says why.
 *
 * So the registry's `tools:` block states each link and these tests resolve it,
 * in BOTH directions. The reverse direction matters as much: a section file or
 * a partial-recon module that maps back to no tool is dead code nobody will
 * notice, and a shipped image nothing claims is a pull on every scan for
 * nothing.
 *
 * @vitest-environment node
 */
import { existsSync, readFileSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'

import { RECON_PRESETS } from '@/lib/recon-presets'
import { field, fieldsWhere, loadRegistry, toolIds } from './registry'

const REPO = fileURLToPath(new URL('../../../../', import.meta.url))
const registry = loadRegistry()
const tools = registry.tools

const SECTIONS_DIR = path.join(REPO, 'webapp/src/components/projects/ProjectForm/sections')
const PARTIAL_DIR = path.join(REPO, 'recon/partial_recon_modules')
const ENTRYPOINT = path.join(REPO, 'recon/entrypoint.sh')
const RECON_SETTINGS = path.join(REPO, 'recon/project_settings.py')

/** The images `entrypoint.sh` pulls before a scan. */
function entrypointImages(): string[] {
  const text = readFileSync(ENTRYPOINT, 'utf8')
  const block = text.slice(text.indexOf('IMAGES=('), text.indexOf(')', text.indexOf('IMAGES=(')))
  return [...block.matchAll(/"([^"]+)"/g)].map(m => m[1])
}

/** Every `*_DOCKER_IMAGE` default, which is what ALLOWED_TOOL_IMAGES is built from. */
function shippedImages(): Set<string> {
  const text = readFileSync(RECON_SETTINGS, 'utf8')
  return new Set(
    [...text.matchAll(/'[A-Z0-9_]+_DOCKER_IMAGE':\s*'([^']+)'/g)].map(m => m[1])
  )
}

// --- T7: the image guardrail stays honest -------------------------------------------

describe('T7 every tool image is one the runtime will actually accept', () => {
  test("every tools[].image is a shipped default, so the guardrail never pins it away", () => {
    // The runtime pins every `*_DOCKER_IMAGE` key to its shipped default. A
    // tool image the registry names but the runtime does not ship would be
    // pinned away on every scan, silently.
    const allowed = shippedImages()
    const problems = toolIds()
      .filter(id => tools[id].image)
      .filter(id => !allowed.has(tools[id].image as string))
      .map(id => `${id}: ${tools[id].image}`)
    expect(problems).toEqual([])
  })

  test('every image the registry names is pulled by entrypoint.sh', () => {
    // An image nothing pulls is a scan that waits for a docker pull mid-run, or
    // fails on an air-gapped host.
    const pulled = new Set(entrypointImages())
    const missing = toolIds()
      .filter(id => tools[id].image && !pulled.has(tools[id].image as string))
      .map(id => `${id}: ${tools[id].image}`)
    expect(missing).toEqual([])
  })

  test('every image entrypoint.sh pulls is claimed by a tool', () => {
    // The reverse: an image pulled on every scan that nothing runs.
    const claimed = new Set(toolIds().map(id => tools[id].image).filter(Boolean))
    const orphans = entrypointImages().filter(img => !claimed.has(img))
    expect(orphans, 'entrypoint.sh pulls images no tool claims').toEqual([])
  })

  test('every *_DOCKER_IMAGE default is pulled at scan startup', () => {
    // Including the secondary ones: gau runs its own image and then httpx for
    // the verification pass, so `tools[].image` names only the primary one. An
    // image only pulled mid-scan stalls the run, or fails on an air-gapped host.
    const pulled = new Set(entrypointImages())
    const missing = [...shippedImages()].filter(img => !pulled.has(img))
    expect(missing).toEqual([])
  })

  test('no image is a project setting: every one is an internal runtime key', () => {
    // A scan runs the image RedAmon ships. A field would put a column, a form
    // control and an MCP write in front of `docker run` on the host daemon.
    expect(fieldsWhere((_s, key) => key.endsWith('DockerImage')).map(f => f.key)).toEqual([])
    const text = readFileSync(RECON_SETTINGS, 'utf8')
    const keys = [...text.matchAll(/'([A-Z0-9_]+_DOCKER_IMAGE)':\s*'/g)].map(m => m[1])
    expect(keys.length).toBeGreaterThan(0)
    const notInternal = keys.filter(k => registry.runtime_only[k]?.source !== 'internal')
    expect(notInternal).toEqual([])
  })
})

// --- T8: the ProjectForm sections ----------------------------------------------------

describe('T8 every form section a tool names is a real file', () => {
  test('every tools[].form_section exists', () => {
    const missing = toolIds()
      .filter(id => tools[id].form_section)
      .filter(id => !existsSync(path.join(SECTIONS_DIR, `${tools[id].form_section}.tsx`)))
      .map(id => `${id}: ${tools[id].form_section}.tsx`)
    expect(missing).toEqual([])
  })

  test('every tool has a form section, so nothing is unreachable in the UI', () => {
    const orphans = toolIds().filter(id => !tools[id].form_section)
    expect(orphans, 'these tools cannot be configured from the project form').toEqual([])
  })
})

// --- T42/T43: the partial-recon modules, both directions --------------------------------

describe('T42/T43 partial recon maps both ways', () => {
  test('every tools[].partial_recon_module is a real file', () => {
    const missing = toolIds()
      .filter(id => tools[id].partial_recon_module)
      .filter(id => !existsSync(path.join(PARTIAL_DIR, `${tools[id].partial_recon_module}.py`)))
      .map(id => `${id}: ${tools[id].partial_recon_module}.py`)
    expect(missing).toEqual([])
  })

  test('a tool with no partial-recon module is a deliberate gap, not a typo', () => {
    // Named, because "cannot be re-run from the workflow graph" is a real
    // product gap and the list of them should be visible rather than implied.
    const withoutModule = toolIds().filter(id => !tools[id].partial_recon_module).sort()
    // Every one of these is either not a pipeline tool at all (the RoE block,
    // the agent, project identity) or a standalone scanner with its own start
    // path (GVM, the GitHub hunt, TruffleHog, supply chain).
    for (const id of withoutModule) {
      const tool = tools[id]
      const isStandalone = tool.phase === 'standalone'
      const isEnrichment = tool.traffic === 'none'
      expect(
        isStandalone || isEnrichment,
        `${id} is a pipeline tool with traffic but no partial-recon module`
      ).toBe(true)
    }
  })
})

// --- the enable flags ------------------------------------------------------------------

describe('the two-level model is wired, not assumed', () => {
  test("every tools[].enabled_key is a field's runtime key", () => {
    const runtimeKeys = new Set(
      fieldsWhere(() => true).map(f => f.runtime_key).filter(Boolean)
    )
    const problems = toolIds()
      .filter(id => tools[id].enabled_key)
      .filter(id => !runtimeKeys.has(tools[id].enabled_key as string))
      .map(id => `${id}: ${tools[id].enabled_key}`)
    expect(problems).toEqual([])
  })

  test('every tool that sends traffic has an enable flag', () => {
    // A tool with no flag runs whenever its phase does, which is a different
    // product decision from "on by default" and should be a deliberate one.
    const problems = toolIds()
      .filter(id => tools[id].traffic !== 'none' && tools[id].phase !== 'standalone')
      .filter(id => !tools[id].enabled_key)
    expect(problems).toEqual([])
  })

  test("an enable flag's phase is its tool's phase", () => {
    // The two-level model: `scanModules` decides the phase and the flag decides
    // the tool inside it. A flag whose phase disagrees with its tool's would
    // make the pairing unpredictable.
    const problems: string[] = []
    for (const f of fieldsWhere((_s, key) => key.endsWith('Enabled'))) {
      const tool = tools[f.tool]
      if (!tool) continue
      if (f.phase !== tool.phase) {
        problems.push(`${f.key}: phase ${f.phase}, tool ${f.tool} is ${tool.phase}`)
      }
    }
    expect(problems).toEqual([])
  })
})

// --- the tool table itself ---------------------------------------------------------------

describe('the tool table is internally consistent', () => {
  test('no two tools share a title', () => {
    const seen = new Map<string, string>()
    const clashes: string[] = []
    for (const id of toolIds()) {
      const prior = seen.get(tools[id].title)
      if (prior) clashes.push(`"${tools[id].title}": ${prior} and ${id}`)
      else seen.set(tools[id].title, id)
    }
    expect(clashes).toEqual([])
  })

  test('an isolated wrapper only appears where a module does', () => {
    // The isolated wrapper is the actual fan-out call path. Claiming one with
    // no module to import it from is a link that resolves to nothing.
    const problems = toolIds()
      .filter(id => tools[id].isolated_fn && !tools[id].module)
      .map(id => `${id}: isolated_fn with no module`)
    expect(problems).toEqual([])
  })

  test('a graph writer only appears where a module does', () => {
    const problems = toolIds()
      .filter(id => tools[id].graph_writer && !tools[id].module)
      .map(id => `${id}: graph_writer with no module`)
    expect(problems).toEqual([])
  })

  test('every module path names the recon package', () => {
    const problems = toolIds()
      .filter(id => tools[id].module && !(tools[id].module as string).startsWith('recon.'))
      .map(id => `${id}: ${tools[id].module}`)
    expect(problems).toEqual([])
  })
})

// --- T9 and the preset apply-time rule ------------------------------------------------

describe('T9 every preset names fields the registry has', () => {
  test('no preset names a column that does not exist', () => {
    // A preset key with no column is silently stripped by the zod schema, so
    // the preset applies less than it says and reports success.
    const ghosts: string[] = []
    for (const preset of RECON_PRESETS) {
      for (const key of Object.keys(preset.parameters ?? {})) {
        if (!field(key)) ghosts.push(`${preset.id}/${key}`)
      }
    }
    expect(ghosts).toEqual([])
  })

  test('no preset sets the engagement scope', () => {
    // The apply-time rule, moved to build time where it cannot reach a user. A
    // preset that named a scope field would either be refused at apply (a
    // failure in front of an operator) or silently stripped (a preset that
    // applied less than it said). Neither is a good outcome; not shipping one
    // is.
    const problems: string[] = []
    for (const preset of RECON_PRESETS) {
      for (const key of Object.keys(preset.parameters ?? {})) {
        const spec = field(key)
        if (spec && spec.mcp === 'create_only') problems.push(`${preset.id}/${key}`)
      }
    }
    expect(problems, 'a preset may not point a project at a different target').toEqual([])
  })

  test('no preset changes the engagement\'s limits', () => {
    // This checked a `tighten_only` disposition the registry no longer has, so it
    // asserted nothing. The limits are the `engagement_limits` group now.
    const problems: string[] = []
    for (const preset of RECON_PRESETS) {
      for (const key of Object.keys(preset.parameters ?? {})) {
        const spec = field(key)
        if (spec && spec.group === 'engagement_limits') problems.push(`${preset.id}/${key}`)
      }
    }
    expect(problems, 'the engagement agreement is not a tuning choice').toEqual([])
  })

  test('no preset names a closed column', () => {
    const problems: string[] = []
    for (const preset of RECON_PRESETS) {
      for (const key of Object.keys(preset.parameters ?? {})) {
        const spec = field(key)
        if (spec && spec.mcp === 'never') problems.push(`${preset.id}/${key}`)
      }
    }
    expect(problems).toEqual([])
  })

  test('every preset sets something', () => {
    // A preset with no parameters applies nothing and says it applied.
    const empty = RECON_PRESETS.filter(p => Object.keys(p.parameters ?? {}).length === 0)
    expect(empty.map(p => p.id)).toEqual([])
  })

  test('a preset that claims to be quiet sets the rates that make it quiet', () => {
    // The trap the applicability field was invented for, checked from the other
    // side: "Stealth Recon" is only stealthy if it actually names the rate
    // limits, and those are settable now.
    const stealth = RECON_PRESETS.find(p => p.id === 'stealth-recon')
    expect(stealth, 'the stealth preset is gone or renamed').toBeDefined()
    const keys = Object.keys(stealth!.parameters ?? {})
    const rates = keys.filter(k => field(k)?.unit === 'rps')
    expect(rates.length, 'the stealth preset sets no rate limit at all').toBeGreaterThan(0)
  })
})
