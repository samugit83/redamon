/**
 * The operator-facing wording for each token scope.
 *
 * Shared by the token-minting UI and the generated MCP API reference, so the
 * checkbox a person ticks and the page that documents it cannot describe the
 * same permission two different ways.
 *
 * `blurb` is doing two jobs, so the fields are split by AUDIENCE:
 *
 *  - `blurb` is the shared, table-safe text. It becomes ONE MARKDOWN TABLE CELL
 *    in the generated API reference, so it stays to a sentence or two. Changing
 *    it changes `redamon.wiki/MCP-API-Reference.md`, which means `npm run
 *    docs:mcp` has to run in the same change or apiReference.test.ts goes red.
 *  - `access`, `detail` and `learnMore` are UI-only. The renderer never prints
 *    them, so adding or editing any of them needs no regeneration.
 */
import type { McpScope } from '@/lib/mcpAuth'

/**
 * What exercising a permission DOES to state, badged on every checkbox so the
 * question an operator actually has - "does ticking this let an agent change
 * something?" - is answered before the blurb is read.
 *
 * It is not editorial. scopeCopy.test.ts derives the same value from the live
 * tools' `readOnlyHint` and fails on a mismatch, so a scope that gains a
 * state-changing tool cannot go on advertising itself as read-only.
 */
export type ScopeAccess = 'read' | 'write' | 'read-write'

export interface ScopeCopy {
  label: string
  /** Table-safe. Printed by the generated API reference. Keep it short. */
  blurb: string
  /** Required, so a new scope cannot ship without saying what it touches. */
  access: ScopeAccess
  /** The longer UI paragraph, for a permission that needs a real explanation. */
  detail?: string
  /** A wiki deep link, UI-only. */
  learnMore?: { text: string; href: string }[]
}

const WIKI = 'https://github.com/samugit83/redamon/wiki'

/** Each write scope states its consequence, so a tick is an informed one. */
export const MCP_SCOPE_COPY: Record<McpScope, ScopeCopy> = {
  'recon:read': {
    label: 'Read recon + graph',
    access: 'read',
    blurb: 'List projects, read scan status and settings, and query the attack-surface graph in natural language.',
  },
  'recon:scan': {
    label: 'Start and stop scans',
    access: 'write',
    blurb: 'Start a full recon pipeline (keeping the current graph as a saved version) and stop the scan running on a project.',
  },
  'recon:overwrite': {
    label: 'Discard the current graph on start',
    access: 'write',
    blurb: 'Permits starting a scan in overwrite mode, which DISCARDS the current graph instead of saving it as a version. This is the only irreversible action on this surface.',
  },
  'recon:settings': {
    label: 'Change recon tuning settings',
    access: 'write',
    // Two of the four claims this blurb used to make became FALSE when the
    // recon settings registry replaced the allowlist, and one broke in the
    // direction that made the permission sound SAFER than it is. It said "a
    // narrow allowlist" (it is now most of the model) and "never any
    // credential" (graphqlAuthHeader and graphqlAuthValue are open, because
    // scanning an authenticated GraphQL endpoint needs them).
    blurb: 'Change any recon tuning value: per-tool enable flags, rate limits, threads, timeouts, depths, wordlists, templates, severity lists and which phases run, AND the engagement\'s own limits - its rate ceiling, its excluded hosts, its scanning window and the agent\'s denylists. Values are validated and capped at scan start rather than blocked, so the ceiling still wins over anything written here. It cannot point the project at a different target, touch the engagement record, or read a stored credential.',
    detail:
      'Every parameter of the recon pipeline is reachable, and each is controlled ' +
      'by a bound or a validator rather than by being refused by name.\n\n' +
      'Three dispositions decide what a token may write. Most fields are settable ' +
      'at any time, the engagement limits among them. The engagement scope (the ' +
      'target domain, the IP list, the domain batch and the target guardrail) is ' +
      'fixed at creation and is refused here by name. A named set is refused ' +
      'entirely: row identity, the version-activation lock, the Kali-exec flag, ' +
      'the stored CypherFix token, and the engagement RECORD - the client name, ' +
      'the contacts, the dates and the uploaded document.\n\n' +
      'The engagement limits move in EITHER direction here, and that is deliberate. ' +
      'What makes them safe is not a write-time direction rule but that each one is ' +
      'enforced at scan start whatever the setting says. A rate ceiling of 3 still ' +
      'caps every rate field it governs at 3; an excluded host is still dropped in three ' +
      'places. preflight_scope_check reports the resolved configuration, which is ' +
      'the check that actually holds.\n\n' +
      'Three validators are worth knowing about. A container image outside the ' +
      'shipped allowlist is accepted and then pinned back to the default at scan ' +
      'start, so get_recon_settings echoes what was written while the scan runs ' +
      'the safe one. A custom header may not carry CR, LF, Host, Authorization, ' +
      'Cookie or Proxy-*, each of which would change where the request goes ' +
      'rather than annotate it. A wordlist or template path must resolve inside ' +
      'this project\'s own upload directory; anything else is dropped to the ' +
      'shipped default at scan start with a guardrail line recording it.\n\n' +
      'One credential pair is open on purpose: graphqlAuthHeader and ' +
      'graphqlAuthValue are what an operator supplies to scan an authenticated ' +
      'GraphQL endpoint, so they are pipeline configuration. They are WRITE ONLY ' +
      'on this surface - no read tool returns the value.',
  },
  'triage:read': {
    label: 'Read suppressed findings, remediations and triage detail',
    access: 'read',
    blurb: 'Read the muted findings, whether a person muted them as noise or one of the project\'s Mute Rules did, including who or which rule muted them and why, and the remediation write-ups (their solutions, evidence summaries and PR status). Muted findings are hidden from every other permission on this surface, so this is the only way an agent can tell "nothing was found" apart from "someone suppressed it". Separate from Read recon + graph on purpose: these are not reachable any other way. It also reads, for any finding, the full breakdown behind its Priority Board score and the evidence a reviewer reads.',
  },
  'recon:queue': {
    label: 'Queue scans to run later',
    access: 'write',
    blurb: 'Queue a full recon to start when the machine has room, instead of being refused while the project is busy, and cancel a job it queued. A queued job DISPATCHES LATER and is not cancelled when you revoke this token - use the Activity view or the agent\'s own cancel to stop it. It also appears in your queue attributed to you, with nothing marking it as an agent\'s.',
  },
  'triage:write': {
    label: 'Record a verdict on a finding',
    access: 'write',
    blurb: 'Let an agent mark a finding Real (which raises its score) or a false positive, or reset a verdict it made, as if you had clicked it yourself. The verdict is DURABLE: it survives re-scans and outranks any AI or agent review, and the node records that it arrived over MCP. A verdict a person made in the app can never be changed or reset from here. A verdict only ranks a finding, it never hides one, and it is refused on a muted finding: on one a Mute Rule muted, a verdict would release the mute. Muting is a separate permission.',
  },
  'triage:mute': {
    label: 'Mute and unmute findings',
    access: 'write',
    blurb: 'Let an agent hide a finding as noise, or bring a muted one back, as if you had pressed Mute or Unmute yourself. A muted finding disappears from the graph, reports, the in-app agent and every other tool here, so an agent misled by target text could hide a real issue: every agent mute needs a reason, is marked as the agent\'s in Muted Nodes, and can be undone there. One call can mute up to 5,000 findings and there is no daily limit. It never hides a confirmed finding or one a person brought back.',
    detail:
      'A verdict ranks a finding; a mute HIDES it, from every read on this surface, the graph ' +
      'views, the reports and RedAmon\'s own agent. That is why this is its own permission, never ' +
      'ticked for you, and why it is bounded in code rather than by the tool\'s wording.\n\n' +
      'What is refused whatever the agent asks: a finding a person or the agent CONFIRMED, one ' +
      'carrying a proof or confirmed by an attack chain ("proven"); a finding a person brought back ' +
      'by unmuting it ("kept visible"); and changing a mute that already exists, whoever made it. A ' +
      'finding a Mute Rule muted is unmuted only when the agent explicitly asks for rule mutes, and ' +
      'never while a recon scan is running; each such unmute becomes a standing exception on the Mute ' +
      'Rules page. Anything refused because the project is busy (a version activation, a rules apply, ' +
      'a scan) is refused cleanly, with nothing half-written.\n\n' +
      'Every agent mute needs a reason. One call can mute or unmute up to 5,000 findings, and a ' +
      'token can make 200 such calls a minute (MCP_RATE_MUTE_PER_MIN). Nothing caps how many ' +
      'findings a token mutes in total, so what bounds an agent is your review in Muted Nodes. If ' +
      'the answer to a mute or unmute is lost in transit, the agent is told the outcome is UNKNOWN ' +
      'and to check before retrying, never that the service was unavailable.\n\n' +
      'Pair it with Read suppressed findings: an agent cannot find the id of a muted finding, and so ' +
      'cannot unmute one, without it. In Muted Nodes every agent mute is badged with the token that ' +
      'made it, and the Muted by and Token filters list one token\'s mutes together so you can ' +
      'review and unmute them in one go.',
    learnMore: [
      {
        text: 'Hiding and revealing findings over MCP',
        href: `${WIKI}/MCP-Server#mute_findings-and-unmute_findings-hiding-and-revealing-findings`,
      },
    ],
  },
  'triage:review': {
    label: 'Submit evidence reviews',
    access: 'write',
    blurb: 'Let an agent act as a second reviewer: it reads a finding\'s evidence and corrects the factors behind its score, quoting the evidence for every correction. RedAmon checks every quote and recomputes the score itself; the agent never sets a number. Its reviews are labelled as an agent\'s on the Priority Board, are replaced by a newer review or when the evidence changes, and never override a person\'s Real or False positive.',
  },
  'triage:run': {
    label: 'Start and stop triage runs',
    access: 'write',
    blurb: 'Let an agent re-rank the project: start a Priority Board run, or stop one before it publishes. A run rewrites the board\'s order and the CypherFix fix list, and its evidence review spends your configured model\'s budget. While it runs, version switching, Recon Delta and Mute Rules wait for it, so runs an agent starts are spaced out and capped per day.',
  },
  'graph:cypher': {
    label: 'Run raw Cypher',
    access: 'read',
    blurb: 'Send read-only Cypher directly instead of a natural-language question. Still tenant-scoped and still read-only.',
  },
  'project:create': {
    label: 'Create projects and set their engagement scope',
    access: 'write',
    blurb: 'Create a new project and fix what it points at: its targeting mode and its engagement kind, with its settings and limits applied at creation so the first scan runs configured. The target domain, the address list and the targeting mode are written ONCE and are immutable afterwards through every route on this surface, so this opens new engagements rather than re-pointing existing ones. It governs create_project alone.',
    detail:
      'This is the act that binds RedAmon to a target, which is why it is its own ' +
      'checkbox rather than part of changing settings. A token with recon:settings ' +
      'can tune the engagements you already have; a token with this one can open ' +
      'new ones.\n\n' +
      'What it can never do is re-point an existing project. The target domain, the ' +
      'address list, the targeting mode and the target guardrail are refused by name on ' +
      'a project that already exists, whatever permissions the token holds. A batch ' +
      'project\'s host list and the other scanners\' targets are the one exception, and ' +
      'they need a separate permission: Change an existing project\'s target lists.\n\n' +
      'It governs create_project and nothing else. An engagement\'s LIMITS - its rate ' +
      'ceiling, its excluded hosts, its scanning window, the agent\'s denylists - are ' +
      'ordinary settings afterwards, changed with recon:settings, and reachable from ' +
      'the project form by a person in exactly the same way. Recording what ' +
      'authorized an engagement is a separate permission again.',
  },
  'engagement:authorize': {
    label: 'Record what authorized an engagement',
    access: 'write',
    blurb: 'Attach the scope document that permits an engagement: its digest, its source and the program it came from. The record is APPEND-ONLY and outlives the token that wrote it, so anyone holding this can make a durable claim, in an audit, that a given document authorized a given scan. Separate from creating projects on purpose: writing the audit trail is a different act from configuring the work.',
    detail:
      'Only a DIGEST of the scope document is stored, never the document, so ' +
      'RedAmon never parses somebody\'s scope prose and the record works the same ' +
      'for a HackerOne policy, a Bugcrowd brief, a signed PDF or an internal ' +
      'ticket.\n\n' +
      'The record cannot be edited or deleted through any path, including this one. ' +
      'When a program changes its scope, a NEW record says the engagement continued ' +
      'under a new authority from that moment, which is what an incident review ' +
      'needs; a row that can be rewritten is not evidence.\n\n' +
      'It carries the id of the token that wrote it, so a revoked credential is ' +
      'still attributable afterwards.',
  },
  'preset:write': {
    label: 'Manage your recon preset library',
    access: 'write',
    blurb: 'Create, edit and delete your own recon presets: from explicit settings, as a copy of another preset, or captured from one of your projects. Every value is validated exactly as a settings change is, and a preset never carries a target, the engagement\'s limits or record, a credential or an upload. Built-in presets cannot be changed. A preset an agent wrote is badged as such in the preset drawer, because a person applies it later.',
    detail:
      'A preset is a stored instruction: whoever loads it into a project later gets its ' +
      'configuration, usually without reading all six hundred values. That is why writing ' +
      'the library is its own checkbox, apart from tuning a project you are looking at.\n\n' +
      'An agent cannot use a preset to reach anything a settings change could not: the same ' +
      'bounds, the same validators, and never the scope, the engagement\'s limits or record, a ' +
      'credential, an uploaded file or the MCP sandbox switch. Deleting a preset keeps its ' +
      'settings in the audit log, which is the only way back.',
  },
  'preset:apply': {
    label: 'Apply a recon preset to a project',
    access: 'write',
    blurb: 'Load a built-in preset or one of your own into a project, as the project form\'s Load preset does. It REPLACES the configuration: every preset field the preset does not name goes back to its default. It never touches the target, the engagement\'s limits, credentials or uploads, and it is refused while anything is reading or writing the project\'s graph.',
    detail:
      'Held together with Manage your recon preset library, this equals Change recon ' +
      'settings over every field a preset covers: an agent can write any preset values and ' +
      'then apply them. It is also a much larger write than one settings change - up to six ' +
      'hundred fields in one call, and it resets whatever the preset does not name - which ' +
      'is why it has its own checkbox.\n\n' +
      'A dry run lists every field that would change, and which of them only because the ' +
      'preset did not name them, before anything is written. The engagement\'s rate ceiling ' +
      'still caps every rate at scan start whatever a preset says.',
  },
  'project:rescope': {
    label: 'Change an existing project\'s target lists',
    access: 'write',
    blurb: 'Edit a domain-batch project\'s host list and re-point the standalone scanners (the GitHub hunt\'s organisation and repositories, the GVM target strategy, the supply-chain organisation and repository) on a project that already exists. The target domain, the IP list and the targeting mode stay locked for everyone. Widening a third-party engagement also needs Record what authorized an engagement.',
    detail:
      'Scope is otherwise fixed at creation for every token. This reopens eight target-list ' +
      'fields, the ones the project form already lets a person edit, and nothing else: the ' +
      'target domain, the address list, the targeting mode, ownership verification and the ' +
      'target guardrail stay refused whatever the token holds.\n\n' +
      'Every batch host, scan root and registrable domain runs the permanent guardrail, and on a ' +
      'third-party engagement any widening - a host or scan root the old list did not admit, a ' +
      'new GitHub organisation or repository, a new supply-chain ' +
      'organisation or repository - must arrive with a new authorization record.\n\n' +
      'Stated plainly: a token holding this AND Record what authorized an engagement can ' +
      'record an authorization for any document digest and widen with it. That claim is ' +
      'attributable to the token that wrote it, not verified.',
  },
  'agent:loop': {
    label: 'Drive the AI agent (Agent in the Loop)',
    access: 'write',
    blurb: 'Answer the reasoning steps of your Agent in the Loop chat sessions. RedAmon still runs every tool and asks you for every dangerous one. Hold it with read scopes only.',
  },
  'kali:exec': {
    label: 'Shell access to the Kali sandbox',
    access: 'read-write',
    blurb: 'Give the agent a SHELL in the Kali sandbox: `bash -c` with the full toolset, pipelines and redirection, no allowlist and no per-command target check. This is the most powerful permission on this surface and the only one that reaches a live target outside a scan.',
    // Leads with the decision the operator is actually making, because "does my
    // agent bring its own tools or borrow RedAmon's" is the real question and
    // everything else follows from it.
    //
    // It deliberately does NOT enumerate the toolset. That lives in the
    // kali_shell TOOL_REGISTRY description, which kali_toolbox serves; a list
    // copied into this string would be wrong within a release.
    detail:
      'Does your agent already have security tools installed where it runs, or should it borrow ' +
      'RedAmon\'s? With this on, your agent runs commands inside RedAmon\'s Kali sandbox instead of ' +
      'on its own machine, so it needs nothing installed locally. It is the SAME access the in-app ' +
      'agent has: a real shell, the sandbox\'s whole toolset, and no allowlist. Unlike the in-app ' +
      'agent there is no human clicking a confirmation, and commands are NOT checked against this ' +
      'project\'s scope, so an agent you grant this to can reach any host the sandbox can. It is ' +
      'ticked by default: untick it for any agent you would not trust with a terminal on that box. ' +
      'It is not sufficient on its own: the deployment switch and the project\'s "Allow MCP Sandbox ' +
      'Commands" toggle must also be on, and both are by default.',
    learnMore: [
      { text: 'What the sandbox carries', href: `${WIKI}/MCP-Server#kali_toolbox-what-the-sandbox-carries` },
      { text: 'What a shell here means', href: `${WIKI}/MCP-Server#kali_exec-a-shell-in-the-sandbox` },
    ],
  },
}

/**
 * How the checkboxes are GROUPED in the token form.
 *
 * `MCP_SCOPES` is not reordered to achieve this, and must not be: that array is
 * the enforcement list, its per-scope comments carry the security rationale, and
 * its order also drives the generated API reference's permission table. This is
 * a presentation structure beside the copy.
 *
 * With a profile now ticking boxes on the operator's behalf, the list has to be
 * readable at a glance: a flat list of nine, where reading, scanning and writing
 * interleave and the one permission that reaches a live target looks like the
 * eight above it, is not.
 *
 * `tone` drives the visual treatment. Rows inside a group look alike: what a
 * given permission touches is carried by its `access` badge, not by tinting the
 * heavier rows red, which asked an operator to decode two colour scales at once.
 * `exec` stays a tier apart because a shell on a target-facing box is a
 * different KIND of permission, not a louder one.
 */
export interface ScopeGroup {
  id: string
  label: string
  /** One line saying what the whole group is, so a profile's ticks read as a shape. */
  hint: string
  tone: 'neutral' | 'action' | 'exec'
  scopes: McpScope[]
}

export const SCOPE_GROUPS: ScopeGroup[] = [
  {
    id: 'read',
    label: 'Read and query',
    hint: 'Nothing here changes any state.',
    tone: 'neutral',
    scopes: ['recon:read', 'triage:read', 'graph:cypher'],
  },
  {
    id: 'scan',
    label: 'Run scans and triage',
    hint: 'Start work that writes the attack-surface graph.',
    tone: 'action',
    scopes: ['recon:scan', 'recon:queue', 'recon:overwrite', 'triage:run'],
  },
  {
    id: 'write',
    label: 'Change settings and findings',
    hint: 'Writes that are not scans.',
    tone: 'action',
    scopes: ['recon:settings', 'triage:write', 'triage:mute', 'triage:review', 'preset:write', 'preset:apply'],
  },
  {
    id: 'engagement',
    label: 'Open and authorize engagements',
    hint: 'Binds RedAmon to a target, and records who said it could.',
    tone: 'action',
    scopes: ['project:create', 'engagement:authorize', 'project:rescope'],
  },
  {
    id: 'loop',
    label: 'Agent in the Loop',
    hint: 'Your own Claude Code or Codex answers the AI agent\'s reasoning steps. Hold it with read scopes only.',
    tone: 'action',
    scopes: ['agent:loop'],
  },
  {
    id: 'exec',
    label: 'Shell access to the sandbox',
    hint: 'A real shell on a target-facing box. Nothing checks what it is aimed at.',
    tone: 'exec',
    scopes: ['kali:exec'],
  },
]
