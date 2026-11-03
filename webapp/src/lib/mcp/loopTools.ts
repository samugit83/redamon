/**
 * The Agent in the Loop MCP tools: a driver (Claude Code, Codex, any MCP client)
 * waits for, reads and answers the model-call steps of its user's chat runs.
 *
 * The driver only answers steps. RedAmon runs every tool, applies every gate,
 * and a person in the UI answers every approval, question and dangerous-tool
 * confirmation: no tool here can.
 *
 * Order in each body: requireScope, the switch, the DB read of the user's owned
 * loop projects, the token rule, argument checks, the rate bucket, the agent call.
 * Those project ids go to the agent, whose broker serves only steps of those
 * projects (a deleted or transferred project's steps never reach a driver).
 */
import prisma from '@/lib/prisma'
import { requireScope } from '@/lib/mcpAuth'
import { LOOP_PREFIX, agentInTheLoopEnabled, isLoopModel } from '@/lib/agentInTheLoop'
import { McpToolError } from './errors'
import { enforceRate, type McpContext } from './tools'
import {
  loopAnswer, loopGet, loopWait,
  type LoopAnswerResult, type LoopStepView, type LoopWaitResult,
} from './loopClient'
import { loopTokenProblem } from './loopScopes'

/** Mirrors the agent's LOOP_ANSWER_MAX_CHARS default; the agent re-checks its own. */
export const LOOP_ANSWER_MAX_CHARS = 262_144
export const LOOP_WAIT_DEFAULT_S = 50
/** The agent refuses a longer project list (MAX_PROJECT_IDS in agent_in_the_loop/routes.py). */
export const MAX_LOOP_PROJECT_IDS = 2000
const STEP_ID_RE = /^[0-9a-f]{32}$/

const NO_LOOP_PROJECT_HINT =
  'No project of yours uses Agent in the Loop. A person picks it as the agent model in the ' +
  'project form.'

function assertLoopEnabled(): void {
  if (!agentInTheLoopEnabled()) {
    throw new McpToolError(
      'Agent in the Loop is turned off on this RedAmon deployment. An operator enables it ' +
      'with AGENT_IN_THE_LOOP_ENABLED=true.',
      'disabled'
    )
  }
}

/**
 * The user's owned projects NOW that a loop run can be in: on a loop model, or with
 * a chat running (a project switched to another model mid-run still serves its
 * open step). Ownership is the filter; the narrow list keeps a user with thousands
 * of projects under the agent's limit.
 */
async function ownedProjects(userId: string): Promise<{ ids: string[]; anyLoop: boolean }> {
  const rows = await prisma.project.findMany({
    where: {
      userId,
      OR: [
        { agentOpenaiModel: { startsWith: LOOP_PREFIX } },
        { conversations: { some: { agentRunning: true } } },
      ],
    },
    select: { id: true, agentOpenaiModel: true },
    take: MAX_LOOP_PROJECT_IDS + 1,
  })
  if (rows.length > MAX_LOOP_PROJECT_IDS) {
    throw new McpToolError(
      `More than ${MAX_LOOP_PROJECT_IDS} of your projects use Agent in the Loop or have a chat ` +
      'running. Switch some of them to another agent model.',
      'too_many_loop_projects'
    )
  }
  return { ids: rows.map((r) => r.id), anyLoop: rows.some((r) => isLoopModel(r.agentOpenaiModel)) }
}

function assertNarrowToken(ctx: McpContext): void {
  const extra = loopTokenProblem(ctx.token.scopes)
  if (extra.length > 0) {
    throw new McpToolError(
      `This token can also ${extra.join(', ')}. A token that drives Agent in the Loop must ` +
      'hold no other write or exec scope: mint one with agent:loop and read scopes only.',
      'loop_token_too_broad'
    )
  }
}

/** Shared preamble: scope, switch, owned projects, token rule. */
async function prepare(ctx: McpContext): Promise<{ ids: string[]; anyLoop: boolean }> {
  requireScope(ctx.token, 'agent:loop')
  assertLoopEnabled()
  const owned = await ownedProjects(ctx.token.userId)
  assertNarrowToken(ctx)
  return owned
}

function identity(ctx: McpContext, projectIds: string[], driver?: string) {
  return { userId: ctx.token.userId, driverId: ctx.token.tokenId, driverName: driver, projectIds }
}

export interface LoopWaitInput {
  sessionId?: string
  driver?: string
  waitSeconds?: number
  delivery?: 'dedup' | 'full'
}

export async function loopWaitStep(ctx: McpContext, input: LoopWaitInput): Promise<LoopWaitResult> {
  const owned = await prepare(ctx)
  if (input.sessionId) {
    const conversation = await prisma.conversation.findFirst({
      where: { sessionId: input.sessionId, userId: ctx.token.userId },
      select: { id: true },
    })
    if (!conversation) throw new McpToolError('Session not found', 'not_found')
  }
  if (owned.ids.length === 0) {
    return { step: null, sessions: [], hint: NO_LOOP_PROJECT_HINT }
  }
  enforceRate(ctx, 'loop')
  const result = await loopWait({
    ...identity(ctx, owned.ids, input.driver),
    sessionId: input.sessionId,
    waitSeconds: input.waitSeconds ?? LOOP_WAIT_DEFAULT_S,
    // Without a client name there is no dedup state to key, so never placeholders.
    delivery: input.driver ? (input.delivery ?? 'dedup') : 'full',
  })
  // An open step of a project switched away mid-turn is still served, so the
  // hint is only for the case where nothing at all came back.
  if (!result.step && result.sessions.length === 0 && !owned.anyLoop) {
    return { ...result, hint: NO_LOOP_PROJECT_HINT }
  }
  return result
}

export interface LoopGetInput {
  stepId: string
  driver?: string
  cursor?: number
  full?: boolean
}

export async function loopGetStep(ctx: McpContext, input: LoopGetInput): Promise<{ step: LoopStepView }> {
  const owned = await prepare(ctx)
  if (!STEP_ID_RE.test(input.stepId) || owned.ids.length === 0) {
    throw new McpToolError('No such step is open for you. Call loop_wait_step for the next one.', 'not_found')
  }
  enforceRate(ctx, 'loop')
  return loopGet({
    ...identity(ctx, owned.ids, input.driver),
    stepId: input.stepId,
    cursor: input.cursor ?? 0,
    full: input.full ?? false,
  })
}

export interface LoopSubmitInput {
  stepId: string
  answer?: string
  declined?: boolean
  reason?: string
  driver?: string
}

export async function loopSubmitStep(
  ctx: McpContext, input: LoopSubmitInput
): Promise<LoopAnswerResult & { stepId: string }> {
  const owned = await prepare(ctx)
  const declined = input.declined === true
  if (declined === (input.answer !== undefined) || (!declined && !input.answer?.trim())) {
    throw new McpToolError(
      'Send exactly one of answer (the text the step asks for) or declined: true.',
      'bad_args'
    )
  }
  if ((input.answer?.length ?? 0) > LOOP_ANSWER_MAX_CHARS) {
    throw new McpToolError('The answer is larger than this RedAmon deployment accepts.', 'answer_too_large')
  }
  if ((input.reason?.length ?? 0) > 300) {
    throw new McpToolError('Keep the reason to 300 characters.', 'bad_args')
  }
  if (!STEP_ID_RE.test(input.stepId) || owned.ids.length === 0) {
    throw new McpToolError(
      'This step is already answered, expired or cancelled. Call loop_wait_step for the next one.',
      'step_closed'
    )
  }
  enforceRate(ctx, 'loop')
  const result = await loopAnswer({
    ...identity(ctx, owned.ids, input.driver),
    stepId: input.stepId,
    ...(declined ? { declined: true, reason: input.reason ?? '' } : { answer: input.answer }),
    // Display prefix and name only, never the token, so the chat history can
    // say which token supplied each decision.
    answeredBy: { tokenPrefix: ctx.token.tokenPrefix, tokenName: ctx.token.name },
  })
  return { ...result, stepId: input.stepId }
}
