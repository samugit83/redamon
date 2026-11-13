/**
 * The MCP exec tools: kali_exec, kali_output, kali_cancel.
 *
 * kali_exec is a SHELL: it hands the command verbatim to `kali_shell`, which is
 * `bash -c` on the sandbox. No allowlist, no per-command target check, at
 * deliberate parity with RedAmon's in-app agent - which has no per-command
 * admission either (its RoE gate matches tool NAMES and never reads a command).
 *
 * So nothing in this file inspects or rewrites the command, and that is the
 * whole point: what stands between a token and a shell is not a check on the
 * command, it is WHO CAN REACH THIS AT ALL.
 *
 *  - THREE independent switches, all of which must be on, each owned by a
 *    different decision-maker:
 *      1. MCP_KALI_EXEC_ENABLED  - the operator, once per deployment. Default on.
 *      2. the `kali:exec` scope  - the user, password-confirmed at mint time.
 *         Ticked by default, so unticking it is what keeps a token off the shell.
 *      3. project.mcpKaliExecEnabled - a human in the project form, per
 *         engagement. Default on. DENIED to update_recon_settings by name
 *         (reason 'escalation'), so a token can never grant itself this.
 *  - THE COMMAND IS AUDITED VERBATIM. With no refusal path left, the audit row
 *    is the ONLY record of what an agent did with the shell, which makes it
 *    more load-bearing than it was, not less.
 *
 * Inside the product `kali_shell` is gated by a human clicking through the
 * DANGEROUS_TOOLS confirmation. An MCP caller has no human and nothing replaces
 * that, which is why each switch can still be turned off independently.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { assertMcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { kaliExec, kaliJobCancel, kaliJobStatus, type KaliJob } from '@/lib/mcp/kaliClient'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

/**
 * The default-on lives in docker-compose.yml (`:-true`), not here: an unset
 * variable reads as OFF, so a bare `node` run or a test without the env gets no
 * sandbox.
 *
 * Off, buildMcpServer does not register the sandbox tools at all
 * (SANDBOX_TOOL_NAMES). assertEnabled() below is the backstop for a direct call.
 */
export function kaliExecEnabled(): boolean {
  return process.env.MCP_KALI_EXEC_ENABLED === 'true' || process.env.MCP_KALI_EXEC_ENABLED === '1'
}

function assertEnabled(): void {
  if (!kaliExecEnabled()) {
    throw new McpToolError(
      'Sandbox commands are disabled on this RedAmon deployment. An operator enables them ' +
      'with MCP_KALI_EXEC_ENABLED=true.',
      'disabled'
    )
  }
}

/**
 * The per-project half of the switch, set by a human in the project form.
 *
 * `mcpKaliExecEnabled` is DENIED to update_recon_settings by name (reason
 * 'escalation'), so a token can never turn on its own ability to run commands.
 * That is the whole point of it being a column rather than another scope: the
 * deployment switch is one operator decision for the whole install, and this is
 * a per-engagement one.
 *
 * Fails CLOSED on a missing row: a project that cannot be read is not a project
 * that opted in.
 */
async function assertProjectOptedIn(projectId: string): Promise<void> {
  const row = await prisma.project.findUnique({
    where: { id: projectId },
    select: { mcpKaliExecEnabled: true },
  })
  if (!row?.mcpKaliExecEnabled) {
    throw new McpToolError(
      'Sandbox commands are not enabled for this project. Turn on "Allow MCP sandbox commands" ' +
      'in the project settings first. A token cannot enable it.',
      'project_opt_out'
    )
  }
}

const MAX_COMMAND_CHARS = 2000

/** Mirrors the agent's KALI_EXEC_MAX_WAIT so the advertised bound is the real one. */
const MAX_WAIT_SECONDS = 60

function auditExec(
  ctx: McpContext,
  projectId: string,
  action: string,
  after: Record<string, unknown>
): void {
  void writeAudit({
    actorId: ctx.token.userId,
    action,
    targetType: 'project',
    targetId: projectId,
    after: { tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix, ...after },
    source: 'mcp',
  })
}

/** The wire shape, with the note a caller needs to act on an unfinished job. */
function jobResult(projectId: string, job: KaliJob): Record<string, unknown> {
  const running = job.status === 'running'
  const timedOut = !running && /timed out/i.test(job.failure ?? '')
  return {
    projectId,
    jobId: job.jobId,
    status: job.status,
    exitCode: job.exitCode,
    output: job.output,
    // Always returned, so resuming never depends on the caller counting bytes.
    nextCursor: job.nextCursor,
    ...(job.truncated ? { truncated: true } : {}),
    ...(job.command ? { command: job.command } : {}),
    ...(job.failure ? { failure: job.failure } : {}),
    note: running
      ? 'Still running. Call kali_output with this jobId and nextCursor for more, or ' +
        'kali_cancel to stop it.'
      : timedOut
        // The single most common failure for real scanning work, and the one an
        // agent can actually do something about. Saying only "it failed" sends
        // it round the retry loop running the same too-broad command again.
        ? 'The sandbox caps one command at 300 seconds and this run hit it. Whatever it ' +
          'printed before the cap is in output, but the run is INCOMPLETE - do not report ' +
          'it as clean. Split the work: fewer nuclei -tags or -severity values, a smaller ' +
          'nmap port range, testssl --fast, or nikto -maxtime under 300.'
      : job.truncated
        ? 'Output continues. Call kali_output with this jobId and nextCursor for the rest.'
        : 'Finished. A non-zero exitCode is the TOOL failing, not RedAmon refusing.',
  }
}

export async function execCommand(
  ctx: McpContext,
  projectId: string,
  command: string,
  waitSeconds?: number
) {
  requireScope(ctx.token, 'kali:exec')
  assertEnabled()
  await assertMcpProjectAccess(ctx.token, projectId)
  await assertProjectOptedIn(projectId)

  const trimmed = typeof command === 'string' ? command.trim() : ''
  if (!trimmed) throw new McpToolError('A command is required.', 'bad_args')
  // Checked here as well as in the guard so an oversized body is refused before
  // it is written to an audit row.
  if (trimmed.length > MAX_COMMAND_CHARS) {
    throw new McpToolError(
      `The command is longer than ${MAX_COMMAND_CHARS} characters.`,
      'bad_args'
    )
  }
  if (waitSeconds !== undefined && (!Number.isFinite(waitSeconds) || waitSeconds < 0)) {
    throw new McpToolError('waitSeconds must be a positive number.', 'bad_args')
  }

  enforceRate(ctx, 'exec')

  let job: KaliJob
  try {
    job = await kaliExec(projectId, trimmed, waitSeconds)
  } catch (err) {
    // Audited BEFORE rethrowing: a refusal is the only record that someone
    // tried to reach outside their scope, and it is the more interesting half.
    auditExec(ctx, projectId, 'mcp.kali_exec.refused', {
      command: trimmed,
      reason: err instanceof McpToolError ? (err.code ?? 'error') : 'error',
    })
    throw err
  }

  auditExec(ctx, projectId, 'mcp.kali_exec', {
    // The admitted, re-quoted form: what actually ran, not what was typed.
    command: job.command ?? trimmed,
    jobId: job.jobId,
    status: job.status,
  })
  return jobResult(projectId, job)
}

export async function readCommandOutput(
  ctx: McpContext,
  projectId: string,
  jobId: string,
  cursor?: number
) {
  requireScope(ctx.token, 'kali:exec')
  assertEnabled()
  await assertMcpProjectAccess(ctx.token, projectId)
  await assertProjectOptedIn(projectId)
  if (!jobId) throw new McpToolError('A jobId is required.', 'bad_args')
  if (cursor !== undefined && (!Number.isInteger(cursor) || cursor < 0)) {
    throw new McpToolError('cursor must be a whole number of bytes, or omitted.', 'bad_args')
  }
  // The cheap bucket: polling a slow command must not consume the exec budget,
  // or watching one command would cost the same as starting another.
  enforceRate(ctx, 'read')

  return jobResult(projectId, await kaliJobStatus(projectId, jobId, cursor ?? 0))
}

export async function cancelCommand(ctx: McpContext, projectId: string, jobId: string) {
  requireScope(ctx.token, 'kali:exec')
  assertEnabled()
  await assertMcpProjectAccess(ctx.token, projectId)
  await assertProjectOptedIn(projectId)
  if (!jobId) throw new McpToolError('A jobId is required.', 'bad_args')
  enforceRate(ctx, 'write')

  const job = await kaliJobCancel(projectId, jobId)
  auditExec(ctx, projectId, 'mcp.kali_cancel', { jobId, status: job.status })
  return jobResult(projectId, job)
}

export { MAX_COMMAND_CHARS, MAX_WAIT_SECONDS }
