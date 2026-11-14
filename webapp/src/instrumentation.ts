// Next.js calls register() once as each runtime boots. The Node.js runtime reads the RBAC
// switches here so a misconfigured one is logged at boot, not at the first request that
// reaches a Node.js route; the edge middleware never logs them (src/lib/authz/flags.ts).
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return
  const { rbacFlags } = await import('./lib/authz/flags')
  rbacFlags()
}
