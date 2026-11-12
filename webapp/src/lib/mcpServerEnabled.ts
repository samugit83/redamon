/**
 * The inbound MCP server's switch (/api/mcp-server), read by the route and by the capability
 * resolution, which caps `self:mcp_tokens` while it is off (authz/capabilities.ts). Here, not in
 * the route file, so a reader does not import the whole MCP server with it.
 */
export function mcpServerEnabled(): boolean {
  // Default OFF. A new authenticated inbound surface must be switched on
  // deliberately, not inherited by upgrading.
  return process.env.MCP_SERVER_ENABLED === 'true' || process.env.MCP_SERVER_ENABLED === '1'
}
