/** scheme://host[:port]/path: no userinfo, query or fragment (the agent's redact_url). */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url)
    return `${u.protocol}//${u.host.toLowerCase()}${u.pathname}`
  } catch {
    return '<unparseable url>'
  }
}
