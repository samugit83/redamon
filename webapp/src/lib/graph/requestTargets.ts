/**
 * Cypher fragments shared by every webapp reader that counts or lists what a
 * recon tool will request. They mirror the partial-recon graph builders
 * (recon/partial_recon_modules/graph_builders.py), so a count never promises a
 * target the tool then skips.
 */

/**
 * True for an Endpoint a tool may request: not quarantined. A quarantined
 * Endpoint's archived URL carried a leaked one-time link, a secret or a
 * web-shell trace (recon/helpers/url_leaks.py); it is never requested.
 */
export const notQuarantined = (alias = 'e') => `NOT coalesce(${alias}.quarantined, false)`
