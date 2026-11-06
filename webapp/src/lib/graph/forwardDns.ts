/**
 * Current forward DNS in the graph: a RESOLVES_TO edge with no `source`.
 *
 * Every passive writer (Shodan's reverse and domain DNS, Censys, FOFA, OTX
 * passive DNS, ZoomEye) stamps a source when it creates the edge, and a DNS
 * resolution of the pair removes it, so "no source" is what a name resolves to
 * now. An old address may belong to someone else today. Mirrors FORWARD_DNS in
 * recon/partial_recon_modules/graph_builders.py. A raw-graph view (the graph
 * page's clustering) keeps every edge and does not use this.
 */
export const currentDns = (rel: string) => `${rel}.source IS NULL`
