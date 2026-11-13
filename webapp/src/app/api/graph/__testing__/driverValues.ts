/**
 * Graph values as the neo4j driver hands them to formatGraphRecords: real `Node`, `Relationship`
 * and `Path` instances, which are the only values format.ts reads as graph objects, and a record
 * with `keys` and `get`. A plain object with the same keys is what the driver returns for a map
 * the query built, so a test that wants a node must build it here.
 */
import { Node, Path, PathSegment, Relationship, int } from 'neo4j-driver'

export function driverNode(id: number, labels: string[], properties: Record<string, unknown> = {}): Node {
  return new Node(int(id), labels, properties, String(id))
}

export function driverRel(id: number, start: number, end: number, type: string, properties: Record<string, unknown> = {}): Relationship {
  return new Relationship(int(id), int(start), int(end), type, properties, String(id), String(start), String(end))
}

/** A path from `start` through each [relationship, next node] hop, as the driver builds one. */
export function driverPath(start: Node, hops: Array<[Relationship, Node]>): Path {
  let from = start
  const segments = hops.map(([rel, to]) => {
    const segment = new PathSegment(from, rel, to)
    from = to
    return segment
  })
  return new Path(start, from, segments)
}

export function driverRecord(fields: Record<string, unknown>): { keys: string[]; get: (key: string) => unknown } {
  return { keys: Object.keys(fields), get: (key: string) => fields[key] }
}
