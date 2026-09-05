import {
  DERIVATION_VERSION,
  DOMAIN_EVIDENCE,
  DOMAIN_GRAPH,
  DOMAIN_NODE,
  DOMAIN_VERIFICATION,
  DOMAIN_VIRTUAL_NODE,
  PROTOCOL_VERSION,
  SCHEMA_VERSION,
} from "./protocol.ts";
import { bufferToHex } from "./component_hasher.ts";

export enum NodeKind {
  Root = "Root",
  RealComponent = "RealComponent",
  Virtual = "Virtual",
}

export interface GraphNode {
  id: string;
  node_kind: NodeKind;
  component_type: string;
  component_hash: string;
  node_commitment: string;
  schema_version: number;
}

export interface GraphEdge {
  source: string;
  relation: string;
  target: string;
}

export interface VirtualNode {
  id: string;
  virtual_type: string;
  derivation_version: number;
  input_commitments: string[];
  virtual_hash: string;
  attributes: Record<string, string>;
}

export interface VirtualPoint {
  id: string;
  value: number; // Integer (e.g. 9800)
  scale: number; // Integer scale (e.g. 10000)
  derivation_version: number;
}

export interface DeviceEvidenceGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  virtual_nodes: VirtualNode[];
  virtual_points: VirtualPoint[];
  evidence_root: string;
  graph_hash: string;
  verification_hash: string;
  graph_version: number;
  schema_version: number;
  derivation_version: number;
}

/**
 * Computes Tier 2 Node Commitment:
 * SHA-512(DOMAIN_NODE || 0x00 || SCHEMA_VERSION (4-byte BE) || 0x00 || TYPE || 0x00 || ID || 0x00 || COMPONENT_HASH)
 */
export async function computeNodeCommitment(
  schemaVersion: number,
  nodeType: string,
  canonicalId: string,
  componentHash: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(DOMAIN_NODE);
  const typeBytes = encoder.encode(nodeType);
  const idBytes = encoder.encode(canonicalId);
  const hashBytes = encoder.encode(componentHash);

  const versionBytes = new Uint8Array(4);
  new DataView(versionBytes.buffer).setUint32(0, schemaVersion, false);

  const delim = new Uint8Array([0x00]);

  const totalLen =
    domainBytes.length + 1 +
    versionBytes.length + 1 +
    typeBytes.length + 1 +
    idBytes.length + 1 +
    hashBytes.length;

  const payload = new Uint8Array(totalLen);
  let offset = 0;

  payload.set(domainBytes, offset);
  offset += domainBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(versionBytes, offset);
  offset += versionBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(typeBytes, offset);
  offset += typeBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(idBytes, offset);
  offset += idBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(hashBytes, offset);

  const digest = await crypto.subtle.digest("SHA-512", payload);
  return bufferToHex(digest);
}

/**
 * Computes Tier 3 Virtual Node Hash:
 * SHA-512(DOMAIN_VNODE || 0x00 || DERIVATION_VERSION || 0x00 || TYPE || 0x00 || COMMITMENTS... || 0x00 || ATTRS)
 */
export async function computeVirtualNodeHash(
  derivationVersion: number,
  virtualType: string,
  sortedInputCommitments: string[],
  canonicalVattrs: Uint8Array,
): Promise<string> {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(DOMAIN_VIRTUAL_NODE);
  const typeBytes = encoder.encode(virtualType);

  const versionBytes = new Uint8Array(4);
  new DataView(versionBytes.buffer).setUint32(0, derivationVersion, false);

  const delim = new Uint8Array([0x00]);
  const unitSep = new Uint8Array([0x1f]);

  let commitBytesLen = 0;
  const commitByteArrays: Uint8Array[] = [];
  for (const c of sortedInputCommitments) {
    const b = encoder.encode(c);
    commitByteArrays.push(b);
    commitBytesLen += b.length + 1; // unit sep
  }

  const totalLen =
    domainBytes.length + 1 +
    versionBytes.length + 1 +
    typeBytes.length + 1 +
    commitBytesLen +
    1 + // delim
    canonicalVattrs.length;

  const payload = new Uint8Array(totalLen);
  let offset = 0;

  payload.set(domainBytes, offset);
  offset += domainBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(versionBytes, offset);
  offset += versionBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(typeBytes, offset);
  offset += typeBytes.length;
  payload.set(delim, offset);
  offset += 1;

  for (const b of commitByteArrays) {
    payload.set(b, offset);
    offset += b.length;
    payload.set(unitSep, offset);
    offset += 1;
  }

  payload.set(delim, offset);
  offset += 1;

  payload.set(canonicalVattrs, offset);

  const digest = await crypto.subtle.digest("SHA-512", payload);
  return bufferToHex(digest);
}

/**
 * Computes Tier 4 Evidence Root from Virtual Nodes and Virtual Points
 */
export async function computeEvidenceRoot(
  derivationVersion: number,
  virtualNodes: VirtualNode[],
  virtualPoints: VirtualPoint[],
): Promise<string> {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(DOMAIN_EVIDENCE);

  const versionBytes = new Uint8Array(4);
  new DataView(versionBytes.buffer).setUint32(0, derivationVersion, false);

  const delim = new Uint8Array([0x00]);

  // Sort virtual nodes by id ASC
  const sortedVnodes = [...virtualNodes].sort((a, b) => a.id.localeCompare(b.id));
  let vnodesText = "";
  for (const v of sortedVnodes) {
    vnodesText += `${v.id}=${v.virtual_hash}\n`;
  }
  const vnodesBytes = encoder.encode(vnodesText);

  // Sort virtual points by id ASC
  const sortedPoints = [...virtualPoints].sort((a, b) => a.id.localeCompare(b.id));
  let pointsText = "";
  for (const p of sortedPoints) {
    pointsText += `id=${p.id}|val=${p.value}|scale=${p.scale}\n`;
  }
  const pointsBytes = encoder.encode(pointsText);

  const totalLen =
    domainBytes.length + 1 +
    versionBytes.length + 1 +
    vnodesBytes.length +
    1 + // delim
    pointsBytes.length;

  const payload = new Uint8Array(totalLen);
  let offset = 0;

  payload.set(domainBytes, offset);
  offset += domainBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(versionBytes, offset);
  offset += versionBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(vnodesBytes, offset);
  offset += vnodesBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(pointsBytes, offset);

  const digest = await crypto.subtle.digest("SHA-512", payload);
  return bufferToHex(digest);
}

/**
 * Encodes Canonical Evidence Graph byte stream
 */
export function encodeCanonicalEvidenceGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  virtualNodes: VirtualNode[],
): Uint8Array {
  const encoder = new TextEncoder();

  // Sort nodes by component_type ASC then id ASC
  const sortedNodes = [...nodes].sort((a, b) => {
    const cmp = a.component_type.localeCompare(b.component_type);
    return cmp !== 0 ? cmp : a.id.localeCompare(b.id);
  });

  // Sort edges by source ASC then relation ASC then target ASC
  const sortedEdges = [...edges].sort((a, b) => {
    const c1 = a.source.localeCompare(b.source);
    if (c1 !== 0) return c1;
    const c2 = a.relation.localeCompare(b.relation);
    return c2 !== 0 ? c2 : a.target.localeCompare(b.target);
  });

  // Sort virtual nodes by id ASC
  const sortedVnodes = [...virtualNodes].sort((a, b) => a.id.localeCompare(b.id));

  let text = "NODES:\n";
  for (const n of sortedNodes) {
    text += `type=${n.component_type}|id=${n.id}|hash=${n.component_hash}|commit=${n.node_commitment}\n`;
  }

  text += "EDGES:\n";
  for (const e of sortedEdges) {
    text += `src=${e.source}|rel=${e.relation}|dst=${e.target}\n`;
  }

  text += "VNODES:\n";
  for (const v of sortedVnodes) {
    text += `type=${v.virtual_type}|id=${v.id}|vhash=${v.virtual_hash}\n`;
  }

  return encoder.encode(text);
}

/**
 * Computes Tier 5 Graph Hash:
 * SHA-512(DOMAIN_GRAPH || 0x00 || PROTOCOL_VERSION || 0x00 || SCHEMA_VERSION || 0x00 || GRAPH_VERSION || 0x00 || CANONICAL_BYTES)
 */
export async function computeGraphHash(
  protocolVersion: number,
  graphVersion: number,
  schemaVersion: number,
  canonicalGraphBytes: Uint8Array,
): Promise<string> {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(DOMAIN_GRAPH);

  const pvBytes = new Uint8Array(4);
  new DataView(pvBytes.buffer).setUint32(0, protocolVersion, false);

  const svBytes = new Uint8Array(4);
  new DataView(svBytes.buffer).setUint32(0, schemaVersion, false);

  const gvBytes = new Uint8Array(4);
  new DataView(gvBytes.buffer).setUint32(0, graphVersion, false);

  const delim = new Uint8Array([0x00]);

  const totalLen =
    domainBytes.length + 1 +
    pvBytes.length + 1 +
    svBytes.length + 1 +
    gvBytes.length + 1 +
    canonicalGraphBytes.length;

  const payload = new Uint8Array(totalLen);
  let offset = 0;

  payload.set(domainBytes, offset);
  offset += domainBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(pvBytes, offset);
  offset += pvBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(svBytes, offset);
  offset += svBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(gvBytes, offset);
  offset += gvBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(canonicalGraphBytes, offset);

  const digest = await crypto.subtle.digest("SHA-512", payload);
  return bufferToHex(digest);
}

/**
 * Computes Tier 5 Verification Hash:
 * SHA-512(DOMAIN_VERIFICATION || 0x00 || PROTOCOL_VERSION || 0x00 || GRAPH_VERSION || 0x00 || GRAPH_HASH || 0x00 || EVIDENCE_ROOT)
 */
export async function computeVerificationHash(
  protocolVersion: number,
  graphVersion: number,
  graphHash: string,
  evidenceRoot: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(DOMAIN_VERIFICATION);
  const ghBytes = encoder.encode(graphHash);
  const erBytes = encoder.encode(evidenceRoot);

  const pvBytes = new Uint8Array(4);
  new DataView(pvBytes.buffer).setUint32(0, protocolVersion, false);

  const gvBytes = new Uint8Array(4);
  new DataView(gvBytes.buffer).setUint32(0, graphVersion, false);

  const delim = new Uint8Array([0x00]);

  const totalLen =
    domainBytes.length + 1 +
    pvBytes.length + 1 +
    gvBytes.length + 1 +
    ghBytes.length + 1 +
    erBytes.length;

  const payload = new Uint8Array(totalLen);
  let offset = 0;

  payload.set(domainBytes, offset);
  offset += domainBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(pvBytes, offset);
  offset += pvBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(gvBytes, offset);
  offset += gvBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(ghBytes, offset);
  offset += ghBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(erBytes, offset);

  const digest = await crypto.subtle.digest("SHA-512", payload);
  return bufferToHex(digest);
}
