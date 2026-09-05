/**
 * CyberV Final State Hasher (TypeScript / Deno Backend)
 * 
 * Computes Tier 6 State Hash using length-prefixed canonical byte encoding
 * matching the Rust Agent byte-for-byte.
 * Ref: rv4.md #9, #10, #11.
 */

import { DOMAIN_STATE, STATE_SCHEMA_VERSION } from "./protocol.ts";
import { bufferToHex } from "./component_hasher.ts";

/**
 * Computes Tier 6 State Hash matching Rust agent compute_state_hash
 */
export async function computeStateHash(
  stateSchemaVersion: number,
  graphVersion: number,
  deviceId: string,
  verificationHash: string,
  canonicalContextBytes: Uint8Array,
): Promise<string> {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(DOMAIN_STATE);
  const devIdBytes = encoder.encode(deviceId);
  const vhBytes = encoder.encode(verificationHash);

  // Versions: 4-byte big-endian
  const svBytes = new Uint8Array(4);
  new DataView(svBytes.buffer).setUint32(0, stateSchemaVersion, false);

  const gvBytes = new Uint8Array(4);
  new DataView(gvBytes.buffer).setUint32(0, graphVersion, false);

  const devIdLenBytes = new Uint8Array(4);
  new DataView(devIdLenBytes.buffer).setUint32(0, devIdBytes.length, false);

  const vhLenBytes = new Uint8Array(4);
  new DataView(vhLenBytes.buffer).setUint32(0, vhBytes.length, false);

  const ctxLenBytes = new Uint8Array(4);
  new DataView(ctxLenBytes.buffer).setUint32(0, canonicalContextBytes.length, false);

  const delim = new Uint8Array([0x00]);

  const totalLen =
    domainBytes.length + 1 +
    svBytes.length + 1 +
    gvBytes.length + 1 +
    devIdLenBytes.length + devIdBytes.length + 1 +
    vhLenBytes.length + vhBytes.length + 1 +
    ctxLenBytes.length + canonicalContextBytes.length;

  const payload = new Uint8Array(totalLen);
  let offset = 0;

  payload.set(domainBytes, offset);
  offset += domainBytes.length;
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

  payload.set(devIdLenBytes, offset);
  offset += devIdLenBytes.length;
  payload.set(devIdBytes, offset);
  offset += devIdBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(vhLenBytes, offset);
  offset += vhLenBytes.length;
  payload.set(vhBytes, offset);
  offset += vhBytes.length;
  payload.set(delim, offset);
  offset += 1;

  payload.set(ctxLenBytes, offset);
  offset += ctxLenBytes.length;
  payload.set(canonicalContextBytes, offset);

  const digest = await crypto.subtle.digest("SHA-512", payload);
  return bufferToHex(digest);
}
