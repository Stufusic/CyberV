/**
 * CyberV Component Hasher (TypeScript / Deno Backend)
 * 
 * Computes component hashes using standard SHA-512 (FIPS 180-4 / NSA CNSA Suite)
 * matching the Rust Agent implementation byte-for-byte.
 * Ref: Pipeline.md Section 7, rv.md #1, #9 and Rule.md Điều 2, 20.
 */

import { DOMAIN_COMPONENT, PROTOCOL_VERSION } from "./protocol.ts";

/**
 * Converts an ArrayBuffer or Uint8Array into a lowercase hexadecimal string
 */
export function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Encodes an object of key-values into canonical UTF-8 bytes (key=value\n sorted by key)
 */
export function encodeCanonicalBytes(attributes: Record<string, string>): Uint8Array {
  const sortedKeys = Object.keys(attributes).sort();
  let text = "";
  for (const key of sortedKeys) {
    text += `${key.trim().toLowerCase()}=${attributes[key].trim().toLowerCase()}\n`;
  }
  return new TextEncoder().encode(text);
}

/**
 * Computes the SHA-512 component hash matching the Rust agent
 */
export async function computeComponentHash(
  componentType: string,
  canonicalBytes: Uint8Array
): Promise<string> {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(DOMAIN_COMPONENT);
  const typeBytes = encoder.encode(componentType.toUpperCase());

  // Protocol version in 4-byte big-endian
  const versionBytes = new Uint8Array(4);
  const view = new DataView(versionBytes.buffer);
  view.setUint32(0, PROTOCOL_VERSION, false); // Big-Endian

  const delimiter = new Uint8Array([0x00]);

  // Total payload = DOMAIN || 0x00 || VERSION || 0x00 || TYPE || 0x00 || CANONICAL_BYTES
  const totalLength =
    domainBytes.length + 1 +
    versionBytes.length + 1 +
    typeBytes.length + 1 +
    canonicalBytes.length;

  const payload = new Uint8Array(totalLength);
  let offset = 0;

  payload.set(domainBytes, offset);
  offset += domainBytes.length;

  payload.set(delimiter, offset);
  offset += 1;

  payload.set(versionBytes, offset);
  offset += versionBytes.length;

  payload.set(delimiter, offset);
  offset += 1;

  payload.set(typeBytes, offset);
  offset += typeBytes.length;

  payload.set(delimiter, offset);
  offset += 1;

  payload.set(canonicalBytes, offset);

  // Compute SHA-512 via standard WebCrypto
  const digest = await crypto.subtle.digest("SHA-512", payload);
  return bufferToHex(digest);
}
