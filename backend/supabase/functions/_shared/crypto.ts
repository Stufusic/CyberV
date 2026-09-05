/**
 * CyberV Cryptographic Operations (TypeScript / Deno Backend)
 * 
 * Implements WebCrypto Ed25519 signature verification, HKDF-SHA-512 state-bound derivation,
 * and canonical signature payload encoding matching the Rust Agent.
 * Ref: rv4.md #10, #13, #18.
 */

import {
  DOMAIN_AUTH,
  DOMAIN_ENROLL,
  DOMAIN_KEY_ROTATION,
  DOMAIN_HKDF_STATE_BOUND,
  DOMAIN_REENROLL,
  PROTOCOL_VERSION,
  PURPOSE_REENROLLMENT,
} from "./protocol.ts";

/**
 * Converts a hexadecimal string into a Uint8Array
 */
export function hexToBuffer(hex: string): Uint8Array {
  const cleanHex = hex.trim().toLowerCase();
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Builds deterministic, length-prefixed canonical signature payload bytes
 * matching Rust build_challenge_signature_payload byte-for-byte.
 */
export function buildChallengeSignaturePayload(
  purpose: string,
  challengeId: string,
  nonce: string,
  deviceId: string,
  stateHash: string,
  graphVersion: number,
): Uint8Array {
  const encoder = new TextEncoder();
  const domainStr = purpose === PURPOSE_REENROLLMENT ? DOMAIN_REENROLL : DOMAIN_AUTH;
  const domainBytes = encoder.encode(domainStr);

  const purpBytes = encoder.encode(purpose);
  const chalBytes = encoder.encode(challengeId);
  const nonceBytes = encoder.encode(nonce);
  const devBytes = encoder.encode(deviceId);
  const hashBytes = encoder.encode(stateHash);

  // Versions: 4-byte big-endian
  const pvBytes = new Uint8Array(4);
  new DataView(pvBytes.buffer).setUint32(0, PROTOCOL_VERSION, false);

  const gvBytes = new Uint8Array(4);
  new DataView(gvBytes.buffer).setUint32(0, graphVersion, false);

  const purpLenBytes = new Uint8Array(4);
  new DataView(purpLenBytes.buffer).setUint32(0, purpBytes.length, false);

  const chalLenBytes = new Uint8Array(4);
  new DataView(chalLenBytes.buffer).setUint32(0, chalBytes.length, false);

  const nonceLenBytes = new Uint8Array(4);
  new DataView(nonceLenBytes.buffer).setUint32(0, nonceBytes.length, false);

  const devLenBytes = new Uint8Array(4);
  new DataView(devLenBytes.buffer).setUint32(0, devBytes.length, false);

  const hashLenBytes = new Uint8Array(4);
  new DataView(hashLenBytes.buffer).setUint32(0, hashBytes.length, false);

  const delim = new Uint8Array([0x00]);

  const totalLen =
    domainBytes.length + 1 +
    pvBytes.length + 1 +
    gvBytes.length + 1 +
    purpLenBytes.length + purpBytes.length + 1 +
    chalLenBytes.length + chalBytes.length + 1 +
    nonceLenBytes.length + nonceBytes.length + 1 +
    devLenBytes.length + devBytes.length + 1 +
    hashLenBytes.length + hashBytes.length;

  const buffer = new Uint8Array(totalLen);
  let offset = 0;

  buffer.set(domainBytes, offset);
  offset += domainBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(pvBytes, offset);
  offset += pvBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(gvBytes, offset);
  offset += gvBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(purpLenBytes, offset);
  offset += purpLenBytes.length;
  buffer.set(purpBytes, offset);
  offset += purpBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(chalLenBytes, offset);
  offset += chalLenBytes.length;
  buffer.set(chalBytes, offset);
  offset += chalBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(nonceLenBytes, offset);
  offset += nonceLenBytes.length;
  buffer.set(nonceBytes, offset);
  offset += nonceBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(devLenBytes, offset);
  offset += devLenBytes.length;
  buffer.set(devBytes, offset);
  offset += devBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(hashLenBytes, offset);
  offset += hashLenBytes.length;
  buffer.set(hashBytes, offset);

  return buffer;
}

/**
 * Verifies an Ed25519 signature against the payload using WebCrypto (rv4.md #18)
 */
export async function verifyEd25519ChallengeSignature(
  publicKeyHex: string,
  payload: Uint8Array,
  signatureHex: string,
): Promise<boolean> {
  try {
    const rawKey = hexToBuffer(publicKeyHex);
    const signatureBytes = hexToBuffer(signatureHex);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "Ed25519" },
      true,
      ["verify"],
    );

    return await crypto.subtle.verify(
      "Ed25519",
      cryptoKey,
      signatureBytes,
      payload,
    );
  } catch (_e) {
    return false;
  }
}

/**
 * Builds length-prefixed canonical bytes for Re-enrollment signature
 * matching Rust build_reenrollment_signature_payload byte-for-byte.
 */
export function buildReenrollmentSignaturePayload(
  deviceId: string,
  previousStateHash: string,
  newStateHash: string,
  newGraphHash: string,
  newGraphVersion: number,
  reason: string,
): Uint8Array {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(DOMAIN_REENROLL);

  const devBytes = encoder.encode(deviceId);
  const prevBytes = encoder.encode(previousStateHash);
  const newSBytes = encoder.encode(newStateHash);
  const newGBytes = encoder.encode(newGraphHash);
  const reasonBytes = encoder.encode(reason);

  const pvBytes = new Uint8Array(4);
  new DataView(pvBytes.buffer).setUint32(0, PROTOCOL_VERSION, false);

  const gvBytes = new Uint8Array(4);
  new DataView(gvBytes.buffer).setUint32(0, newGraphVersion, false);

  const devLen = new Uint8Array(4);
  new DataView(devLen.buffer).setUint32(0, devBytes.length, false);

  const prevLen = new Uint8Array(4);
  new DataView(prevLen.buffer).setUint32(0, prevBytes.length, false);

  const newSLen = new Uint8Array(4);
  new DataView(newSLen.buffer).setUint32(0, newSBytes.length, false);

  const newGLen = new Uint8Array(4);
  new DataView(newGLen.buffer).setUint32(0, newGBytes.length, false);

  const reasonLen = new Uint8Array(4);
  new DataView(reasonLen.buffer).setUint32(0, reasonBytes.length, false);

  const delim = new Uint8Array([0x00]);

  const totalLen =
    domainBytes.length + 1 +
    pvBytes.length + 1 +
    gvBytes.length + 1 +
    devLen.length + devBytes.length + 1 +
    prevLen.length + prevBytes.length + 1 +
    newSLen.length + newSBytes.length + 1 +
    newGLen.length + newGBytes.length + 1 +
    reasonLen.length + reasonBytes.length;

  const buffer = new Uint8Array(totalLen);
  let offset = 0;

  buffer.set(domainBytes, offset);
  offset += domainBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(pvBytes, offset);
  offset += pvBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(gvBytes, offset);
  offset += gvBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(devLen, offset);
  offset += devLen.length;
  buffer.set(devBytes, offset);
  offset += devBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(prevLen, offset);
  offset += prevLen.length;
  buffer.set(prevBytes, offset);
  offset += prevBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(newSLen, offset);
  offset += newSLen.length;
  buffer.set(newSBytes, offset);
  offset += newSBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(newGLen, offset);
  offset += newGLen.length;
  buffer.set(newGBytes, offset);
  offset += newGBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(reasonLen, offset);
  offset += reasonLen.length;
  buffer.set(reasonBytes, offset);

  return buffer;
}

/**
 * Builds length-prefixed canonical bytes for Initial Device Enrollment signature
 * matching Rust build_enrollment_signature_payload byte-for-byte.
 */
export function buildEnrollmentSignaturePayload(
  deviceId: string,
  publicKeyHex: string,
  graphHash: string,
  stateHash: string,
  graphVersion = 1,
): Uint8Array {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(DOMAIN_ENROLL);

  const devBytes = encoder.encode(deviceId);
  const pkBytes = encoder.encode(publicKeyHex);
  const ghBytes = encoder.encode(graphHash);
  const shBytes = encoder.encode(stateHash);

  const pvBytes = new Uint8Array(4);
  new DataView(pvBytes.buffer).setUint32(0, PROTOCOL_VERSION, false);

  const gvBytes = new Uint8Array(4);
  new DataView(gvBytes.buffer).setUint32(0, graphVersion, false);

  const devLen = new Uint8Array(4);
  new DataView(devLen.buffer).setUint32(0, devBytes.length, false);

  const pkLen = new Uint8Array(4);
  new DataView(pkLen.buffer).setUint32(0, pkBytes.length, false);

  const ghLen = new Uint8Array(4);
  new DataView(ghLen.buffer).setUint32(0, ghBytes.length, false);

  const shLen = new Uint8Array(4);
  new DataView(shLen.buffer).setUint32(0, shBytes.length, false);

  const delim = new Uint8Array([0x00]);

  const totalLen =
    domainBytes.length + 1 +
    pvBytes.length + 1 +
    gvBytes.length + 1 +
    devLen.length + devBytes.length + 1 +
    pkLen.length + pkBytes.length + 1 +
    ghLen.length + ghBytes.length + 1 +
    shLen.length + shBytes.length;

  const buffer = new Uint8Array(totalLen);
  let offset = 0;

  buffer.set(domainBytes, offset);
  offset += domainBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(pvBytes, offset);
  offset += pvBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(gvBytes, offset);
  offset += gvBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(devLen, offset);
  offset += devLen.length;
  buffer.set(devBytes, offset);
  offset += devBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(pkLen, offset);
  offset += pkLen.length;
  buffer.set(pkBytes, offset);
  offset += pkBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(ghLen, offset);
  offset += ghLen.length;
  buffer.set(ghBytes, offset);
  offset += ghBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(shLen, offset);
  offset += shLen.length;
  buffer.set(shBytes, offset);

  return buffer;
}

/**
 * Builds length-prefixed canonical bytes for Key Rotation request
 * matching Rust build_key_rotation_signature_payload byte-for-byte.
 */
export function buildKeyRotationSignaturePayload(
  deviceId: string,
  oldPublicKeyHex: string,
  newPublicKeyHex: string,
  stateHash: string,
  graphVersion: number,
  nonce: string,
  timestamp: number,
): Uint8Array {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(DOMAIN_KEY_ROTATION);

  const devBytes = encoder.encode(deviceId);
  const oldPkBytes = encoder.encode(oldPublicKeyHex);
  const newPkBytes = encoder.encode(newPublicKeyHex);
  const shBytes = encoder.encode(stateHash);
  const nonceBytes = encoder.encode(nonce);

  const pvBytes = new Uint8Array(4);
  new DataView(pvBytes.buffer).setUint32(0, PROTOCOL_VERSION, false);

  const gvBytes = new Uint8Array(4);
  new DataView(gvBytes.buffer).setUint32(0, graphVersion, false);

  const tsBytes = new Uint8Array(8);
  new DataView(tsBytes.buffer).setBigUint64(0, BigInt(timestamp), false);

  const devLen = new Uint8Array(4);
  new DataView(devLen.buffer).setUint32(0, devBytes.length, false);

  const oldPkLen = new Uint8Array(4);
  new DataView(oldPkLen.buffer).setUint32(0, oldPkBytes.length, false);

  const newPkLen = new Uint8Array(4);
  new DataView(newPkLen.buffer).setUint32(0, newPkBytes.length, false);

  const shLen = new Uint8Array(4);
  new DataView(shLen.buffer).setUint32(0, shBytes.length, false);

  const nonceLen = new Uint8Array(4);
  new DataView(nonceLen.buffer).setUint32(0, nonceBytes.length, false);

  const delim = new Uint8Array([0x00]);

  const totalLen =
    domainBytes.length + 1 +
    pvBytes.length + 1 +
    gvBytes.length + 1 +
    tsBytes.length + 1 +
    devLen.length + devBytes.length + 1 +
    oldPkLen.length + oldPkBytes.length + 1 +
    newPkLen.length + newPkBytes.length + 1 +
    shLen.length + shBytes.length + 1 +
    nonceLen.length + nonceBytes.length;

  const buffer = new Uint8Array(totalLen);
  let offset = 0;

  buffer.set(domainBytes, offset);
  offset += domainBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(pvBytes, offset);
  offset += pvBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(gvBytes, offset);
  offset += gvBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(tsBytes, offset);
  offset += tsBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(devLen, offset);
  offset += devLen.length;
  buffer.set(devBytes, offset);
  offset += devBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(oldPkLen, offset);
  offset += oldPkLen.length;
  buffer.set(oldPkBytes, offset);
  offset += oldPkBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(newPkLen, offset);
  offset += newPkLen.length;
  buffer.set(newPkBytes, offset);
  offset += newPkBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(shLen, offset);
  offset += shLen.length;
  buffer.set(shBytes, offset);
  offset += shBytes.length;
  buffer.set(delim, offset);
  offset += 1;

  buffer.set(nonceLen, offset);
  offset += nonceLen.length;
  buffer.set(nonceBytes, offset);

  return buffer;
}

/**
 * Verifies both old and new Ed25519 signatures for a Key Rotation request
 */
export async function verifyEd25519KeyRotationSignatures(
  oldPublicKeyHex: string,
  newPublicKeyHex: string,
  payload: Uint8Array,
  signatureOldHex: string,
  signatureNewHex: string,
): Promise<boolean> {
  const isOldValid = await verifyEd25519ChallengeSignature(oldPublicKeyHex, payload, signatureOldHex);
  if (!isOldValid) return false;

  const isNewValid = await verifyEd25519ChallengeSignature(newPublicKeyHex, payload, signatureNewHex);
  return isNewValid;
}
