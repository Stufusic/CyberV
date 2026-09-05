/**
 * CyberV Protocol Constants and Domain Separators
 * 
 * Shared constants between Client Agent and Backend Edge Functions.
 * Ref: rv.md, rv p3.md and Rule.md Điều 2, 20.
 */

export const PROTOCOL_ID = "cyberv-device-binding";
export const PROTOCOL_VERSION = 1;
export const SCHEMA_VERSION = 1;
export const DERIVATION_VERSION = 1;
export const STATE_SCHEMA_VERSION = 1;

// Domain Separators for 6-Tier Hash Commitment Hierarchy & Challenge Protocol
export const DOMAIN_COMPONENT       = "CYBERV/DBS/COMPONENT/v1";
export const DOMAIN_NODE            = "CYBERV/DBS/NODE/v1";
export const DOMAIN_VIRTUAL_NODE    = "CYBERV/DBS/VNODE/v1";
export const DOMAIN_EVIDENCE        = "CYBERV/DBS/EVIDENCE/v1";
export const DOMAIN_GRAPH           = "CYBERV/DBS/GRAPH/v1";
export const DOMAIN_VERIFICATION    = "CYBERV/DBS/VERIFICATION/v1";
export const DOMAIN_STATE           = "CYBERV/DBS/STATE/v1";
export const DOMAIN_AUTH            = "CYBERV/DBS/AUTH/v1";
export const DOMAIN_REENROLL        = "CYBERV/DBS/REENROLL/v1";
export const DOMAIN_ENROLL          = "CYBERV/DBS/ENROLL/v1";
export const DOMAIN_KEY_ROTATION    = "CYBERV/DBS/KEY_ROTATION/v1";
export const DOMAIN_HKDF_STATE_BOUND= "CYBERV/HKDF/STATE_BOUND/v1";

// Purpose identifiers (rv4.md #13)
export const PURPOSE_DEVICE_AUTH    = "device-auth";
export const PURPOSE_REENROLLMENT   = "reenrollment";
export const PURPOSE_ENROLLMENT     = "device-enrollment";
export const PURPOSE_KEY_ROTATION   = "key-rotation";

// Security limits
export const CHALLENGE_TTL_SECONDS = 60;

// Device Status enum
export enum DeviceStatus {
  ACTIVE = "ACTIVE",
  PENDING = "PENDING",
  REVOKED = "REVOKED",
  REJECTED = "REJECTED",
}

// Risk Level enum
export enum RiskLevel {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL",
}
