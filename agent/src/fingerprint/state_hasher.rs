//! CyberV Final State Hasher (Tier 6)
//!
//! Ref: rv4.md #9, #10, #11, #12:
//! "State Hash là một commitment công khai đến toàn bộ trạng thái hiện tại của thiết bị...
//! Length-prefixed canonical encoding, SHA-512...
//! Final Hash != Authentication Credential."

use crate::fingerprint::canonical::CanonicalEncoder;
use crate::protocol::constants::{DOMAIN_STATE, STATE_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

/// Represents the evaluated cryptographic state of the device
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceState {
    pub device_id: String,
    pub state_schema_version: u32,
    pub graph_version: u32,
    pub verification_hash: String, // Tier 5 verification hash from Phase 3
    pub state_hash: String,        // Tier 6 state hash (128 hex chars SHA-512)
    pub context: BTreeMap<String, String>,
}

/// Computes Tier 6 State Hash using length-prefixed canonical encoding
pub fn compute_state_hash(
    state_schema_version: u32,
    graph_version: u32,
    device_id: &str,
    verification_hash: &str,
    canonical_context_bytes: &[u8],
) -> String {
    let mut hasher = Sha512::new();

    // Domain separator
    hasher.update(DOMAIN_STATE);
    hasher.update([0x00]);

    // Versions
    hasher.update(state_schema_version.to_be_bytes());
    hasher.update([0x00]);
    hasher.update(graph_version.to_be_bytes());
    hasher.update([0x00]);

    // Length-prefixed device_id
    let dev_id_bytes = device_id.as_bytes();
    hasher.update((dev_id_bytes.len() as u32).to_be_bytes());
    hasher.update(dev_id_bytes);
    hasher.update([0x00]);

    // Length-prefixed verification_hash
    let vh_bytes = verification_hash.as_bytes();
    hasher.update((vh_bytes.len() as u32).to_be_bytes());
    hasher.update(vh_bytes);
    hasher.update([0x00]);

    // Length-prefixed canonical context
    hasher.update((canonical_context_bytes.len() as u32).to_be_bytes());
    hasher.update(canonical_context_bytes);

    let digest = hasher.finalize();
    format!("{:x}", digest)
}

/// Evaluates and encapsulates current device state from verification hash and context
pub fn evaluate_device_state(
    device_id: &str,
    graph_version: u32,
    verification_hash: &str,
    context_attrs: &BTreeMap<String, String>,
) -> DeviceState {
    let mut encoder = CanonicalEncoder::new();
    for (k, v) in context_attrs {
        encoder.add_field(k, v);
    }
    let canonical_context_bytes = encoder.to_canonical_bytes();

    let state_hash = compute_state_hash(
        STATE_SCHEMA_VERSION,
        graph_version,
        device_id,
        verification_hash,
        &canonical_context_bytes,
    );

    DeviceState {
        device_id: device_id.to_string(),
        state_schema_version: STATE_SCHEMA_VERSION,
        graph_version,
        verification_hash: verification_hash.to_string(),
        state_hash,
        context: context_attrs.clone(),
    }
}
