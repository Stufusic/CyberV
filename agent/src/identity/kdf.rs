// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
//! State-Bound Key & Material Derivation via HKDF-SHA-512 (RFC 5869)
//!
//! Ref: rv4.md #1, #16, #17:
//! "kdf.rs: derive_state_bound_material()...
//! Device Seed -> HKDF-SHA-512 (Salt = verification_hash)...
//! KHÔNG dùng nó để mã hóa chính vault chứa Device Seed."

use super::error::IdentityError;
use super::secret::Secret32;
use crate::protocol::constants::DOMAIN_HKDF_STATE_BOUND;
use hkdf::Hkdf;
use sha2::Sha512;

/// Derives ephemeral 32-byte state-bound secret material using HKDF-SHA-512.
///
/// Salt: `verification_hash` (changes whenever hardware changes)
/// IKM: `device_seed` (stable local secret)
/// Info: `DOMAIN_HKDF_STATE_BOUND || info_context`
pub fn derive_state_bound_material(
    device_seed: &Secret32,
    verification_hash: &str,
    info_context: &[u8],
) -> Result<Secret32, IdentityError> {
    let salt = verification_hash.as_bytes();
    let ikm = device_seed.as_bytes();

    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);

    let mut info = Vec::with_capacity(DOMAIN_HKDF_STATE_BOUND.len() + 1 + info_context.len());
    info.extend_from_slice(DOMAIN_HKDF_STATE_BOUND);
    info.push(0x00);
    info.extend_from_slice(info_context);

    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|e| IdentityError::KdfFailure(e.to_string()))?;

    Ok(Secret32::new(okm))
}

/// Derives arbitrary length state-bound material (up to 255 * 64 bytes)
pub fn derive_state_bound_bytes(
    device_seed: &Secret32,
    verification_hash: &str,
    info_context: &[u8],
    out: &mut [u8],
) -> Result<(), IdentityError> {
    let salt = verification_hash.as_bytes();
    let ikm = device_seed.as_bytes();

    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);

    let mut info = Vec::with_capacity(DOMAIN_HKDF_STATE_BOUND.len() + 1 + info_context.len());
    info.extend_from_slice(DOMAIN_HKDF_STATE_BOUND);
    info.push(0x00);
    info.extend_from_slice(info_context);

    hk.expand(&info, out)
        .map_err(|e| IdentityError::KdfFailure(e.to_string()))
}
