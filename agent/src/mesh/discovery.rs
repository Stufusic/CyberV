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
//! Mesh Discovery — beacon codec (NSG-2, phần pure)
//!
//! Ref: plan v2 §7.1 (UC-1 bước 1), §10 (Tier A). Beacon mDNS TXT/SRV chỉ
//! chứa **node_id + vk** — không metadata máy (privacy, T6). Decode bounds
//! nghiêm ngặt; beacon KHÔNG nâng trust — presence ≠ trust (INV-012), peer
//! chỉ vào `Discovered`, phải bắt tay chữ ký mới được `Attested`.
//!
//! Trung thực: tầng này chỉ là codec — **socket mDNS wiring là NSG-2b**
//! (khi wire vào daemon + chọn crate discovery qua cargo-deny/machete).

use super::graph::NodeId;
use super::MeshError;

/// Magic nhận diện beacon trên dây.
pub const BEACON_MAGIC: &[u8] = b"CYBERV-MESH-BEACON";
/// Phiên bản beacon.
pub const BEACON_VERSION: u32 = 1;
/// Kích thước beacon chuẩn: magic(18) + version(4) + node_id(32) + vk(32).
pub const BEACON_LEN: usize = 18 + 4 + 32 + 32;
/// Trần tuyệt đối cho beacon (phòng version tương lai dài hơn).
pub const MAX_BEACON_SIZE: usize = 256;

/// Quảng bá một node mesh trên LAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshBeacon {
    pub node_id: NodeId,
    /// Ed25519 verifying key của node — peer dùng làm neo pinning **sau khi
    /// đối chiếu qua kênh enrollment** (KHÔNG tin trực tiếp từ beacon).
    pub vk: [u8; 32],
    pub wire_version: u32,
}

impl MeshBeacon {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BEACON_LEN);
        out.extend_from_slice(BEACON_MAGIC);
        out.extend_from_slice(&self.wire_version.to_be_bytes());
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.vk);
        out
    }

    /// Decode + bounds: magic sai / độ dài lệch / vượt trần → từ chối.
    pub fn decode(bytes: &[u8]) -> Result<Self, MeshError> {
        if bytes.len() > MAX_BEACON_SIZE {
            return Err(MeshError::Frame(format!(
                "beacon vượt trần kích thước: {}",
                bytes.len()
            )));
        }
        if bytes.len() != BEACON_LEN {
            return Err(MeshError::Frame(format!(
                "beacon lệch độ dài chuẩn: {} ≠ {BEACON_LEN}",
                bytes.len()
            )));
        }
        if &bytes[..BEACON_MAGIC.len()] != BEACON_MAGIC {
            return Err(MeshError::Frame("magic beacon sai".into()));
        }
        let rest = &bytes[BEACON_MAGIC.len()..];
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&rest[4..36]);
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&rest[36..68]);
        Ok(Self {
            node_id,
            vk,
            wire_version: u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MeshBeacon {
        MeshBeacon { node_id: [0x11; 32], vk: [0x22; 32], wire_version: BEACON_VERSION }
    }

    #[test]
    fn roundtrip_preserves_fields() {
        let beacon = sample();
        let decoded = MeshBeacon::decode(&beacon.encode()).unwrap();
        assert_eq!(decoded, beacon);
    }

    #[test]
    fn wrong_magic_rejected() {
        let mut wire = sample().encode();
        wire[0] = b'X';
        assert!(matches!(MeshBeacon::decode(&wire), Err(MeshError::Frame(_))));
    }

    #[test]
    fn truncated_and_oversized_rejected() {
        let wire = sample().encode();
        assert!(MeshBeacon::decode(&wire[..wire.len() - 1]).is_err());
        let mut over = wire.clone();
        over.extend_from_slice(&[0u8; MAX_BEACON_SIZE]);
        assert!(matches!(MeshBeacon::decode(&over), Err(MeshError::Frame(_))));
    }
}
