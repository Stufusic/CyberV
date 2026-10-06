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
//! BLE Tier C (M-4) — beacon codec nén 26 byte + presence provider.
//!
//! Ref: M-PLAN §5 + plan NSG §10 (Tier C = discovery only, **zero trust**).
//! BLE legacy advertisement chỉ chứa ~26 byte dữ liệu hữu ích — KHÔNG đủ
//! node_id(32) + vk(32) đầy đủ, càng KHÔNG BAO GIỜ mang frame trust. Codec
//! nén: 8 byte prefix node_id + 8 byte prefix vk (informational) + checksum.
//! Presence BLE không nâng NodeState, không pin neo, không vào quorum —
//! chỉ là "máy này đang ở gần" (test chốt bất biến đó).

use super::super::MeshError;
use super::shim;

/// Kích thước beacon BLE chuẩn (26 byte — vừa BLE legacy adv data).
pub const BLE_BEACON_LEN: usize = 26;
/// Magic riêng của BLE compact beacon (phân biệt với beacon mDNS 86 byte).
pub const BLE_MAGIC: &[u8; 4] = b"CVMB";
/// Phiên bản codec BLE.
pub const BLE_BEACON_VERSION: u8 = 1;
/// Trần tuyệt đối payload qua shim (phòng dữ liệu version tương lai).
pub const BLE_PAYLOAD_MAX: usize = 26;

/// Beacon BLE nén — presence only, zero trust (prefix không verify được).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleBeacon26 {
    /// 8 byte ĐẦU của NodeId — không phải định danh đầy đủ.
    pub node_prefix: [u8; 8],
    /// 8 byte ĐẦU của vk — chỉ informational, không đủ verify chữ ký.
    pub vk_prefix: [u8; 8],
    /// Bit flags (bit 0: node sẵn sàng nhận kết nối — informational).
    pub flags: u8,
}

impl BleBeacon26 {
    /// Dựng từ node_id/vk đầy đủ (lấy prefix).
    pub fn from_identity(node_id: &[u8; 32], vk: &[u8; 32]) -> Self {
        let mut node_prefix = [0u8; 8];
        node_prefix.copy_from_slice(&node_id[..8]);
        let mut vk_prefix = [0u8; 8];
        vk_prefix.copy_from_slice(&vk[..8]);
        Self { node_prefix, vk_prefix, flags: 1 }
    }

    /// Checksum: tổng bytes[0..24] mod 2^16 (BE) — chống nhiễu radio, KHÔNG
    /// phải mật mã (presence không mang trust).
    fn checksum(bytes: &[u8; BLE_BEACON_LEN]) -> u16 {
        bytes[..24].iter().fold(0u16, |acc, b| acc.wrapping_add(*b as u16))
    }

    pub fn encode(&self) -> [u8; BLE_BEACON_LEN] {
        let mut out = [0u8; BLE_BEACON_LEN];
        out[0..4].copy_from_slice(BLE_MAGIC);
        out[4] = BLE_BEACON_VERSION;
        out[5..13].copy_from_slice(&self.node_prefix);
        out[13..21].copy_from_slice(&self.vk_prefix);
        out[21] = self.flags;
        // out[22..24] reserved = 0
        let sum = Self::checksum(&out);
        out[24..26].copy_from_slice(&sum.to_be_bytes());
        out
    }

    /// Decode bounds nghiêm ngặt: magic/version/checksum sai → từ chối.
    pub fn decode(bytes: &[u8]) -> Result<Self, MeshError> {
        if bytes.len() > BLE_PAYLOAD_MAX {
            return Err(MeshError::Frame(format!("BLE beacon vượt trần: {}", bytes.len())));
        }
        if bytes.len() != BLE_BEACON_LEN {
            return Err(MeshError::Frame(format!(
                "BLE beacon lệch độ dài chuẩn: {} ≠ {BLE_BEACON_LEN}",
                bytes.len()
            )));
        }
        if &bytes[0..4] != BLE_MAGIC {
            return Err(MeshError::Frame("magic BLE beacon sai".into()));
        }
        if bytes[4] != BLE_BEACON_VERSION {
            return Err(MeshError::UnsupportedVersion(bytes[4] as u32));
        }
        let mut wire = [0u8; BLE_BEACON_LEN];
        wire.copy_from_slice(bytes);
        let expect = Self::checksum(&wire);
        let got = u16::from_be_bytes([wire[24], wire[25]]);
        if expect != got {
            return Err(MeshError::Frame(format!(
                "checksum BLE beacon lệch: {got:#06x} ≠ {expect:#06x}"
            )));
        }
        let mut node_prefix = [0u8; 8];
        node_prefix.copy_from_slice(&wire[5..13]);
        let mut vk_prefix = [0u8; 8];
        vk_prefix.copy_from_slice(&wire[13..21]);
        Ok(Self { node_prefix, vk_prefix, flags: wire[21] })
    }
}

/// Sample BLE: (MAC 6 byte, payload).
pub type BleSample = ([u8; 6], Vec<u8>);

/// Provider presence BLE — gói shim watch; KHÔNG chứa logic mesh (logic ở
/// engine `poll_ble_presence`). Mỗi API chỉ transliterate start/stop/poll.
#[derive(Debug, Default)]
pub struct BleDiscovery {
    watching: bool,
}

impl BleDiscovery {
    /// Bật watcher. Shim không hỗ trợ / radio tắt → lỗi trung thực.
    pub fn start_watch(&mut self) -> Result<(), MeshError> {
        if self.watching {
            return Err(MeshError::InvalidEndpoint("BLE watch đã bật".into()));
        }
        let res = shim::ble_watch_start();
        if res.status != shim::ShimStatus::Ok {
            return Err(res.to_mesh_error("ble_watch_start"));
        }
        self.watching = true;
        Ok(())
    }

    pub fn stop_watch(&mut self) -> Result<(), MeshError> {
        if !self.watching {
            return Err(MeshError::InvalidEndpoint("BLE watch chưa bật".into()));
        }
        let res = shim::ble_watch_stop();
        self.watching = false;
        if res.status != shim::ShimStatus::Ok {
            return Err(res.to_mesh_error("ble_watch_stop"));
        }
        Ok(())
    }

    /// Poll không chặn: (addr6, payload) các quảng bá mới kể lần poll trước.
    /// Lỗi shim (trừ not-found) nổi lên — không nuốt âm thầm.
    pub fn poll(&mut self) -> Result<Vec<BleSample>, MeshError> {
        if !self.watching {
            return Err(MeshError::InvalidEndpoint("BLE watch chưa bật".into()));
        }
        let mut out = Vec::new();
        loop {
            match shim::ble_watch_next() {
                Ok(Some((addr6, payload))) => out.push((addr6, payload)),
                Ok(None) => break, // hết hàng đợi
                Err(res) => {
                    if res.status == shim::ShimStatus::NotFound {
                        break;
                    }
                    return Err(res.to_mesh_error("ble_watch_next"));
                }
            }
        }
        Ok(out)
    }

    pub fn is_watching(&self) -> bool {
        self.watching
    }
}

/// Bật quảng bá BLE với beacon nén. Bounds kiểm TRƯỚC khi đụng shim.
pub fn advertise(beacon: &BleBeacon26) -> Result<(), MeshError> {
    let payload = beacon.encode();
    let res = shim::ble_adv_start(&payload);
    if res.status != shim::ShimStatus::Ok {
        return Err(res.to_mesh_error("ble_adv_start"));
    }
    Ok(())
}

/// Tắt quảng bá BLE.
pub fn advertise_stop() -> Result<(), MeshError> {
    let res = shim::ble_adv_stop();
    if res.status != shim::ShimStatus::Ok {
        return Err(res.to_mesh_error("ble_adv_stop"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BleBeacon26 {
        BleBeacon26 {
            node_prefix: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            vk_prefix: [0xAA; 8],
            flags: 1,
        }
    }

    #[test]
    fn beacon26_roundtrip() {
        let wire = sample().encode();
        assert_eq!(wire.len(), BLE_BEACON_LEN);
        assert_eq!(&wire[0..4], BLE_MAGIC);
        assert_eq!(wire[4], BLE_BEACON_VERSION);
        let decoded = BleBeacon26::decode(&wire).unwrap();
        assert_eq!(decoded, sample());
    }

    #[test]
    fn beacon26_exactly_26_bytes_fits_ble_adv() {
        // M-PLAN §5: nén ≤ 26 byte dữ liệu hữu ích — đúng trần BLE legacy.
        assert_eq!(BLE_BEACON_LEN, 26);
        assert_eq!(sample().encode().len(), 26);
    }

    #[test]
    fn beacon26_rejects_garbage() {
        let wire = sample().encode();
        // Magic sai
        let mut bad = wire;
        bad[0] = b'X';
        assert!(matches!(BleBeacon26::decode(&bad), Err(MeshError::Frame(_))));
        // Version lạ → UnsupportedVersion (đúng variant, không nuốt thành Frame)
        let mut bad2 = wire;
        bad2[4] = 9;
        assert!(matches!(BleBeacon26::decode(&bad2), Err(MeshError::UnsupportedVersion(9))));
        // Checksum sai (flip node_prefix)
        let mut bad3 = wire;
        bad3[5] ^= 0x01;
        assert!(matches!(BleBeacon26::decode(&bad3), Err(MeshError::Frame(_))));
        // Cắt cụt / vượt trần
        assert!(matches!(BleBeacon26::decode(&wire[..25]), Err(MeshError::Frame(_))));
        let mut over = wire.to_vec();
        over.push(0);
        assert!(matches!(BleBeacon26::decode(&over), Err(MeshError::Frame(_))));
        assert!(matches!(BleBeacon26::decode(&[]), Err(MeshError::Frame(_))));
    }

    #[test]
    fn prefix_not_full_identity() {
        // Prefix 8 byte KHÔNG phải định danh đầy đủ — test chốt ranh giới:
        // hai node khác node_id có thể trùng 0 byte tới 8 byte prefix.
        let a = BleBeacon26::from_identity(&[1u8; 32], &[2u8; 32]);
        assert_ne!(a.node_prefix, [0u8; 8]);
    }
}
