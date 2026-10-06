// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
//! P2-2 (phần user-mode) — PCI/Storage enumeration THẬT qua CfgMgr32.
//!
//! Ref: `Docs/PHASE1_2_IMPLEMENTATION_PLAN.md` P2-2 + README §10.1 (giới hạn
//! kernel PCI qua PnP registry). Sensor này enumerates device instance ID
//! THẬT từ PnP Manager qua `CM_Get_Device_ID_List` (cfgmgr32.dll) — không
//! hard-code, không fabrication; dùng để **kiểm chéo** danh sách PCI mà driver
//! thu thập từ nhánh kernel registry.
//!
//! Ranh giới trung thực: đây là quan sát user-mode (phía trên PnP Manager —
//! cùng lớp trừu tượng với driver hiện tại, KHÔNG phải direct
//! BUS_INTERFACE_STANDARD ở tầng bus driver — phần đó cần WDK và nằm ở
//! driver-side, chưa làm). Lỗi enumerate → `Err` rõ ràng, caller phải báo
//! "chưa quan sát được", KHÔNG bịa dữ liệu (INV-007).
//!
//! Digest: SHA-512/32 trên danh sách device ID **đã sort** — deterministic,
//! cùng máy cùng phần cứng = cùng digest; cắm/rút thiết bị = digest đổi.

use sha2::{Digest, Sha512};

/// Kết quả enumerate một lớp thiết bị.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceClassDigest {
    /// Lớp PnP đã enumerate ("PCI" / "DISKDRIVE").
    pub class: &'static str,
    /// Số device instance ID quan sát được.
    pub device_count: usize,
    /// SHA-512/32 trên danh sách đã sort (mỗi ID một dòng, có NUL phân cách).
    pub digest: [u8; 32],
    /// Danh sách ID đã sort (audit — không gửi serial thô ra mạng, chỉ hash).
    pub device_ids: Vec<String>,
}

const CONFIGRET_SUCCESS: u32 = 0;

/// GUID setup class chuẩn của Windows (device setup classes).
pub const PCI_CLASS_GUID: &str = "{4D36E968-E325-11CE-BFC1-08002BE10318}";
pub const DISKDRIVE_CLASS_GUID: &str = "{4D36E967-E325-11CE-BFC1-08002BE10318}";

/// Enumerate device instance IDs của một lớp PnP (filter GUID), sort
/// deterministic. Lưu ý thực đo: filter bằng TÊN lớp ("PCI") bị Windows
/// trả CR_CALL_NOT_IMPLEMENTED (0x1F) trên máy đo — dùng GUID hoạt động.
fn enumerate_class(class_label: &'static str, class_guid: &str) -> Result<Vec<String>, String> {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Get_Device_ID_List_SizeA, CM_Get_Device_ID_ListA, CM_GETIDLIST_FILTER_CLASS,
    };

    let filter = format!("{class_guid}\0");
    let mut len: u32 = 0;
    let size_status = unsafe {
        CM_Get_Device_ID_List_SizeA(
            &mut len,
            filter.as_ptr(),
            CM_GETIDLIST_FILTER_CLASS,
        )
    };
    if size_status != CONFIGRET_SUCCESS {
        return Err(format!(
            "CM_Get_Device_ID_List_SizeA({class_label}) thất bại: CONFIGRET 0x{size_status:08X}"
        ));
    }
    if len == 0 {
        return Ok(Vec::new()); // Lớp rỗng — hợp lệ, không phải lỗi.
    }
    // Buffer multi-sz: chuỗi nối NUL, kết thúc NUL rỗng.
    let mut buffer = vec![0u8; len as usize];
    let status = unsafe {
        CM_Get_Device_ID_ListA(
            filter.as_ptr(),
            buffer.as_mut_ptr(),
            len,
            CM_GETIDLIST_FILTER_CLASS,
        )
    };
    if status != CONFIGRET_SUCCESS {
        return Err(format!(
            "CM_Get_Device_ID_ListA({class_label}) thất bại: CONFIGRET 0x{status:08X}"
        ));
    }
    let ids: Vec<String> = buffer
        .split(|&b| b == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut sorted = ids;
    sorted.sort();
    sorted.dedup();
    Ok(sorted)
}

fn digest_of(class: &'static str, ids: &[String]) -> DeviceClassDigest {
    // Hợp đồng: digest của danh sách ĐÃ SORT — thứ tự đầu vào không ảnh hưởng.
    let mut sorted_ids = ids.to_vec();
    sorted_ids.sort();
    sorted_ids.dedup();
    let mut hasher = Sha512::new();
    // Domain separator — chống mở rộng hash giữa các lớp thiết bị.
    hasher.update(b"CYBERV/PNP-CLASS/v1\x00");
    hasher.update((sorted_ids.len() as u32).to_be_bytes());
    for id in &sorted_ids {
        hasher.update(id.as_bytes());
        hasher.update([0x00]); // phân cách — chống nối chuỗi mơ hồ
    }
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out[..32]);
    DeviceClassDigest {
        class,
        device_count: sorted_ids.len(),
        digest,
        device_ids: sorted_ids,
    }
}

/// Enumerate PCI devices thật.
pub fn enumerate_pci() -> Result<DeviceClassDigest, String> {
    let ids = enumerate_class("PCI", PCI_CLASS_GUID)?;
    Ok(digest_of("PCI", &ids))
}

/// Enumerate physical disk drives thật (device level — KHÔNG phải drive letter).
pub fn enumerate_disk_drives() -> Result<DeviceClassDigest, String> {
    let ids = enumerate_class("DISKDRIVE", DISKDRIVE_CLASS_GUID)?;
    Ok(digest_of("DISKDRIVE", &ids))
}

/// Enumerate cả hai lớp — tiện cho cross-validation với driver report.
pub fn enumerate_pci_and_storage() -> Result<(DeviceClassDigest, DeviceClassDigest), String> {
    let pci = enumerate_pci()?;
    let disks = enumerate_disk_drives()?;
    Ok((pci, disks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_enumeration_is_real_and_deterministic() {
        // Máy Windows thật luôn có PCI devices — đây là quan sát thật.
        let pci = enumerate_pci().expect("enumerate PCI thật");
        assert!(pci.device_count > 0, "máy thật phải có ít nhất 1 PCI device");
        assert!(
            pci.device_ids.iter().any(|id| id.starts_with("PCI\\")),
            "instance ID phải có prefix PCI\\ — thực tế: {:?}",
            pci.device_ids.first()
        );

        // Gọi lại — deterministic (cùng digest, cùng count).
        let pci2 = enumerate_pci().unwrap();
        assert_eq!(pci2.digest, pci.digest);
        assert_eq!(pci2.device_count, pci.device_count);
    }

    #[test]
    fn disk_drive_enumeration_is_real() {
        let disks = enumerate_disk_drives().expect("enumerate DISKDRIVE thật");
        assert!(disks.device_count > 0, "máy test phải có ít nhất 1 ổ vật lý");
        // Instance ID của disk theo BUS enumerator (SCSI\, IDE\...) — lớp là
        // DISKDRIVE nhưng instance ID không nhất thiết có prefix đó.
        assert!(
            disks.device_ids.iter().all(|id| !id.is_empty()),
            "instance ID phải non-empty"
        );
    }

    #[test]
    fn digest_changes_when_device_list_changes() {
        // Đơn vị test digest: cùng danh sách = cùng digest; khác 1 device =
        // khác digest (chống collision nối chuỗi).
        let ids = vec!["PCI\\VEN_A".to_string(), "PCI\\VEN_B".to_string()];
        let d1 = digest_of("PCI", &ids);
        let d2 = digest_of("PCI", &ids);
        assert_eq!(d1.digest, d2.digest);

        // Đảo thứ tự vẫn cùng digest (đã sort).
        let reversed = vec!["PCI\\VEN_B".to_string(), "PCI\\VEN_A".to_string()];
        let d3 = digest_of("PCI", &reversed);
        assert_eq!(d3.digest, d1.digest, "sort trước khi hash — deterministic");

        let extra = vec![
            "PCI\\VEN_A".to_string(),
            "PCI\\VEN_B".to_string(),
            "PCI\\VEN_C".to_string(),
        ];
        let d4 = digest_of("PCI", &extra);
        assert_ne!(d4.digest, d1.digest, "thêm device phải đổi digest");

        // Chống nối chuỗi mơ hồ: {"VEN_A", "VEN_BC"} vs {"VEN_AB", "VEN_C"}.
        let set1 = digest_of("PCI", &["A".into(), "BC".into()]);
        let set2 = digest_of("PCI", &["AB".into(), "C".into()]);
        assert_ne!(set1.digest, set2.digest, "NUL separator chặn collision nối chuỗi");
    }

    #[test]
    fn class_digest_records_count_and_ids() {
        let pci = enumerate_pci().unwrap();
        assert_eq!(pci.class, "PCI");
        assert_eq!(pci.device_ids.len(), pci.device_count);
    }
}
