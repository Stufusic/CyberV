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
//! WFP Enforcement (I-2 — M-PLAN §6.2, plan NSG §9): chặn traffic tới peer
//! bị cách ly qua Windows Filtering Platform.
//!
//! Semantics theo plan §9:
//! - Scope: chặn per-IP của peer (mọi port), CẢ inbound + outbound;
//! - **KHÔNG BAO GIỜ chạm loopback** (IPC agent-UI không bị ảnh hưởng);
//! - Rule đánh dấu `CyberV-NSG-<subject8>`; **deadline TTL tuyệt đối**
//!   (unix ms) lưu trong description — reboot không reset vòng đời;
//! - `sweep_expired` = watchdog + startup reconcile: quét marker rules,
//!   xóa rule hết hạn, idempotent;
//! - Fallback trung thực: không mở được engine (thiếu quyền admin) → trả
//!   `WfpError::AccessDenied` — tầng trên chuyển logic-only, KHÔNG giả vờ
//!   đã chặn mạng (INV-007).

/// Tiền tố tên rule — dùng để nhận diện rule mồ côi khi reconcile (plan §9).
pub const MARKER_PREFIX: &str = "CyberV-NSG-";

/// Tên rule cho một subject: `CyberV-NSG-<8 hex đầu>`.
pub fn marker_name(subject: &[u8; 32]) -> String {
    let mut name = String::from(MARKER_PREFIX);
    for byte in subject.iter().take(4) {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// Parse subject từ tên rule — None nếu không phải marker của chúng ta.
pub fn parse_marker_subject(name: &str) -> Option<[u8; 32]> {
    let hex = name.strip_prefix(MARKER_PREFIX)?;
    if hex.len() != 8 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut subject = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks(2).take(4).enumerate() {
        let hi = pair[0] as char;
        let lo = pair[1] as char;
        subject[i] = (hi.to_digit(16)? * 16 + lo.to_digit(16)?) as u8;
    }
    Some(subject)
}

/// Description chứa deadline tuyệt đối: `deadline=<unix ms>`.
pub fn deadline_desc(until_unix_ms: u64) -> String {
    format!("deadline={until_unix_ms}")
}

/// Parse deadline từ description rule — None nếu sai format.
pub fn parse_deadline(description: &str) -> Option<u64> {
    description.strip_prefix("deadline=")?.parse().ok()
}

/// Lỗi WFP — mọi nhánh đều là NHÁN TỪ CHỐI trung thực (không có "lỗi thì
/// coi như đã chặn").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpError {
    /// Không mở được engine — thiếu quyền admin. Tầng trên phải chuyển
    /// logic-only và báo UI `is_verified: false`.
    AccessDenied,
    /// Plan §9: KHÔNG BAO GIỜ tạo rule cho loopback (bảo vệ IPC agent-UI).
    LoopbackDenied,
    /// I-2 chỉ hỗ trợ IPv4 (mesh LAN); IPv6 → báo rõ, không giả vờ chặn.
    UnsupportedFamily,
    /// Nền không hỗ trợ WFP (không phải Windows).
    Unsupported,
    /// Lỗi Windows khác — mã lỗi gốc.
    Os(u32),
}

#[cfg(windows)]
mod imp {
    use std::net::IpAddr;
    use std::ptr::{null, null_mut};

    use windows_sys::core::{GUID, PWSTR};
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
        FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
        FWPM_ACTION0, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
        FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWP_ACTION_BLOCK, FWP_CONDITION_VALUE0,
        FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_UINT32, FWP_VALUE0,
        FWP_VALUE0_0,
    };

    use super::{deadline_desc, marker_name, WfpError};

    /// RPC_C_AUTHN_DEFAULT — để WFP tự chọn xác thực mặc định.
    const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
    /// Trần số filter mỗi lần enum (dư dả cho cap link 64 × 2 chiều).
    const ENUM_BATCH: u32 = 1024;

    fn map_rc(rc: u32) -> WfpError {
        if rc == ERROR_ACCESS_DENIED {
            WfpError::AccessDenied
        } else {
            WfpError::Os(rc)
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// Engine handle WFP — đóng khi drop.
    pub struct WfpEngine {
        engine: HANDLE,
    }

    impl Drop for WfpEngine {
        fn drop(&mut self) {
            unsafe { FwpmEngineClose0(self.engine) };
        }
    }

    impl WfpEngine {
        /// Mở engine WFP (cần quyền admin — không có thì `AccessDenied`).
        pub fn open() -> Result<Self, WfpError> {
            let mut engine: HANDLE = 0;
            let rc = unsafe {
                FwpmEngineOpen0(null(), RPC_C_AUTHN_DEFAULT, null(), null(), &mut engine)
            };
            if rc != 0 {
                return Err(map_rc(rc));
            }
            Ok(Self { engine })
        }

        /// Chặn mọi traffic tới `ip` (cả 2 chiều) cho tới `until_unix_ms`.
        /// Idempotent: rule cũ của subject bị xóa trước khi thêm mới.
        /// Trả danh sách filter id đã tạo (audit + teardown).
        pub fn block_peer(
            &mut self,
            ip: IpAddr,
            subject: &[u8; 32],
            until_unix_ms: u64,
        ) -> Result<Vec<u64>, WfpError> {
            // Plan §9: KHÔNG BAO GIỜ chạm loopback — bảo vệ kênh IPC agent-UI.
            if ip.is_loopback() {
                return Err(WfpError::LoopbackDenied);
            }
            let v4 = match ip {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => return Err(WfpError::UnsupportedFamily),
            };
            // Idempotent — dọn rule cũ cùng subject trước.
            self.unblock_subject(subject)?;

            // Địa chỉ remote theo host byte order cho layer V4 (MSDN):
            // 192.168.1.5 → 0xC0A80105.
            let remote_u32 = u32::from_be_bytes(v4.octets());
            let name = wide(&marker_name(subject));
            let desc = wide(&deadline_desc(until_unix_ms));
            let mut ids = Vec::with_capacity(2);
            for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4] {
                let id = self.add_filter(layer, remote_u32, &name, &desc)?;
                ids.push(id);
            }
            Ok(ids)
        }

        fn add_filter(
            &mut self,
            layer: GUID,
            remote_u32: u32,
            name: &[u16],
            desc: &[u16],
        ) -> Result<u64, WfpError> {
            let condition = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint32: remote_u32 },
                },
            };
            // Các union/blob không có Default — zeroed() an toàn với kiểu
            // POD kích thước cố định của windows-sys (chỉ chứa số/con trỏ).
            let filter = FWPM_FILTER0 {
                filterKey: GUID::from_u128(0),
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_ptr() as PWSTR,
                    description: desc.as_ptr() as PWSTR,
                },
                flags: 0,
                providerKey: null_mut(),
                providerData: unsafe { std::mem::zeroed() },
                layerKey: layer,
                // Universal sublayer (GUID zero) — không tạo sublayer riêng.
                subLayerKey: GUID::from_u128(0),
                weight: FWP_VALUE0 { r#type: FWP_EMPTY, Anonymous: FWP_VALUE0_0 { uint32: 0 } },
                numFilterConditions: 1,
                filterCondition: &condition as *const FWPM_FILTER_CONDITION0
                    as *mut FWPM_FILTER_CONDITION0,
                action: FWPM_ACTION0 {
                    r#type: FWP_ACTION_BLOCK,
                    Anonymous: unsafe { std::mem::zeroed() },
                },
                Anonymous: unsafe { std::mem::zeroed() },
                reserved: null_mut(),
                filterId: 0,
                effectiveWeight: FWP_VALUE0 { r#type: FWP_EMPTY, Anonymous: FWP_VALUE0_0 { uint32: 0 } },
            };
            let mut filter_id = 0u64;
            let rc = unsafe { FwpmFilterAdd0(self.engine, &filter, std::ptr::null_mut(), &mut filter_id) };
            if rc != 0 {
                return Err(map_rc(rc));
            }
            Ok(filter_id)
        }

        /// Xóa MỌI rule của một subject. Idempotent; trả số rule đã xóa.
        pub fn unblock_subject(&mut self, subject: &[u8; 32]) -> Result<usize, WfpError> {
            let want = marker_name(subject);
            let ids = self.enum_marker_ids(Some(&want), u64::MAX)?;
            let mut removed = 0;
            for id in ids {
                let rc = unsafe { FwpmFilterDeleteById0(self.engine, id) };
                if rc == 0 {
                    removed += 1;
                }
            }
            Ok(removed)
        }

        /// Startup reconcile + watchdog (plan §9): quét marker rules, xóa rule
        /// hết hạn so với `now_unix_ms`. Idempotent — gọi bao nhiêu lần cũng an toàn.
        pub fn sweep_expired(&mut self, now_unix_ms: u64) -> Result<usize, WfpError> {
            let ids = self.enum_marker_ids(None, now_unix_ms)?;
            let mut removed = 0;
            for id in ids {
                let rc = unsafe { FwpmFilterDeleteById0(self.engine, id) };
                if rc == 0 {
                    removed += 1;
                }
            }
            Ok(removed)
        }

        /// Enum mọi marker filter; nếu `name_exact` đặt thì lọc đúng tên,
        /// ngược lại lọc rule có deadline ≤ `now_unix_ms`. Trả filter id.
        fn enum_marker_ids(
            &mut self,
            name_exact: Option<&str>,
            now_unix_ms: u64,
        ) -> Result<Vec<u64>, WfpError> {
            let template = FWPM_FILTER_ENUM_TEMPLATE0 {
                providerKey: null_mut(),
                // GUID zero = mọi layer.
                layerKey: GUID::from_u128(0),
                enumType: 0, // FWP_FILTER_ENUM_FULLY_CONTAINED
                flags: 0,
                providerContextTemplate: null_mut(),
                numFilterConditions: 0,
                filterCondition: null_mut(),
                actionMask: 0,
                calloutKey: null_mut(),
            };
            let mut enum_handle: HANDLE = 0;
            let rc = unsafe { FwpmFilterCreateEnumHandle0(self.engine, &template, &mut enum_handle) };
            if rc != 0 {
                return Err(map_rc(rc));
            }
            let mut ids = Vec::new();
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = null_mut();
                let mut returned = 0u32;
                let rc = unsafe {
                    FwpmFilterEnum0(
                        self.engine,
                        enum_handle,
                        ENUM_BATCH,
                        &mut entries,
                        &mut returned,
                    )
                };
                if rc != 0 {
                    unsafe { FwpmFilterDestroyEnumHandle0(self.engine, enum_handle) };
                    return Err(map_rc(rc));
                }
                if returned == 0 || entries.is_null() {
                    break;
                }
                for i in 0..returned as usize {
                    // SAFETY: entries do Windows cấp — mảng `returned` con trỏ
                    // tới FWPM_FILTER0; giải phóng bằng FwpmFreeMemory0 bên dưới.
                    let filter = unsafe { *entries.add(i) };
                    let name = unsafe { pwstr_to_string((*filter).displayData.name) };
                    if !name.starts_with(super::MARKER_PREFIX) {
                        continue;
                    }
                    if let Some(want) = name_exact {
                        if name != want {
                            continue;
                        }
                    } else {
                        let desc = unsafe { pwstr_to_string((*filter).displayData.description) };
                        let Some(deadline) = super::parse_deadline(&desc) else {
                            // Marker không đọc được deadline — coi như hết hạn
                            // cho sạch (không có rule không rõ hạn còn lại).
                            continue;
                        };
                        if deadline > now_unix_ms {
                            continue; // còn hạn
                        }
                    }
                    ids.push(unsafe { (*filter).filterId });
                }
                let free = entries as *mut *mut std::ffi::c_void;
                unsafe { FwpmFreeMemory0(free) };
                if (returned as usize) < ENUM_BATCH as usize {
                    break;
                }
            }
            unsafe { FwpmFilterDestroyEnumHandle0(self.engine, enum_handle) };
            Ok(ids)
        }
    }

    /// Đọc PWSTR (UTF-16, NUL-terminated) từ WFP — bounds: cắt tại NUL đầu
    /// tiên, trần 512 ký tự (tên/description của chúng ta luôn ngắn hơn).
    unsafe fn pwstr_to_string(p: PWSTR) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while len < 512 && *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

#[cfg(windows)]
pub use imp::WfpEngine;

/// Nền không phải Windows — API tồn tại để tầng trên biên dịch được, mọi
/// thao tác trả `Unsupported` (trung thực: không chặn được gì).
#[cfg(not(windows))]
pub struct WfpEngine;

#[cfg(not(windows))]
impl WfpEngine {
    pub fn open() -> Result<Self, WfpError> {
        Err(WfpError::Unsupported)
    }

    pub fn block_peer(
        &mut self,
        _ip: std::net::IpAddr,
        _subject: &[u8; 32],
        _until_unix_ms: u64,
    ) -> Result<Vec<u64>, WfpError> {
        Err(WfpError::Unsupported)
    }

    pub fn unblock_subject(&mut self, _subject: &[u8; 32]) -> Result<usize, WfpError> {
        Err(WfpError::Unsupported)
    }

    pub fn sweep_expired(&mut self, _now_unix_ms: u64) -> Result<usize, WfpError> {
        Err(WfpError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_roundtrip() {
        let subject = [0xABu8, 0x01, 0x23, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let name = marker_name(&subject);
        assert_eq!(name, "CyberV-NSG-ab012345");
        assert_eq!(parse_marker_subject(&name), Some(subject));
        // Tên lạ — không phải marker của chúng ta.
        assert_eq!(parse_marker_subject("Other-Tool-12345678"), None);
        assert_eq!(parse_marker_subject("CyberV-NSG-zz012345"), None);
        assert_eq!(parse_marker_subject("CyberV-NSG-ab0123456"), None);
    }

    #[test]
    fn deadline_roundtrip() {
        let desc = deadline_desc(1_742_000_000_000);
        assert_eq!(desc, "deadline=1742000000000");
        assert_eq!(parse_deadline(&desc), Some(1_742_000_000_000));
        assert_eq!(parse_deadline("something else"), None);
        assert_eq!(parse_deadline("deadline=NaN"), None);
    }

    #[cfg(windows)]
    #[test]
    fn wfp_open_honest_verdict() {
        // Không đòi quyền admin trong test: mở được (máy elevated) → cleanup
        // ngay; không được → PHẢI là AccessDenied (mapping trung thực).
        match WfpEngine::open() {
            Ok(_) => {}
            Err(e) => assert_eq!(e, WfpError::AccessDenied, "lỗi khác AccessDenied phải được phân loại rõ: {e:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "cần admin + đụng WFP thật — chạy tay: cargo test --release -p cyberv-agent wfp_admin -- --ignored"]
    fn wfp_admin_block_unblock_sweep() {
        let mut engine = WfpEngine::open().expect("cần chạy với admin");
        let subject = [0x7Eu8; 32];
        let ip: std::net::IpAddr = "203.0.113.9".parse().unwrap();

        let ids = engine.block_peer(ip, &subject, 1).unwrap(); // deadline quá khứ
        assert_eq!(ids.len(), 2, "một filter mỗi chiều (out + in)");

        // Idempotent: block lại — rule cũ bị thay, không chồng chất.
        let ids2 = engine.block_peer(ip, &subject, 1).unwrap();
        assert_eq!(ids2.len(), 2);

        // Unblock đúng subject.
        let removed = engine.unblock_subject(&subject).unwrap();
        assert_eq!(removed, 2);

        // Sweep rule mồ côi (deadline quá khứ) — sau block lần 2 rồi sweep.
        engine.block_peer(ip, &subject, 1).unwrap();
        let removed = engine.sweep_expired(u64::MAX).unwrap();
        assert!(removed >= 2);
        engine.unblock_subject(&subject).unwrap();

        // Loopback BỊ TỪ CHỐI — plan §9.
        let loop_err = engine
            .block_peer("127.0.0.1".parse().unwrap(), &subject, u64::MAX)
            .unwrap_err();
        assert_eq!(loop_err, WfpError::LoopbackDenied);
        engine.unblock_subject(&subject).unwrap();
    }
}
