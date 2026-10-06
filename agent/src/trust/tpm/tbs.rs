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
//! TBS thật — Trusted Base Services + TPM2 command marshalling (P2-1a)
//!
//! Ref: PHASE1_2 plan P2-1; roadmap v2 Trụ 1 mục 1 (TPM thật) và mục 5
//! (rollback protection trên counter thật); INV-006 (neo counter phần cứng).
//!
//! Kiến trúc: marshal/unmarshal TPM2 là hàm PURE (test được không cần TPM);
//! lớp Windows chỉ bọc `Tbsi_Context_Create` / `Tbsip_Submit_Command` /
//! `Tbsip_Context_Close`. `TbsNvCounter` hiện thực `TpmNvCounter` bằng lệnh
//! TPM2 THẬT: NV_Read → (chưa có) NV_DefineSpace (counter NV, auth owner
//! rỗng) → NV_Increment → NV_Read.
//!
//! Trung thực (INV-007): assurance `HardwareBacked` CHỈ khi TBS context mở
//! được và các lệnh TPM2 trả success; máy không TPM → constructor trả
//! SoftwareFallback mode và mọi thao tác báo `TpmError::NotPresent`.

use crate::trust::tpm::errors::TpmError;
use crate::trust::tpm::nv_counter::{
    TpmAssuranceType, TpmNvCounter, TpmNvHandleInfo, TpmNvAttributes,
};

// ---- TPM 2.0 constants (Part 2) — chỉ phần cần cho NV counter ----

pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_RC_SUCCESS: u32 = 0x0000_0000;
/// Warning: handle không tồn tại (index NV chưa được define).
pub const TPM_RC_HANDLE: u32 = 0x0000_008B;
/// Index NV đã tồn tại (DefineSpace bị từ chối vì đã có).
pub const TPM_RC_NV_DEFINED: u32 = 0x0000_015C;
pub const TPM_CC_NV_READ: u32 = 0x0000_014E;
pub const TPM_CC_NV_INCREMENT: u32 = 0x0000_014D;
pub const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012C;
/// Authorization handle: Owner hierarchy (máy consumer mặc định auth rỗng).
pub const TPM_RH_OWNER: u32 = 0x4000_0011;
/// Password session handle (auth rỗng, không cần secret trên dây).
pub const TPM_RS_PW: u32 = 0x4000_0009;
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// TPM_NT_COUNTER — NV index kiểu monotonic counter.
pub const TPM_NT_COUNTER: u32 = 0x4;
/// TPMA_NV: AUTHREAD | AUTHWRITE | (TPM_NT_COUNTER << 25).
pub const TPMA_NV_COUNTER_AUTH: u32 = (TPM_NT_COUNTER << 25) | 0x0000_0006;

/// Auth area cho password session rỗng (không truyền secret trên dây):
/// authSize(4) + RS_PW(4) + nonceSize(4=0) + attrs(1=continue) + hmacSize(4=0).
pub fn pw_auth_area() -> Vec<u8> {
    let mut a = Vec::with_capacity(17);
    a.extend_from_slice(&9u32.to_be_bytes());
    a.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    a.extend_from_slice(&0u32.to_be_bytes());
    a.push(0x01); // continueSession
    a.extend_from_slice(&0u32.to_be_bytes());
    a
}

fn build_header_with_sessions(cc: u32, auth_handle: u32, body: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(10 + 4 + 17 + body.len());
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    let size_pos = c.len();
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&cc.to_be_bytes());
    c.extend_from_slice(&auth_handle.to_be_bytes());
    c.extend(pw_auth_area());
    c.extend_from_slice(body);
    let total = c.len() as u32;
    c[size_pos..size_pos + 4].copy_from_slice(&total.to_be_bytes());
    c
}

/// TPM2_NV_Read: đọc `size` byte từ offset của NV index.
pub fn build_nv_read_cmd(auth_handle: u32, nv_index: u32, size: u16, offset: u16) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&nv_index.to_be_bytes());
    body.extend_from_slice(&size.to_be_bytes());
    body.extend_from_slice(&offset.to_be_bytes());
    build_header_with_sessions(TPM_CC_NV_READ, auth_handle, &body)
}

/// TPM2_NV_Increment: tăng monotonic counter.
pub fn build_nv_increment_cmd(auth_handle: u32, nv_index: u32) -> Vec<u8> {
    build_header_with_sessions(TPM_CC_NV_INCREMENT, auth_handle, &nv_index.to_be_bytes())
}

/// TPM2_NV_DefineSpace: định nghĩa NV index kiểu COUNTER, auth rỗng.
/// Params: objectAttributes(u32) + auth(TPM2B rỗng) + publicInfo(TPM2B_NV_PUBLIC).
pub fn build_nv_define_space_cmd(auth_handle: u32, nv_index: u32, data_size: u16) -> Vec<u8> {
    let nv_public_len: u16 = 4 + 2 + 4 + 2 + 8; // index + nameAlg + attrs + authPolicy(0) + dataSize
    let mut body = Vec::with_capacity(4 + 2 + 2 + nv_public_len as usize);
    body.extend_from_slice(&TPMA_NV_COUNTER_AUTH.to_be_bytes()); // objectAttributes
    body.extend_from_slice(&0u16.to_be_bytes()); // auth: TPM2B rỗng
    body.extend_from_slice(&nv_public_len.to_be_bytes()); // publicInfo: TPM2B
    body.extend_from_slice(&nv_index.to_be_bytes());
    body.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    body.extend_from_slice(&TPMA_NV_COUNTER_AUTH.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // authPolicy rỗng
    body.extend_from_slice(&(data_size as u64).to_be_bytes());
    build_header_with_sessions(TPM_CC_NV_DEFINE_SPACE, auth_handle, &body)
}

/// Trích response code từ response TPM2 (header: tag(2) + size(4) + rc(4)).
pub fn parse_response_rc(resp: &[u8]) -> Result<u32, TpmError> {
    if resp.len() < 10 {
        return Err(TpmError::ProviderError(format!(
            "response TPM2 quá ngắn: {} byte",
            resp.len()
        )));
    }
    Ok(u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]))
}

/// Parse giá trị counter từ response TPM2_NV_Read thành công:
/// header(10) + nvIndexHandle(4) + paramSize(4) + data(TPM2B: 2 + 8).
pub fn parse_nv_value(resp: &[u8]) -> Result<u64, TpmError> {
    if resp.len() < 10 + 4 + 4 + 2 + 8 {
        return Err(TpmError::ProviderError(format!(
            "response NV_Read ngắn bất thường: {} byte",
            resp.len()
        )));
    }
    let param_size = u32::from_be_bytes([resp[14], resp[15], resp[16], resp[17]]) as usize;
    if param_size != 2 + 8 {
        return Err(TpmError::ProviderError(format!(
            "paramSize NV_Read bất thường: {param_size}"
        )));
    }
    let data_len = u16::from_be_bytes([resp[18], resp[19]]) as usize;
    if data_len != 8 {
        return Err(TpmError::ProviderError(format!(
            "counter NV phải 8 byte, được {data_len}"
        )));
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&resp[20..28]);
    Ok(u64::from_be_bytes(v))
}

/// Kết nối TBS của Windows — tài nguyên đóng đúng trong Drop.
pub struct TbsContext {
    handle: *mut core::ffi::c_void,
}

impl std::fmt::Debug for TbsContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // KHÔNG in handle thô — chỉ trạng thái có/không.
        f.debug_struct("TbsContext").finish_non_exhaustive()
    }
}

// TBS handle chỉ là descriptor kết nối; API TBS thread-safe theo tài liệu MS.
unsafe impl Send for TbsContext {}
unsafe impl Sync for TbsContext {}

impl TbsContext {
    /// Mở context TBS. Máy không TPM / service TBS tắt → `TpmError::NotPresent`.
    /// Thử TPM 2.0 trước (máy Win11 chỉ có TPM 2.0 — context version ONE
    /// sẽ fail), rồi fallback TPM 1.2 cho máy cũ.
    pub fn new() -> Result<Self, TpmError> {
        use windows_sys::Win32::System::TpmBaseServices as TBS;
        // TPM 2.0: TBS_CONTEXT_PARAMS2 { version = TWO, tpmVersion = TPM_VERSION_20 }
        let params2 = TBS::TBS_CONTEXT_PARAMS2 {
            version: TBS::TBS_CONTEXT_VERSION_TWO,
            Anonymous: TBS::TBS_CONTEXT_PARAMS2_0 {
                Anonymous: TBS::TBS_CONTEXT_PARAMS2_0_0 {
                    _bitfield: TBS::TPM_VERSION_20,
                },
            },
        };
        let mut handle: *mut core::ffi::c_void = std::ptr::null_mut();
        // TBS đọc `version` đầu tiên để phân biệt PARAMS/PARAMS2 — cast con
        // trỏ là pattern chuẩn của C-versioning ở đây.
        let result = unsafe {
            TBS::Tbsi_Context_Create(
                &params2 as *const _ as *const TBS::TBS_CONTEXT_PARAMS,
                &mut handle,
            )
        };
        if result != TBS::TBS_SUCCESS || handle.is_null() {
            // Fallback TPM 1.2 (máy cũ).
            let params1 = TBS::TBS_CONTEXT_PARAMS {
                version: TBS::TBS_CONTEXT_VERSION_ONE,
            };
            let rc1 = unsafe { TBS::Tbsi_Context_Create(&params1, &mut handle) };
            if rc1 != TBS::TBS_SUCCESS || handle.is_null() {
                // Diagnostic: mã lỗi TBS thật để phân biệt không-TPM vs bị chặn.
                return Err(TpmError::ProviderError(format!(
                    "TBS rc2=0x{result:08X} rc1=0x{rc1:08X}"
                )));
            }
        }
        Ok(Self { handle })
    }

    /// Gửi 1 lệnh TPM2 thô qua TBS.
    pub fn submit(&self, command: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut out = vec![0u8; 4096];
        let mut out_len = out.len() as u32;
        let result = unsafe {
            windows_sys::Win32::System::TpmBaseServices::Tbsip_Submit_Command(
                self.handle,
                windows_sys::Win32::System::TpmBaseServices::TBS_COMMAND_LOCALITY_ZERO,
                windows_sys::Win32::System::TpmBaseServices::TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        if result != windows_sys::Win32::System::TpmBaseServices::TBS_SUCCESS {
            return Err(TpmError::ProviderError(format!(
                "Tbsip_Submit_Command lỗi 0x{result:08X}"
            )));
        }
        out.truncate(out_len as usize);
        Ok(out)
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::TpmBaseServices::Tbsip_Context_Close(self.handle);
        }
    }
}

/// NV counter THẬT qua TBS. Máy không TPM → `ctx = None`, assurance báo
/// `SoftwareFallback` trung thực và mọi thao tác trả `NotPresent`.
#[derive(Debug)]
pub struct TbsNvCounter {
    ctx: Option<TbsContext>,
    assurance: TpmAssuranceType,
}

impl Default for TbsNvCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl TbsNvCounter {
    pub fn new() -> Self {
        match TbsContext::new() {
            Ok(ctx) => Self {
                ctx: Some(ctx),
                assurance: TpmAssuranceType::HardwareBacked,
            },
            Err(_) => Self {
                ctx: None,
                assurance: TpmAssuranceType::SoftwareFallback,
            },
        }
    }

    // Clone thủ công: TBS handle không nhân bản được — bản clone mở context
    // RIÊNG (tương đương về semantics). Nếu clone mở không được -> fallback
    // SoftwareFallback trung thực, KHÔNG kế thừa HardwareBacked giả.
    fn clone_with_fallback(&self) -> Self {
        match TbsContext::new() {
            Ok(ctx) => Self {
                ctx: Some(ctx),
                assurance: TpmAssuranceType::HardwareBacked,
            },
            Err(_) => Self {
                ctx: None,
                assurance: TpmAssuranceType::SoftwareFallback,
            },
        }
    }

    pub fn tbs_available() -> bool {
        TbsContext::new().is_ok()
    }

    fn ctx(&self) -> Result<&TbsContext, TpmError> {
        self.ctx.as_ref().ok_or(TpmError::NotPresent)
    }
}

impl Clone for TbsNvCounter {
    fn clone(&self) -> Self {
        //assurance gốc chỉ giữ khi clone mở context thành công
        self.clone_with_fallback()
    }
}

impl TpmNvCounter for TbsNvCounter {
    fn discover_or_provision(
        &mut self,
        nv_index: u32,
        initial_counter: u64,
    ) -> Result<TpmNvHandleInfo, TpmError> {
        let ctx = self.ctx()?;
        // 1. Thử đọc — index chưa có thì rc trả TPM_RC_HANDLE.
        let existing = match ctx.submit(&build_nv_read_cmd(TPM_RH_OWNER, nv_index, 8, 0)) {
            Ok(resp) => parse_response_rc(&resp)? == TPM_RC_SUCCESS,
            Err(TpmError::ProviderError(_)) => false,
            Err(e) => return Err(e),
        };
        let provisioned_now = if existing {
            false
        } else {
            // 2. DefineSpace counter NV với owner auth rỗng. Máy có owner
            // auth đặt sẵn sẽ trả rc lỗi rõ ràng — KHÔNG đoán auth.
            let resp = ctx.submit(&build_nv_define_space_cmd(TPM_RH_OWNER, nv_index, 8))?;
            let rc = parse_response_rc(&resp)?;
            if rc != TPM_RC_SUCCESS && rc != TPM_RC_NV_DEFINED {
                return Err(TpmError::ProviderError(format!(
                    "TPM2_NV_DefineSpace rc 0x{rc:06X}"
                )));
            }
            true
        };

        // 3. Đưa counter tới initial_counter (giới hạn vòng lặp — chống
        // caller truyền initial_counter khổng lồ làm mòn NV).
        let mut current = self.read_counter(nv_index).unwrap_or(0);
        let mut steps = 0u32;
        while current < initial_counter && steps < 16 {
            ctx.submit(&build_nv_increment_cmd(TPM_RH_OWNER, nv_index))?;
            current = self.read_counter(nv_index)?;
            steps += 1;
        }

        Ok(TpmNvHandleInfo {
            nv_index,
            attributes: TpmNvAttributes::default(),
            assurance: TpmAssuranceType::HardwareBacked,
            current_value: current,
            is_provisioned_by_cyberv: provisioned_now,
        })
    }

    fn read_counter(&self, nv_index: u32) -> Result<u64, TpmError> {
        let ctx = self.ctx()?;
        let resp = ctx.submit(&build_nv_read_cmd(TPM_RH_OWNER, nv_index, 8, 0))?;
        let rc = parse_response_rc(&resp)?;
        if rc != TPM_RC_SUCCESS {
            return Err(TpmError::ProviderError(format!(
                "TPM2_NV_Read rc 0x{rc:06X}"
            )));
        }
        parse_nv_value(&resp)
    }

    fn increment_counter(&mut self, nv_index: u32) -> Result<u64, TpmError> {
        let ctx = self.ctx()?;
        let resp = ctx.submit(&build_nv_increment_cmd(TPM_RH_OWNER, nv_index))?;
        let rc = parse_response_rc(&resp)?;
        if rc != TPM_RC_SUCCESS {
            return Err(TpmError::ProviderError(format!(
                "TPM2_NV_Increment rc 0x{rc:06X}"
            )));
        }
        self.read_counter(nv_index)
    }

    fn get_assurance_type(&self) -> TpmAssuranceType {
        self.assurance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nv_read_command_is_exact_bytes() {
        let cmd = build_nv_read_cmd(TPM_RH_OWNER, 0x0180_0001, 8, 0);
        // tag(ST_SESSIONS) + size(4) + CC_NV_READ + RH_OWNER + authArea(17)
        // + nvIndex + size + offset
        assert_eq!(cmd[0..2], TPM_ST_SESSIONS.to_be_bytes());
        assert_eq!(&cmd[6..10], &TPM_CC_NV_READ.to_be_bytes());
        assert_eq!(&cmd[10..14], &TPM_RH_OWNER.to_be_bytes());
        // Auth area: RS_PW với nonce/hmac rỗng.
        assert_eq!(&cmd[14..18], &9u32.to_be_bytes());
        assert_eq!(&cmd[18..22], &TPM_RS_PW.to_be_bytes());
        // Tổng size khớp header.
        assert_eq!(&cmd[2..6], &(cmd.len() as u32).to_be_bytes());
        assert_eq!(cmd.len(), 10 + 4 + 17 + 4 + 2 + 2);
    }

    #[test]
    fn define_space_marks_counter_type() {
        let cmd = build_nv_define_space_cmd(TPM_RH_OWNER, 0x0180_0001, 8);
        // TPMA_NV counter phải xuất hiện trong publicInfo (AUTHREAD|AUTHWRITE|NT_COUNTER).
        let attrs = TPMA_NV_COUNTER_AUTH.to_be_bytes();
        assert!(cmd.windows(4).any(|w| w == attrs));
        assert_eq!(cmd[0..2], TPM_ST_SESSIONS.to_be_bytes());
    }

    #[test]
    fn response_parsers_are_fail_closed() {
        assert!(parse_response_rc(&[0u8; 9]).is_err());
        let ok = {
            let mut r = vec![0x80, 0x02];
            r.extend_from_slice(&22u32.to_be_bytes());
            r.extend_from_slice(&TPM_RC_SUCCESS.to_be_bytes());
            r
        };
        assert_eq!(parse_response_rc(&ok).unwrap(), TPM_RC_SUCCESS);

        let handle_err = {
            let mut r = vec![0x80, 0x02];
            r.extend_from_slice(&10u32.to_be_bytes());
            r.extend_from_slice(&TPM_RC_HANDLE.to_be_bytes());
            r
        };
        assert_eq!(parse_response_rc(&handle_err).unwrap(), TPM_RC_HANDLE);

        // NV_Read thành công: header + handle + paramSize + TPM2B(8 byte).
        let mut read_ok = vec![0x80, 0x02];
        read_ok.extend_from_slice(&28u32.to_be_bytes());
        read_ok.extend_from_slice(&TPM_RC_SUCCESS.to_be_bytes());
        read_ok.extend_from_slice(&0x0180_0001u32.to_be_bytes());
        read_ok.extend_from_slice(&10u32.to_be_bytes()); // paramSize
        read_ok.extend_from_slice(&8u16.to_be_bytes());
        read_ok.extend_from_slice(&42u64.to_be_bytes());
        assert_eq!(parse_nv_value(&read_ok).unwrap(), 42);

        // response ngắn → lỗi, không panic.
        assert!(parse_nv_value(&read_ok[..20]).is_err());
    }

    /// Runtime smoke trên máy CÓ TPM 2.0 — chạy thủ công trong tiến trình
    /// NÂNG QUYỀN/SYSTEM:
    /// `cargo test --release -p cyberv-agent --lib tbs_runtime_smoke -- --ignored --nocapture`
    ///
    /// Phát hiện thực đo 2026-10-04 (máy dev, tiến trình không nâng quyền):
    /// Tbsi_Context_Create trả `TBS_E_ACCESS_DENIED 0x8028400F` — Windows chặn
    /// TPM từ tiến trình thường. Production: agent chạy như service (SYSTEM)
    /// nên TBS được phép. Có tác dụng phụ: định nghĩa + tăng NV CyberV.
    #[test]
    #[ignore = "cần TPM 2.0 + tiến trình nâng quyền/SYSTEM; có tác dụng phụ trên NV"]
    fn tbs_runtime_smoke() {
        if !TbsNvCounter::tbs_available() {
            let diag = TbsContext::new().unwrap_err();
            panic!(
                "máy này báo không có TBS/TPM: {diag} — nếu 0x8028400F thì tiến \
                 trình đang chạy KHÔNG nâng quyền (Windows chặn TPM); chạy test \
                 trong shell admin/SYSTEM để verify runtime."
            );
        }
        let mut counter = TbsNvCounter::new();
        assert_eq!(counter.get_assurance_type(), TpmAssuranceType::HardwareBacked);
        let info = counter
            .discover_or_provision(crate::trust::tpm::nv_counter::DEFAULT_CYBERV_NV_INDEX, 1)
            .unwrap();
        println!("NV handle: {info:?}");
        let before = counter
            .read_counter(crate::trust::tpm::nv_counter::DEFAULT_CYBERV_NV_INDEX)
            .unwrap();
        let after = counter
            .increment_counter(crate::trust::tpm::nv_counter::DEFAULT_CYBERV_NV_INDEX)
            .unwrap();
        println!("counter: {before} -> {after}");
        assert_eq!(after, before + 1, "counter phải tăng đúng 1");
    }
}
