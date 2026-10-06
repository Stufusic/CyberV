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
//! IPC Client Authorization & Token Validation (P24.4)
//!
//! Ref: Docs/rv13.md Section 5:
//! "Authenticated IPC: Xác thực Client PID & Token SID trước khi xử lý thông điệp."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcClientIdentity {
    pub client_pid: u32,
    pub client_sid: String,
    pub executable_name: String,
    pub is_authenticated: bool,
}

pub struct IpcAuthorizer;

impl IpcAuthorizer {
    /// Kiểm tra xem client kết nối vào pipe có phải là thành phần CyberV được ủy quyền hay không
    pub fn authorize_client(
        client_pid: u32,
        client_sid: &str,
        executable_name: &str,
        expected_sid: &str,
    ) -> IpcClientIdentity {
        let is_sid_valid = client_sid == expected_sid;
        let is_known_component = executable_name == "CyberVAgent.exe"
            || executable_name == "CyberVWatchdog.exe"
            || executable_name == "CyberVUpdater.exe"
            || executable_name == "CyberVUi.exe";

        let is_authenticated = is_sid_valid && is_known_component && client_pid > 0;

        IpcClientIdentity {
            client_pid,
            client_sid: client_sid.to_string(),
            executable_name: executable_name.to_string(),
            is_authenticated,
        }
    }
}
