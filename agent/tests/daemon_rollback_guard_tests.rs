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
//! P2-1b — TPM NV counter anti-rollback guard wired vào daemon tick.
//!
//! Bất biến kiểm chứng:
//! - Rollback thật (counter mới NHỎ hơn lần đọc trước) ⟹ INV-006 lockdown
//!   ngay trong tick, TRƯỚC mọi attestation (SuspendedOrRejected).
//! - Lỗi đọc counter là TRUNG THỰC (READ_ERROR) — Unknown ≠ rollback (INV-002),
//!   daemon tiếp tục hoạt động bình thường.
//! - Chưa wire counter → NOT_WIRED, không bịa dữ liệu.
//! - Snapshot IPC phản ánh đúng trạng thái counter.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cyberv_agent::daemon::{AgentDaemon, AgentState};
use cyberv_agent::daemon_runner::{daemon_tick_loop, new_shared_status};
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::transport::client::MockDeviceTransport;
use cyberv_agent::trust::tpm::{TpmAssuranceType, TpmError, TpmNvCounter, TpmNvHandleInfo};

/// Counter giả LẬP TRÌNH ĐƯỢC giá trị — mô phỏng cả rollback (impossible
/// trên TPM thật, đúng tính chất đơn điệu cần test) lẫn lỗi I/O.
#[derive(Clone)]
struct RollbackSimulator {
    value: Arc<AtomicU64>,
    fail_read: Arc<AtomicBool>,
}

impl RollbackSimulator {
    fn new(initial: u64) -> Self {
        Self {
            value: Arc::new(AtomicU64::new(initial)),
            fail_read: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_value(&self, v: u64) {
        self.value.store(v, Ordering::SeqCst);
    }

    fn set_fail_read(&self, fail: bool) {
        self.fail_read.store(fail, Ordering::SeqCst);
    }
}

impl TpmNvCounter for RollbackSimulator {
    fn discover_or_provision(
        &mut self,
        _nv_index: u32,
        _initial_counter: u64,
    ) -> Result<TpmNvHandleInfo, TpmError> {
        Ok(TpmNvHandleInfo {
            nv_index: 0x01800001,
            attributes: Default::default(),
            assurance: TpmAssuranceType::SoftwareFallback,
            current_value: self.value.load(Ordering::SeqCst),
            is_provisioned_by_cyberv: true,
        })
    }

    fn read_counter(&self, _nv_index: u32) -> Result<u64, TpmError> {
        if self.fail_read.load(Ordering::SeqCst) {
            return Err(TpmError::ProviderError("TBS access denied (mô phỏng)".into()));
        }
        Ok(self.value.load(Ordering::SeqCst))
    }

    fn increment_counter(&mut self, _nv_index: u32) -> Result<u64, TpmError> {
        Ok(self.value.fetch_add(1, Ordering::SeqCst) + 1)
    }

    fn get_assurance_type(&self) -> TpmAssuranceType {
        TpmAssuranceType::SoftwareFallback
    }
}

fn daemon_with_counter(counter: RollbackSimulator) -> AgentDaemon<MockDeviceTransport, MockHardwareCollector> {
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut rng = OsCryptoRng;
    let identity_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    AgentDaemon::new(transport, collector, identity_key, "rollback-guard-dev", "test-jwt")
        .with_nv_counter(Box::new(counter), 0x01800001)
}

#[tokio::test]
async fn rollback_detection_locks_down_before_any_attestation() {
    let sim = RollbackSimulator::new(5);
    let sim2 = sim.clone();
    let mut daemon = daemon_with_counter(sim);

    // Tick 1: enroll (Unregistered → ...) — counter 5 đọc OK.
    let _ = daemon.tick().await.unwrap();
    assert_eq!(daemon.tpm_counter_status(), "OK");
    assert_eq!(daemon.tpm_last_counter(), Some(5));
    assert!(!daemon.tpm_rollback_detected());

    // Chạy tới Active (mock transport attest mọi challenge).
    for _ in 0..3 {
        if matches!(daemon.state(), AgentState::Active { .. }) {
            break;
        }
        let _ = daemon.tick().await.unwrap();
    }
    assert!(matches!(daemon.state(), AgentState::Active { .. }), "mock phải lên Active");

    // ROLLBACK: counter "tụt" 5 → 3 (không thể xảy ra trên TPM thật —
    // chính là bằng chứng snapshot bị tua).
    sim2.set_value(3);
    let state = daemon.tick().await.unwrap();
    assert!(matches!(state, AgentState::SuspendedOrRejected { .. }), "phải lockdown ngay");
    assert!(daemon.tpm_rollback_detected());
    assert!(
        daemon.tpm_counter_status().contains("ROLLBACK_DETECTED"),
        "status phải ghi rõ: {}",
        daemon.tpm_counter_status()
    );
    // Lockdown giữ vững ở các tick kế tiếp (không tự hồi phục).
    let state2 = daemon.tick().await.unwrap();
    assert!(matches!(state2, AgentState::SuspendedOrRejected { .. }));
    assert_eq!(daemon.tpm_last_counter(), Some(5), "giá trị tụt KHÔNG được ghi nhận làm baseline");
}

#[tokio::test]
async fn read_error_is_honest_not_rollback() {
    let sim = RollbackSimulator::new(7);
    let sim2 = sim.clone();
    let mut daemon = daemon_with_counter(sim);

    let _ = daemon.tick().await.unwrap();
    assert_eq!(daemon.tpm_counter_status(), "OK");

    // Mất khả năng đọc (vd TBS access denied): trung thực là READ_ERROR —
    // KHÔNG được coi là rollback (Unknown ≠ bằng chứng tấn công, INV-002).
    sim2.set_fail_read(true);
    let _ = daemon.tick().await.unwrap();
    assert!(daemon.tpm_counter_status().starts_with("READ_ERROR"));
    assert!(!daemon.tpm_rollback_detected());

    // Đọc lại được → tiếp tục bình thường.
    sim2.set_fail_read(false);
    sim2.set_value(9);
    let _ = daemon.tick().await.unwrap();
    assert_eq!(daemon.tpm_counter_status(), "OK");
    assert_eq!(daemon.tpm_last_counter(), Some(9));
}

#[tokio::test]
async fn not_wired_reports_honestly_and_never_locks_down() {
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut rng = OsCryptoRng;
    let identity_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let mut daemon = AgentDaemon::new(transport, collector, identity_key, "no-counter-dev", "jwt");

    for _ in 0..3 {
        let _ = daemon.tick().await.unwrap();
    }
    assert_eq!(daemon.tpm_counter_status(), "NOT_WIRED");
    assert!(!daemon.tpm_rollback_detected());
    assert_eq!(daemon.tpm_last_counter(), None);
    assert_eq!(daemon.tpm_assurance(), None);
}

#[tokio::test]
async fn tick_loop_snapshot_reflects_counter_state() {
    let sim = RollbackSimulator::new(2);
    let daemon = daemon_with_counter(sim);

    let status = new_shared_status();
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        flag.store(true, Ordering::SeqCst);
    });

    daemon_tick_loop(daemon, status.clone(), shutdown, 1).await.unwrap();
    let snap = status.read().unwrap().clone().unwrap();
    assert_eq!(snap.tpm_counter_status, "OK");
    assert_eq!(snap.tpm_last_counter, Some(2));
    assert!(!snap.tpm_rollback_detected);
}
