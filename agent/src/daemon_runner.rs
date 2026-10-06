//! CyberV Daemon Runner (P1-2 — wire AgentDaemon thật vào service)
//!
//! Ref: Docs/PHASE1_2_IMPLEMENTATION_PLAN.md P1-2 + Docs/DEFENSE_ROADMAP.md Trụ 1.
//!
//! Nhiệm vụ: chạy `AgentDaemon::tick()` thật trong Windows Service hoặc CLI
//! foreground, bơm trạng thái vào `SharedAgentStatus` để IPC `GetStatus` phản
//! ánh TRẠNG THÁI THẬT (thay cho hằng số "PROTECTED" bịa từ trước — đã xóa).
//!
//! Nguyên tắc:
//! - Identity nạp/tạo từ DPAPI vault (như đường demo, KHÔNG key cứng).
//! - Transport/collector thật; không đường nào tham chiếu mock.
//! - Snapshot chỉ được cập nhật từ kết quả tick thật; không tick = không snapshot.

use crate::daemon::{AgentDaemon, AgentState, DaemonConfig};
use crate::hardware::collector::HardwareCollector;
use crate::hardware::windows::WindowsWmiCollector;
use crate::identity::{
    DeviceIdentityKey, DeviceSecureStorage, OsCryptoRng, PersistedIdentity, Secret32, SecureRandom,
    WindowsDpapiStorage,
};
use crate::kernel::client::WindowsKernelClient;
use crate::kernel::KernelProbeProvider;
use crate::service_config::AgentServiceConfig;
use crate::transport::client::HttpDeviceTransport;
use crate::transport::error::TransportError;
use crate::transport::traits::DeviceTransport;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Trạng thái agent được IPC `GetStatus` đọc — chỉ cập nhật từ tick thật.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatusSnapshot {
    /// UNREGISTERED / ACTIVE / HARDWARE_MUTATED / PENDING_APPROVAL /
    /// OFFLINE_GRACE / SUSPENDED_OR_REJECTED (...) / ERROR_UNAUTHORIZED
    pub state: String,
    pub device_id: String,
    pub graph_version: u32,
    pub last_attested_at: Option<u64>,
    /// Probe driver thật tại thời điểm snapshot (CreateFileW tới \\.\CyberVProbe)
    pub driver_available: bool,
    /// P2-1b: NOT_WIRED / OK / READ_ERROR: ... / ROLLBACK_DETECTED: ...
    pub tpm_counter_status: String,
    pub tpm_last_counter: Option<u64>,
    pub tpm_rollback_detected: bool,
    pub updated_at: u64,
}

pub type SharedAgentStatus = Arc<RwLock<Option<AgentStatusSnapshot>>>;

pub fn new_shared_status() -> SharedAgentStatus {
    Arc::new(RwLock::new(None))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn summarize_state(state: &AgentState) -> (String, u32, Option<u64>, bool) {
    match state {
        AgentState::Unregistered => ("UNREGISTERED".to_string(), 0, None, false),
        AgentState::Active {
            graph_version,
            last_attested_at,
            ..
        } => ("ACTIVE".to_string(), *graph_version, Some(*last_attested_at), true),
        AgentState::HardwareMutated {
            previous_graph_version,
            ..
        } => ("HARDWARE_MUTATED".to_string(), *previous_graph_version, None, false),
        AgentState::PendingApproval { .. } => ("PENDING_APPROVAL".to_string(), 0, None, false),
        AgentState::OfflineGracePeriod { .. } => ("OFFLINE_GRACE".to_string(), 0, None, false),
        AgentState::SuspendedOrRejected { reason } => (
            format!("SUSPENDED_OR_REJECTED ({})", reason),
            0,
            None,
            false,
        ),
    }
}

/// Map snapshot daemon → payload GetStatus IPC (honest: chỉ ACTIVE mới
/// hardware_verified=true; driver_available từ probe thật; các trường chưa có
/// dữ liệu thật để null thay vì bịa).
pub fn snapshot_to_getstatus_value(s: &AgentStatusSnapshot) -> serde_json::Value {
    let protection_state = match s.state.as_str() {
        "ACTIVE" => "ACTIVE_ATTESTED",
        st if st.starts_with("SUSPENDED_OR_REJECTED") => "ISOLATED",
        _ => "UNKNOWN",
    };
    serde_json::json!({
        "protection": {
            "state": protection_state,
            "substate": s.state,
            "driver_available": s.driver_available,
            "is_isolated": protection_state == "ISOLATED",
            "reason": format!("Live daemon state: {}", s.state)
        },
        "kernel_shield": {
            "is_active": s.driver_available,
            "driver_version": null,
            "cross_validator_active": false,
            "hook_bypass_protection": s.driver_available,
            "dacl_hardened": false,
            "last_attested_at": s.last_attested_at
        },
        "hardware_verified": s.state == "ACTIVE",
        // P2-1b: null khi counter chưa wire (trung thực — không bịa);
        // wired → object trạng thái thật.
        "tpm_contradiction": if s.tpm_counter_status == "NOT_WIRED" {
            serde_json::Value::Null
        } else {
            serde_json::json!({
                "counter_status": s.tpm_counter_status,
                "last_counter": s.tpm_last_counter,
                "rollback_detected": s.tpm_rollback_detected,
            })
        },
        "verification_hash": null,
        "graph_version": s.graph_version,
        "device_id": s.device_id,
        "snapshot_updated_at": s.updated_at
    })
}

/// Nạp identity từ DPAPI vault; nếu chưa có thì sinh mới và lưu.
/// Device seed và signing key đều sinh qua OS CSPRNG — không key cứng.
#[cfg(windows)]
pub fn load_or_create_identity() -> Result<(DeviceIdentityKey, String), String> {
    let storage = WindowsDpapiStorage::default_path()
        .map_err(|e| format!("Không xác định được đường dẫn vault: {:?}", e))?;

    if let Some(existing) = storage
        .load_identity()
        .map_err(|e| format!("Lỗi đọc vault identity: {:?}", e))?
    {
        // PersistedIdentity.signing_key đã là Secret32
        let key = DeviceIdentityKey::from_secret_bytes(&existing.signing_key)
            .map_err(|e| format!("Khôi phục khóa từ vault thất bại: {:?}", e))?;
        return Ok((key, existing.device_id));
    }

    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng)
        .map_err(|e| format!("Sinh khóa thất bại: {:?}", e))?;
    let mut seed_bytes = [0u8; 32];
    rng.fill(&mut seed_bytes)
        .map_err(|e| format!("Sinh device seed thất bại: {:?}", e))?;
    let device_seed = Secret32::new(seed_bytes);
    let dev_id = uuid::Uuid::new_v4().to_string();

    let new_identity = PersistedIdentity::new(
        dev_id.clone(),
        device_seed,
        key.secret_bytes(),
        now_secs(),
    );
    storage
        .save_identity(&new_identity)
        .map_err(|e| format!("Lưu vault thất bại: {:?}", e))?;
    Ok((key, dev_id))
}

#[cfg(not(windows))]
pub fn load_or_create_identity() -> Result<(DeviceIdentityKey, String), String> {
    Err("Identity vault (DPAPI) chỉ khả dụng trên Windows".to_string())
}

/// Vòng lặp tick của daemon: mỗi chu kỳ gọi `tick()`, cập nhật snapshot cho IPC,
/// xử lý lỗi theo hợp đồng state machine. Dừng khi `shutdown` bật hoặc lỗi
/// cấu hình không thể phục hồi (Unauthorized).
pub async fn daemon_tick_loop<T, C>(
    mut daemon: AgentDaemon<T, C>,
    status: SharedAgentStatus,
    shutdown: Arc<AtomicBool>,
    interval_secs: u64,
) -> Result<(), String>
where
    T: DeviceTransport + 'static,
    C: HardwareCollector + 'static,
{
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }

        let tick_result = daemon.tick().await;
        let (state_str, graph_version, last_attested, hardware_verified) =
            summarize_state(daemon.state());
        let driver_available = WindowsKernelClient::new().is_driver_available();

        *status.write().map_err(|_| "Status lock poisoned")? = Some(AgentStatusSnapshot {
            state: state_str,
            device_id: daemon.device_id().to_string(),
            graph_version,
            last_attested_at: last_attested,
            driver_available,
            tpm_counter_status: daemon.tpm_counter_status().to_string(),
            tpm_last_counter: daemon.tpm_last_counter(),
            tpm_rollback_detected: daemon.tpm_rollback_detected(),
            updated_at: now_secs(),
        });
        let _ = hardware_verified; // đã thể hiện qua state == "ACTIVE" trong map ở trên

        match tick_result {
            Ok(_) => {}
            Err(TransportError::Unauthorized) => {
                // JWT hết hạn/sai: lỗi cấu hình cần con người — dừng tick,
                // giữ snapshot trạng thái lỗi để UI hiển thị trung thực.
                if let Ok(mut guard) = status.write() {
                    if let Some(s) = guard.as_mut() {
                        s.state = "ERROR_UNAUTHORIZED".to_string();
                        s.updated_at = now_secs();
                    }
                }
                return Err("Daemon dừng: user_jwt bị từ chối (401) — cần cấp JWT mới".to_string());
            }
            Err(_) => {
                // Lỗi mạng/tạm thời: state machine đã chuyển OfflineGracePeriod
                // hoặc ghi nhận; vòng lặp tiếp tục theo interval.
            }
        }

        // Ngủ theo lát 1s để phản ứng kịp với shutdown flag
        for _ in 0..interval_secs.max(1) {
            if shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

/// Xây daemon thật từ config và chạy vòng lặp — dùng chung cho Windows Service
/// và CLI foreground.
pub async fn run_configured_daemon(
    config: AgentServiceConfig,
    status: SharedAgentStatus,
    shutdown: Arc<AtomicBool>,
) -> Result<(), String> {
    let transport = HttpDeviceTransport::new(&config.server_url, &config.anon_key)
        .map_err(|e| format!("Khởi tạo transport thất bại: {:?}", e))?;
    let collector = WindowsWmiCollector::new();
    let (identity_key, device_id) = load_or_create_identity()?;

    let daemon = AgentDaemon::new(
        transport,
        collector,
        identity_key,
        device_id,
        config.user_jwt.clone(),
    )
    // P2-1b: anti-rollback guard — TBS thật khi service SYSTEM được phép,
    // fallback phần mềm trung thực (assurance SoftwareFallback) khi không.
    .with_nv_counter(
        Box::new(crate::trust::tpm::WindowsTbsNvCounter::new()),
        crate::trust::tpm::DEFAULT_CYBERV_NV_INDEX,
    )
    .with_config(DaemonConfig {
        attestation_interval_secs: config.attestation_interval_secs,
        max_offline_grace_secs: config.max_offline_grace_secs,
    });

    daemon_tick_loop(daemon, status, shutdown, config.attestation_interval_secs).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::mock::MockHardwareCollector;
    use crate::transport::client::MockDeviceTransport;

    #[test]
    fn summarize_state_maps_all_variants() {
        let (s, _, _, hv) = summarize_state(&AgentState::Unregistered);
        assert_eq!(s, "UNREGISTERED");
        assert!(!hv);

        let (s, v, ts, hv) = summarize_state(&AgentState::Active {
            graph_version: 3,
            state_hash: "h".to_string(),
            last_attested_at: 12345,
        });
        assert_eq!(s, "ACTIVE");
        assert!(hv);
        assert_eq!(v, 3);
        assert_eq!(ts, Some(12345));

        let (s, _, _, _) = summarize_state(&AgentState::SuspendedOrRejected {
            reason: "test".to_string(),
        });
        assert!(s.starts_with("SUSPENDED_OR_REJECTED"));
    }

    #[test]
    fn getstatus_mapping_is_honest() {
        let snap = AgentStatusSnapshot {
            state: "ACTIVE".to_string(),
            device_id: "dev-1".to_string(),
            graph_version: 2,
            last_attested_at: Some(100),
            driver_available: true,
            tpm_counter_status: "NOT_WIRED".to_string(),
            tpm_last_counter: None,
            tpm_rollback_detected: false,
            updated_at: 200,
        };
        let v = snapshot_to_getstatus_value(&snap);
        assert_eq!(v["protection"]["state"], "ACTIVE_ATTESTED");
        assert_eq!(v["hardware_verified"], true);
        assert_eq!(v["kernel_shield"]["is_active"], true);
        // Trường chưa có dữ liệu thật phải là null, không bịa
        assert_eq!(v["verification_hash"], serde_json::Value::Null);
        assert_eq!(v["tpm_contradiction"], serde_json::Value::Null);

        // P2-1b: counter wired → object trạng thái thật, không null
        let mut wired = snap.clone();
        wired.tpm_counter_status = "OK".to_string();
        wired.tpm_last_counter = Some(42);
        let v1 = snapshot_to_getstatus_value(&wired);
        assert_eq!(v1["tpm_contradiction"]["counter_status"], "OK");
        assert_eq!(v1["tpm_contradiction"]["last_counter"], 42);
        assert_eq!(v1["tpm_contradiction"]["rollback_detected"], false);

        let mut rolled = snap.clone();
        rolled.tpm_counter_status = "ROLLBACK_DETECTED: counter 3 < lần đọc trước 5".to_string();
        rolled.tpm_rollback_detected = true;
        let v2 = snapshot_to_getstatus_value(&rolled);
        assert_eq!(v2["tpm_contradiction"]["rollback_detected"], true);

        let mut offline = snap.clone();
        offline.state = "OFFLINE_GRACE".to_string();
        offline.driver_available = false;
        let v2 = snapshot_to_getstatus_value(&offline);
        assert_eq!(v2["protection"]["state"], "UNKNOWN");
        assert_eq!(v2["hardware_verified"], false);
        assert_eq!(v2["kernel_shield"]["is_active"], false);

        let mut rejected = snap;
        rejected.state = "SUSPENDED_OR_REJECTED (policy)".to_string();
        let v3 = snapshot_to_getstatus_value(&rejected);
        assert_eq!(v3["protection"]["state"], "ISOLATED");
        assert_eq!(v3["protection"]["is_isolated"], true);
    }

    /// Snapshot phải phản ánh tick thật: với mock transport (always authenticated),
    /// daemon đi Unregistered → Active; tick loop cập nhật snapshot tương ứng.
    #[tokio::test]
    async fn tick_loop_updates_snapshot_from_real_ticks() {
        let transport = MockDeviceTransport::new();
        let collector = MockHardwareCollector::baseline().unwrap();
        let mut rng = OsCryptoRng;
        let identity_key = DeviceIdentityKey::generate(&mut rng).unwrap();

        let daemon = AgentDaemon::new(
            transport,
            collector,
            identity_key,
            "test-device-001",
            "test-jwt",
        );

        let status = new_shared_status();
        assert!(status.read().unwrap().is_none(), "chưa tick = chưa snapshot");

        let shutdown = Arc::new(AtomicBool::new(false));
        // Tắt ngay sau tick đầu tiên: dùng task tắt flag sau 500ms
        let flag = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            flag.store(true, Ordering::SeqCst);
        });

        let res = daemon_tick_loop(daemon, status.clone(), shutdown, 1).await;
        assert!(res.is_ok());

        let snap = status.read().unwrap().clone().expect("phải có snapshot sau tick");
        assert_eq!(snap.state, "ACTIVE", "mock transport authenticate mọi challenge");
        assert!(!snap.device_id.is_empty());
        assert!(snap.updated_at > 0);
    }
}
