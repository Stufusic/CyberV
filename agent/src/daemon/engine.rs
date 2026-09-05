//! CyberV Agent Daemon Engine
//!
//! Ref: Plan.md Section 1, 15, 17, 18, Rule.md Điều 1, 8, 15, 17, 18:
//! Vòng lặp giám sát tự hành: Quan sát phần cứng -> Chứng thực định kỳ -> Tự động phát hiện biến động -> Re-enrollment.

use super::{AgentState, DaemonConfig};
use crate::fingerprint::component_hasher::hash_snapshot;
use crate::fingerprint::graph::builder::build_evidence_graph;
use crate::fingerprint::graph::diff::diff_evidence_graphs;
use crate::fingerprint::graph::models::DeviceEvidenceGraph;
use crate::fingerprint::state_hasher::evaluate_device_state;
use crate::hardware::collector::HardwareCollector;
use crate::hardware::models::ComponentStatus;
use crate::identity::keypair::DeviceIdentityKey;
use crate::protocol::challenge::{create_challenge_proof, ChallengeObject};
use crate::protocol::constants::PURPOSE_DEVICE_AUTH;
use crate::protocol::enroll::create_enrollment_request;
use crate::protocol::reenroll::create_reenrollment_request;
use crate::transport::error::TransportError;
use crate::transport::models::{
    ComponentDiffDto, EnrollResponseDto, KeyRotationResponseDto, ReenrollResponseDto,
    VerifyStateResponseDto,
};
use crate::transport::traits::DeviceTransport;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn standard_context_attrs() -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    attrs.insert("os".to_string(), std::env::consts::OS.to_string());
    attrs.insert("arch".to_string(), std::env::consts::ARCH.to_string());
    attrs.insert(
        "agent_ver".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    );
    attrs
}

/// Daemon tiến trình giám sát và liên kết thiết bị CyberV
pub struct AgentDaemon<T: DeviceTransport, C: HardwareCollector> {
    transport: T,
    collector: C,
    identity_key: DeviceIdentityKey,
    device_id: String,
    user_jwt: String,
    config: DaemonConfig,
    state: AgentState,
    current_graph: Option<DeviceEvidenceGraph>,
    current_graph_version: u32,
    current_state_hash: Option<String>,
}

impl<T: DeviceTransport, C: HardwareCollector> AgentDaemon<T, C> {
    pub fn new(
        transport: T,
        collector: C,
        identity_key: DeviceIdentityKey,
        device_id: impl Into<String>,
        user_jwt: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            collector,
            identity_key,
            device_id: device_id.into(),
            user_jwt: user_jwt.into(),
            config: DaemonConfig::default(),
            state: AgentState::Unregistered,
            current_graph: None,
            current_graph_version: 1,
            current_state_hash: None,
        }
    }

    pub fn with_config(mut self, config: DaemonConfig) -> Self {
        self.config = config;
        self
    }

    pub fn state(&self) -> &AgentState {
        &self.state
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn current_graph_version(&self) -> u32 {
        self.current_graph_version
    }

    pub fn current_state_hash(&self) -> Option<&str> {
        self.current_state_hash.as_deref()
    }

    pub fn set_user_jwt(&mut self, jwt: impl Into<String>) {
        self.user_jwt = jwt.into();
    }

    pub fn set_collector(&mut self, collector: C) {
        self.collector = collector;
    }

    pub fn identity_key(&self) -> &DeviceIdentityKey {
        &self.identity_key
    }

    /// Đăng ký thiết bị lần đầu với Server
    pub async fn enroll(&mut self) -> Result<EnrollResponseDto, TransportError> {
        let snapshot = self
            .collector
            .collect()
            .map_err(|e| TransportError::Serialization(format!("Collector error: {}", e)))?;

        let hashed = hash_snapshot(&snapshot);
        let graph = build_evidence_graph(&hashed, 1);
        let context = standard_context_attrs();
        let state_eval =
            evaluate_device_state(&self.device_id, 1, &graph.verification_hash, &context);

        let canonical_json = serde_json::to_value(&graph)
            .map_err(|e| TransportError::Serialization(format!("Graph serialize error: {}", e)))?;

        let enroll_req = create_enrollment_request(
            &self.identity_key,
            &self.device_id,
            &graph.graph_hash,
            &state_eval.state_hash,
            1,
            canonical_json,
        )
        .map_err(|e| TransportError::Serialization(format!("Crypto error: {}", e)))?;

        let resp = self
            .transport
            .enroll_device(&enroll_req, &self.user_jwt)
            .await?;

        if resp.status == "ACTIVE" {
            let state_hash = state_eval.state_hash.clone();
            self.current_graph = Some(graph);
            self.current_graph_version = 1;
            self.current_state_hash = Some(state_hash.clone());
            self.state = AgentState::Active {
                graph_version: 1,
                state_hash,
                last_attested_at: now_secs(),
            };
        }

        Ok(resp)
    }

    /// Thực hiện một chu kỳ chứng thực định kỳ (Challenge-Response Attestation)
    pub async fn attest_step(&mut self) -> Result<VerifyStateResponseDto, TransportError> {
        let state_hash = match &self.current_state_hash {
            Some(h) => h.clone(),
            None => {
                return Err(TransportError::Forbidden(
                    "Cannot attest unregistered device".to_string(),
                ));
            }
        };

        // 1. Nhận Nonce thử thách từ Server
        let chal_resp = self
            .transport
            .request_challenge(&self.device_id, PURPOSE_DEVICE_AUTH, &self.user_jwt)
            .await?;

        let challenge = ChallengeObject {
            challenge_id: chal_resp.challenge_id,
            nonce: chal_resp.nonce,
            device_id: self.device_id.clone(),
            purpose: PURPOSE_DEVICE_AUTH.to_string(),
            issued_at: now_secs(),
            expires_at: now_secs() + 60,
        };

        // 2. Ký số Proof-of-Possession
        let proof = create_challenge_proof(
            &self.identity_key,
            &challenge,
            &state_hash,
            self.current_graph_version,
        )
        .map_err(|e| TransportError::Serialization(format!("Sign proof error: {}", e)))?;

        // 3. Gửi lên server
        let verify_resp = self
            .transport
            .submit_attestation(&proof, &self.user_jwt)
            .await?;

        if verify_resp.authenticated && verify_resp.status == "AUTHENTICATED" {
            if let AgentState::Active {
                ref mut last_attested_at,
                ..
            } = self.state
            {
                *last_attested_at = now_secs();
            }
        }

        Ok(verify_resp)
    }

    /// Kích hoạt quy trình Tái Cấp Quyền khi phát hiện linh kiện thay đổi
    pub async fn trigger_reenrollment(
        &mut self,
        new_graph: DeviceEvidenceGraph,
        new_state_hash: String,
        reason: &str,
    ) -> Result<ReenrollResponseDto, TransportError> {
        let old_graph = match &self.current_graph {
            Some(g) => g,
            None => {
                return Err(TransportError::Forbidden(
                    "No baseline graph found for re-enrollment".to_string(),
                ));
            }
        };

        let diff = diff_evidence_graphs(old_graph, &new_graph);
        let mut changes = Vec::new();
        for c in &diff.changes {
            changes.push(ComponentDiffDto {
                target_id: c.target_id.clone(),
                operation: format!("{:?}", c.operation),
            });
        }

        let has_partial = new_graph
            .nodes
            .iter()
            .any(|n| n.status == ComponentStatus::Partial);

        let new_version = self.current_graph_version + 1;
        let prev_state_hash = self.current_state_hash.clone().unwrap_or_default();

        let reenroll_req = create_reenrollment_request(
            &self.identity_key,
            &self.device_id,
            &prev_state_hash,
            &new_state_hash,
            &new_graph.graph_hash,
            new_version,
            reason,
        )
        .map_err(|e| TransportError::Serialization(format!("Reenroll crypto error: {}", e)))?;

        let new_graph_json = serde_json::to_value(&new_graph)
            .map_err(|e| TransportError::Serialization(format!("Graph serialize error: {}", e)))?;

        let resp = self
            .transport
            .submit_reenrollment(
                &reenroll_req,
                new_graph_json,
                &changes,
                has_partial,
                &self.user_jwt,
            )
            .await?;

        match resp.status.as_str() {
            "ACTIVE" => {
                // Auto-promoted
                self.current_graph_version = new_version;
                self.current_graph = Some(new_graph);
                self.current_state_hash = Some(new_state_hash.clone());
                self.state = AgentState::Active {
                    graph_version: new_version,
                    state_hash: new_state_hash,
                    last_attested_at: now_secs(),
                };
            }
            "PENDING_APPROVAL" => {
                self.state = AgentState::PendingApproval {
                    request_id: resp.request_id.clone(),
                    submitted_at: now_secs(),
                };
            }
            _ => {
                self.state = AgentState::SuspendedOrRejected {
                    reason: resp
                        .error
                        .clone()
                        .unwrap_or_else(|| "Re-enrollment rejected".to_string()),
                };
            }
        }

        Ok(resp)
    }

    /// Thực hiện quy trình quay vòng cặp khóa ký Ed25519 (Key Rotation Protocol - Phase 8)
    pub async fn rotate_identity_key(&mut self) -> Result<KeyRotationResponseDto, TransportError> {
        let current_state_hash = self.current_state_hash.clone().ok_or_else(|| {
            TransportError::Serialization("Cannot rotate key before initial enrollment".to_string())
        })?;

        // 1. Sinh khóa Ed25519 mới ngẫu nhiên độc lập từ OS CSPRNG
        let mut rng = crate::identity::rng::OsCryptoRng;
        let new_identity_key = DeviceIdentityKey::generate(&mut rng)
            .map_err(|e| TransportError::Serialization(format!("Key generation error: {}", e)))?;

        // 2. Xin Nonce thử thách từ Server cho mục đích "key-rotation"
        let challenge = self
            .transport
            .request_challenge(
                &self.device_id,
                crate::protocol::constants::PURPOSE_KEY_ROTATION,
                &self.user_jwt,
            )
            .await?;

        // 3. Tạo yêu cầu quay vòng khóa có chữ ký kép (Dual-Proof-of-Possession)
        let rotation_req = crate::protocol::key_rotation::create_key_rotation_request(
            &self.identity_key,
            &new_identity_key,
            &self.device_id,
            &current_state_hash,
            self.current_graph_version,
            &challenge.nonce,
            now_secs(),
        )
        .map_err(|e| TransportError::Serialization(format!("Key rotation crypto error: {}", e)))?;

        // 4. Gửi lên server qua Transport
        let resp = self
            .transport
            .rotate_key(&rotation_req, &self.user_jwt)
            .await?;

        if resp.success {
            // Server đã chấp thuận -> Cập nhật khóa hiện hành trong Daemon
            self.identity_key = new_identity_key;
        }

        Ok(resp)
    }

    /// Một nhịp kiểm tra tự hành (Single Tick) của Daemon
    pub async fn tick(&mut self) -> Result<AgentState, TransportError> {
        match self.state.clone() {
            AgentState::Unregistered => {
                self.enroll().await?;
                Ok(self.state.clone())
            }
            AgentState::Active {
                graph_version,
                state_hash,
                ..
            } => {
                // 1. Thu thập phần cứng mới
                let snapshot = match self.collector.collect() {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(TransportError::Serialization(format!(
                            "Collection failed: {}",
                            e
                        )));
                    }
                };

                let hashed = hash_snapshot(&snapshot);
                let fresh_graph = build_evidence_graph(&hashed, graph_version);
                let context = standard_context_attrs();
                let fresh_state = evaluate_device_state(
                    &self.device_id,
                    graph_version,
                    &fresh_graph.verification_hash,
                    &context,
                );

                if fresh_state.state_hash == state_hash {
                    // Phần cứng nguyên vẹn -> Thực hiện Attestation định kỳ
                    match self.attest_step().await {
                        Ok(_) => Ok(self.state.clone()),
                        Err(err) => match err {
                            TransportError::NetworkFailure(_) | TransportError::Timeout => {
                                self.state = AgentState::OfflineGracePeriod {
                                    consecutive_failures: 1,
                                    last_success_at: now_secs(),
                                };
                                Ok(self.state.clone())
                            }
                            TransportError::Unauthorized => Err(err),
                            TransportError::Forbidden(ref msg) => {
                                self.state = AgentState::SuspendedOrRejected {
                                    reason: msg.clone(),
                                };
                                Ok(self.state.clone())
                            }
                            _ => Err(err),
                        },
                    }
                } else {
                    // Phát hiện biến động phần cứng!
                    let new_version = graph_version + 1;
                    let promoted_graph = build_evidence_graph(&hashed, new_version);
                    let promoted_state = evaluate_device_state(
                        &self.device_id,
                        new_version,
                        &promoted_graph.verification_hash,
                        &context,
                    );

                    self.state = AgentState::HardwareMutated {
                        previous_graph_version: graph_version,
                        previous_state_hash: state_hash,
                        new_state_hash: promoted_state.state_hash.clone(),
                    };

                    self.trigger_reenrollment(
                        promoted_graph,
                        promoted_state.state_hash,
                        "Hardware mutation detected by autonomous daemon",
                    )
                    .await?;

                    Ok(self.state.clone())
                }
            }
            AgentState::HardwareMutated {
                previous_graph_version,
                previous_state_hash: _,
                new_state_hash: _,
            } => {
                // Đã ở trạng thái mutated, thử kích hoạt lại re-enrollment nếu chưa giải quyết
                let snapshot = self.collector.collect().map_err(|e| {
                    TransportError::Serialization(format!("Collection failed: {}", e))
                })?;
                let hashed = hash_snapshot(&snapshot);
                let new_version = previous_graph_version + 1;
                let fresh_graph = build_evidence_graph(&hashed, new_version);
                let context = standard_context_attrs();
                let fresh_state = evaluate_device_state(
                    &self.device_id,
                    new_version,
                    &fresh_graph.verification_hash,
                    &context,
                );

                self.trigger_reenrollment(
                    fresh_graph,
                    fresh_state.state_hash,
                    "Retrying pending hardware re-enrollment",
                )
                .await?;

                Ok(self.state.clone())
            }
            AgentState::OfflineGracePeriod {
                consecutive_failures,
                last_success_at,
            } => {
                // Thử kết nối lại
                match self.attest_step().await {
                    Ok(_) => {
                        self.state = AgentState::Active {
                            graph_version: self.current_graph_version,
                            state_hash: self.current_state_hash.clone().unwrap_or_default(),
                            last_attested_at: now_secs(),
                        };
                        Ok(self.state.clone())
                    }
                    Err(err) => {
                        let elapsed = now_secs().saturating_sub(last_success_at);
                        if elapsed > self.config.max_offline_grace_secs {
                            self.state = AgentState::SuspendedOrRejected {
                                reason: "Offline grace period expired".to_string(),
                            };
                        } else {
                            self.state = AgentState::OfflineGracePeriod {
                                consecutive_failures: consecutive_failures + 1,
                                last_success_at,
                            };
                        }
                        Err(err)
                    }
                }
            }
            AgentState::PendingApproval { .. } => {
                // Đang chờ người dùng duyệt trên Dashboard
                Ok(self.state.clone())
            }
            AgentState::SuspendedOrRejected { .. } => {
                // Bị khóa
                Ok(self.state.clone())
            }
        }
    }
}
