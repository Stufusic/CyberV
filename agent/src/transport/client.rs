//! CyberV HTTP & Mock Device Transport Implementations
//!
//! Ref: Rule.md Điều 1, 8, 18, 19: Kết nối bảo mật TLS, cơ chế Backoff Jitter, phân định rõ mã lỗi.

use super::error::TransportError;
use super::models::*;
use super::traits::DeviceTransport;
use crate::protocol::challenge::SignedChallengeProof;
use crate::protocol::enroll::DeviceEnrollmentRequest;
use crate::protocol::reenroll::ReenrollmentRequest;
use reqwest::{Client, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Triển khai Transport thực tế qua HTTPS sử dụng reqwest
#[derive(Clone)]
pub struct HttpDeviceTransport {
    client: Client,
    base_url: String,
    anon_key: String,
    max_retries: u32,
}

impl HttpDeviceTransport {
    pub fn new(base_url: impl Into<String>, anon_key: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            anon_key: anon_key.into(),
            max_retries: 3,
        }
    }

    pub fn with_client(
        client: Client,
        base_url: impl Into<String>,
        anon_key: impl Into<String>,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            anon_key: anon_key.into(),
            max_retries: 3,
        }
    }

    /// Gửi request JSON kèm retry với Exponential Backoff cho lỗi tạm thời
    async fn post_json_with_retry<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        endpoint: &str,
        body: &B,
        jwt: &str,
    ) -> Result<T, TransportError> {
        let url = format!("{}/{}", self.base_url, endpoint.trim_start_matches('/'));
        let mut attempts = 0;

        loop {
            attempts += 1;
            let response = self
                .client
                .post(&url)
                .header("apikey", &self.anon_key)
                .header("Authorization", format!("Bearer {}", jwt))
                .header("Content-Type", "application/json")
                .json(body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        let parsed = resp.json::<T>().await.map_err(|e| {
                            TransportError::Serialization(format!(
                                "Failed to parse JSON response: {}",
                                e
                            ))
                        })?;
                        return Ok(parsed);
                    }

                    // Xử lý các mã lỗi cụ thể
                    let error_body = resp.text().await.unwrap_or_default();

                    if status == StatusCode::UNAUTHORIZED {
                        return Err(TransportError::Unauthorized);
                    }
                    if status == StatusCode::FORBIDDEN {
                        return Err(TransportError::Forbidden(error_body));
                    }
                    if status == StatusCode::NOT_FOUND {
                        return Err(TransportError::NotFound(error_body));
                    }
                    if status == StatusCode::CONFLICT {
                        return Err(TransportError::Conflict(error_body));
                    }

                    // Các lỗi có thể thử lại: 429 Too Many Requests, 502, 503, 504
                    let is_retriable = status == StatusCode::TOO_MANY_REQUESTS
                        || status == StatusCode::BAD_GATEWAY
                        || status == StatusCode::SERVICE_UNAVAILABLE
                        || status == StatusCode::GATEWAY_TIMEOUT;

                    if is_retriable && attempts <= self.max_retries {
                        let delay = Duration::from_millis(100 * (1 << attempts));
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    return Err(TransportError::ServerError(status.as_u16(), error_body));
                }
                Err(err) => {
                    if err.is_timeout() {
                        if attempts <= self.max_retries {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                        return Err(TransportError::Timeout);
                    }

                    if attempts <= self.max_retries {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }

                    return Err(TransportError::NetworkFailure(err.to_string()));
                }
            }
        }
    }
}

impl DeviceTransport for HttpDeviceTransport {
    async fn enroll_device(
        &self,
        req: &DeviceEnrollmentRequest,
        jwt: &str,
    ) -> Result<EnrollResponseDto, TransportError> {
        let body = EnrollRequestDto {
            device_id: req.device_id.clone(),
            public_key: req.public_key_hex.clone(),
            current_graph_hash: req.current_graph_hash.clone(),
            current_state_hash: req.current_state_hash.clone(),
            current_graph_version: req.current_graph_version,
            canonical_graph_json: req.canonical_graph_json.clone(),
            signature_hex: req.proof_signature.clone(),
        };
        self.post_json_with_retry("enroll", &body, jwt).await
    }

    async fn request_challenge(
        &self,
        device_id: &str,
        purpose: &str,
        jwt: &str,
    ) -> Result<ChallengeResponseDto, TransportError> {
        let body = ChallengeRequestDto {
            device_id: device_id.to_string(),
            purpose: purpose.to_string(),
        };
        self.post_json_with_retry("challenge", &body, jwt).await
    }

    async fn submit_attestation(
        &self,
        proof: &SignedChallengeProof,
        jwt: &str,
    ) -> Result<VerifyStateResponseDto, TransportError> {
        let body = VerifyStateRequestDto {
            challenge_id: proof.challenge_id.clone(),
            nonce: proof.nonce.clone(),
            device_id: proof.device_id.clone(),
            purpose: proof.purpose.clone(),
            state_hash: proof.state_hash.clone(),
            graph_version: proof.graph_version,
            signature_hex: proof.signature_hex.clone(),
        };
        self.post_json_with_retry("verify-state", &body, jwt).await
    }

    async fn submit_reenrollment(
        &self,
        req: &ReenrollmentRequest,
        new_graph_json: serde_json::Value,
        changes: &[ComponentDiffDto],
        has_partial_status: bool,
        jwt: &str,
    ) -> Result<ReenrollResponseDto, TransportError> {
        let body = ReenrollRequestDto {
            device_id: req.device_id.clone(),
            previous_state_hash: req.previous_state_hash.clone(),
            new_state_hash: req.new_state_hash.clone(),
            new_graph_hash: req.new_graph_hash.clone(),
            new_graph_version: req.new_graph_version,
            new_graph_json,
            changes: changes.to_vec(),
            has_partial_status,
            reason: req.reason.clone(),
            signature_hex: req.proof_signature.clone(),
        };
        self.post_json_with_retry("re-enroll", &body, jwt).await
    }

    async fn rotate_key(
        &self,
        req: &crate::protocol::key_rotation::KeyRotationRequest,
        jwt: &str,
    ) -> Result<KeyRotationResponseDto, TransportError> {
        let body = KeyRotationRequestDto {
            device_id: req.device_id.clone(),
            old_public_key: req.old_public_key_hex.clone(),
            new_public_key: req.new_public_key_hex.clone(),
            state_hash: req.state_hash.clone(),
            graph_version: req.graph_version,
            nonce: req.nonce.clone(),
            timestamp: req.timestamp,
            signature_old: req.signature_old.clone(),
            signature_new: req.signature_new.clone(),
        };
        self.post_json_with_retry("key-rotate", &body, jwt).await
    }
}

/// Triển khai Mock Transport phục vụ kiểm thử đơn vị & kiểm thử bảo mật
#[derive(Clone, Default)]
pub struct MockDeviceTransport {
    pub mock_enroll_response: Arc<Mutex<Option<EnrollResponseDto>>>,
    pub mock_challenge_response: Arc<Mutex<Option<ChallengeResponseDto>>>,
    pub mock_attest_response: Arc<Mutex<Option<VerifyStateResponseDto>>>,
    pub mock_reenroll_response: Arc<Mutex<Option<ReenrollResponseDto>>>,
    pub mock_rotate_response: Arc<Mutex<Option<KeyRotationResponseDto>>>,
    pub forced_error: Arc<Mutex<Option<TransportError>>>,
    pub recorded_requests: Arc<Mutex<Vec<String>>>,
}

impl MockDeviceTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set_enroll_response(&self, resp: EnrollResponseDto) {
        let mut guard = self.mock_enroll_response.lock().await;
        *guard = Some(resp);
    }

    pub async fn set_challenge_response(&self, resp: ChallengeResponseDto) {
        let mut guard = self.mock_challenge_response.lock().await;
        *guard = Some(resp);
    }

    pub async fn set_attest_response(&self, resp: VerifyStateResponseDto) {
        let mut guard = self.mock_attest_response.lock().await;
        *guard = Some(resp);
    }

    pub async fn set_reenroll_response(&self, resp: ReenrollResponseDto) {
        let mut guard = self.mock_reenroll_response.lock().await;
        *guard = Some(resp);
    }

    pub async fn set_rotate_response(&self, resp: KeyRotationResponseDto) {
        let mut guard = self.mock_rotate_response.lock().await;
        *guard = Some(resp);
    }

    pub async fn set_forced_error(&self, err: Option<TransportError>) {
        let mut guard = self.forced_error.lock().await;
        *guard = err;
    }

    pub async fn get_recorded_requests(&self) -> Vec<String> {
        self.recorded_requests.lock().await.clone()
    }
}

impl DeviceTransport for MockDeviceTransport {
    async fn enroll_device(
        &self,
        req: &DeviceEnrollmentRequest,
        _jwt: &str,
    ) -> Result<EnrollResponseDto, TransportError> {
        self.recorded_requests
            .lock()
            .await
            .push(format!("enroll:{}", req.device_id));

        if let Some(err) = self.forced_error.lock().await.clone() {
            return Err(err);
        }

        let guard = self.mock_enroll_response.lock().await;
        if let Some(resp) = &*guard {
            Ok(resp.clone())
        } else {
            Ok(EnrollResponseDto {
                status: "ACTIVE".to_string(),
                device_id: req.device_id.clone(),
                graph_version: Some(req.current_graph_version),
                message: Some("Mock device enrolled".to_string()),
            })
        }
    }

    async fn request_challenge(
        &self,
        device_id: &str,
        purpose: &str,
        _jwt: &str,
    ) -> Result<ChallengeResponseDto, TransportError> {
        self.recorded_requests
            .lock()
            .await
            .push(format!("challenge:{}:{}", device_id, purpose));

        if let Some(err) = self.forced_error.lock().await.clone() {
            return Err(err);
        }

        let guard = self.mock_challenge_response.lock().await;
        if let Some(resp) = &*guard {
            Ok(resp.clone())
        } else {
            Ok(ChallengeResponseDto {
                challenge_id: uuid::Uuid::new_v4().to_string(),
                nonce: "0123456789abcdef".repeat(4),
                issued_at: Some("2026-09-05T00:00:00Z".to_string()),
                expires_at: Some("2026-09-05T00:01:00Z".to_string()),
                purpose: Some(purpose.to_string()),
            })
        }
    }

    async fn submit_attestation(
        &self,
        proof: &SignedChallengeProof,
        _jwt: &str,
    ) -> Result<VerifyStateResponseDto, TransportError> {
        self.recorded_requests
            .lock()
            .await
            .push(format!("verify-state:{}", proof.device_id));

        if let Some(err) = self.forced_error.lock().await.clone() {
            return Err(err);
        }

        let guard = self.mock_attest_response.lock().await;
        if let Some(resp) = &*guard {
            Ok(resp.clone())
        } else {
            Ok(VerifyStateResponseDto {
                authenticated: true,
                status: "AUTHENTICATED".to_string(),
                message: Some("Mock verification passed".to_string()),
                expected_state_hash: Some(proof.state_hash.clone()),
                presented_state_hash: Some(proof.state_hash.clone()),
            })
        }
    }

    async fn submit_reenrollment(
        &self,
        req: &ReenrollmentRequest,
        _new_graph_json: serde_json::Value,
        _changes: &[ComponentDiffDto],
        _has_partial_status: bool,
        _jwt: &str,
    ) -> Result<ReenrollResponseDto, TransportError> {
        self.recorded_requests
            .lock()
            .await
            .push(format!("re-enroll:{}", req.device_id));

        if let Some(err) = self.forced_error.lock().await.clone() {
            return Err(err);
        }

        let guard = self.mock_reenroll_response.lock().await;
        if let Some(resp) = &*guard {
            Ok(resp.clone())
        } else {
            Ok(ReenrollResponseDto {
                status: "ACTIVE".to_string(),
                decision: Some("AUTO_PROMOTE".to_string()),
                request_id: None,
                message: Some("Mock auto-promoted".to_string()),
                error: None,
            })
        }
    }

    async fn rotate_key(
        &self,
        req: &crate::protocol::key_rotation::KeyRotationRequest,
        _jwt: &str,
    ) -> Result<KeyRotationResponseDto, TransportError> {
        self.recorded_requests
            .lock()
            .await
            .push(format!("key-rotate:{}", req.device_id));

        if let Some(err) = self.forced_error.lock().await.clone() {
            return Err(err);
        }

        let guard = self.mock_rotate_response.lock().await;
        if let Some(resp) = &*guard {
            Ok(resp.clone())
        } else {
            Ok(KeyRotationResponseDto {
                success: true,
                status: "ACTIVE".to_string(),
                new_public_key: req.new_public_key_hex.clone(),
                message: Some("Mock key rotation successful".to_string()),
            })
        }
    }
}
