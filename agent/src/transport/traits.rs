//! CyberV Device Transport Trait Abstraction
//!
//! Ref: Rule.md Điều 1, 8, 20. Cho phép cắm rút giữa HTTP Network thật và Mock phục vụ test.

use super::error::TransportError;
use super::models::*;
use crate::protocol::challenge::SignedChallengeProof;
use crate::protocol::enroll::DeviceEnrollmentRequest;
use crate::protocol::reenroll::ReenrollmentRequest;

/// Trait trừu tượng hóa giao tiếp mạng giữa Agent và Server
pub trait DeviceTransport: Send + Sync {
    /// Đăng ký thiết bị lần đầu lên Cloud (POST /enroll)
    fn enroll_device<'a>(
        &'a self,
        req: &'a DeviceEnrollmentRequest,
        jwt: &'a str,
    ) -> impl std::future::Future<Output = Result<EnrollResponseDto, TransportError>> + Send + 'a;

    /// Yêu cầu Nonce thử thách từ Server (POST /challenge)
    fn request_challenge<'a>(
        &'a self,
        device_id: &'a str,
        purpose: &'a str,
        jwt: &'a str,
    ) -> impl std::future::Future<Output = Result<ChallengeResponseDto, TransportError>> + Send + 'a;

    /// Gửi Proof-of-Possession chứng thực trạng thái thiết bị (POST /verify-state)
    fn submit_attestation<'a>(
        &'a self,
        proof: &'a SignedChallengeProof,
        jwt: &'a str,
    ) -> impl std::future::Future<Output = Result<VerifyStateResponseDto, TransportError>> + Send + 'a;

    /// Gửi yêu cầu Tái cấp quyền khi linh kiện thay đổi (POST /re-enroll)
    fn submit_reenrollment<'a>(
        &'a self,
        req: &'a ReenrollmentRequest,
        new_graph_json: serde_json::Value,
        changes: &'a [ComponentDiffDto],
        has_partial_status: bool,
        jwt: &'a str,
    ) -> impl std::future::Future<Output = Result<ReenrollResponseDto, TransportError>> + Send + 'a;

    /// Gửi yêu cầu Quay vòng Khóa Ký (POST /key-rotate)
    fn rotate_key<'a>(
        &'a self,
        req: &'a crate::protocol::key_rotation::KeyRotationRequest,
        jwt: &'a str,
    ) -> impl std::future::Future<Output = Result<KeyRotationResponseDto, TransportError>> + Send + 'a;
}
