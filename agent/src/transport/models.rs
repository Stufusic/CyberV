//! CyberV Transport DTO Models
//!
//! Các cấu trúc trao đổi dữ liệu qua mạng với Edge Functions.

use serde::{Deserialize, Serialize};

/// DTO mô tả thay đổi linh kiện gửi lên server khi re-enroll
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentDiffDto {
    pub target_id: String,
    pub operation: String,
}

/// DTO Yêu cầu Đăng ký Thiết bị ban đầu (POST /enroll)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequestDto {
    pub device_id: String,
    pub public_key: String,
    pub current_graph_hash: String,
    pub current_state_hash: String,
    pub current_graph_version: u32,
    pub canonical_graph_json: serde_json::Value,
    pub signature_hex: String,
}

/// DTO Phản hồi Đăng ký Thiết bị ban đầu
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponseDto {
    pub status: String,
    pub device_id: String,
    pub graph_version: Option<u32>,
    pub message: Option<String>,
}

/// DTO Yêu cầu Thử thách Xác thực (POST /challenge)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequestDto {
    pub device_id: String,
    pub purpose: String,
}

/// DTO Phản hồi Thử thách Xác thực
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResponseDto {
    pub challenge_id: String,
    pub nonce: String,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    pub purpose: Option<String>,
}

/// DTO Gửi Bằng chứng Xác thực Trạng thái (POST /verify-state)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyStateRequestDto {
    pub challenge_id: String,
    pub nonce: String,
    pub device_id: String,
    pub purpose: String,
    pub state_hash: String,
    pub graph_version: u32,
    pub signature_hex: String,
}

/// DTO Phản hồi Xác thực Trạng thái
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyStateResponseDto {
    pub authenticated: bool,
    pub status: String,
    pub message: Option<String>,
    pub expected_state_hash: Option<String>,
    pub presented_state_hash: Option<String>,
}

/// DTO Yêu cầu Tái cấp quyền Phần cứng (POST /re-enroll)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReenrollRequestDto {
    pub device_id: String,
    pub previous_state_hash: String,
    pub new_state_hash: String,
    pub new_graph_hash: String,
    pub new_graph_version: u32,
    pub new_graph_json: serde_json::Value,
    pub changes: Vec<ComponentDiffDto>,
    pub has_partial_status: bool,
    pub reason: String,
    pub signature_hex: String,
}

/// DTO Phản hồi Tái cấp quyền Phần cứng
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReenrollResponseDto {
    pub status: String,
    pub decision: Option<String>,
    pub request_id: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
}

/// DTO Yêu cầu Quay vòng Khóa Ký (POST /key-rotate)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationRequestDto {
    pub device_id: String,
    pub old_public_key: String,
    pub new_public_key: String,
    pub state_hash: String,
    pub graph_version: u32,
    pub nonce: String,
    pub timestamp: u64,
    pub signature_old: String,
    pub signature_new: String,
}

/// DTO Phản hồi Quay vòng Khóa Ký
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationResponseDto {
    pub success: bool,
    pub status: String,
    pub new_public_key: String,
    pub message: Option<String>,
}
