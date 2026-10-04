//! CyberV NSG — Network Security Graph (mạng đồ thị an ninh) — tầng pure logic
//!
//! Ref: `Docs/NETWORK_SECURITY_GRAPH_PLAN.md` v2 (NSG-1 / NSG-1.5 / NSG-1.6):
//! đồ thị node bounded + máy trạng thái fail-closed, mô hình sự kiện có chữ ký
//! (NSG Event Model), quorum independence có trọng số (TrustScore 5 chiều),
//! epoch + partition/merge consistency.
//!
//! Ranh giới trung thực (INV-007): tầng này **chưa có I/O mạng** — khi NSG-2
//! hiện thực kênh truyền, mọi frame bắt buộc đi qua phiên AEAD + chữ ký
//! identity (INV-012 planned); không có đường nào nâng trust từ "ping được".
//! Các ngưỡng policy hiện là `Default` placeholder — khi NSG-3 chuyển sang
//! signed policy sẽ tái dụng kênh INV-011 và giá trị mặc định chỉ là sở khởi.

pub mod consistency;
pub mod correlation;
pub mod discovery;
pub mod events;
pub mod graph;
pub mod gossip;
pub mod quorum;
pub mod reputation;
pub mod session;
pub mod shadow;
pub mod sim;

use thiserror::Error;

/// Lỗi của tầng NSG. Toàn bộ nhánh lỗi là nhánh **từ chối** —
/// tầng này không có nhánh "lỗi thì cho qua".
#[derive(Error, Debug, PartialEq, Eq)]
pub enum MeshError {
    #[error("Node không tồn tại trong đồ thị: {0}")]
    UnknownNode(String),

    #[error("Chuyển trạng thái node không hợp lệ: từ {from} sang {to}")]
    IllegalTransition { from: &'static str, to: &'static str },

    #[error("Vượt giới hạn tài nguyên mesh ({kind}): đã từ chối {dropped} entry")]
    LimitExceeded { kind: &'static str, dropped: u64 },

    #[error("Cạnh/tham chiếu đồ thị không hợp lệ: {0}")]
    InvalidEdge(String),

    #[error("Sự kiện mesh bị từ chối khi xác thực: {0}")]
    EventRejected(String),

    #[error("Sự kiện stale/hết hạn/epoch bất hợp lệ bị từ chối: {0}")]
    StaleEvent(String),

    #[error("Replay sự kiện bị từ chối: {0}")]
    ReplayRejected(String),

    #[error("Frame mesh không hợp lệ: {0}")]
    Frame(String),

    #[error("Mật mã phiên mesh thất bại: {0}")]
    Crypto(String),

    #[error("Bắt tay mesh thất bại: {0}")]
    HandshakeFailed(String),

    #[error("Phiên bản wire mesh không hỗ trợ: {0}")]
    UnsupportedVersion(u32),
}
