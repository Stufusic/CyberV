//! CyberV Protocol Constants and Domain Separators
//!
//! Khóa giao thức và cách ly không gian tên mật mã học theo rv.md, rv p3.md và Rule.md Điều 2, 20.

/// Tên định danh của giao thức
pub const PROTOCOL_ID: &str = "cyberv-device-binding";

/// Phiên bản giao thức hiện hành
pub const PROTOCOL_VERSION: u32 = 1;

/// Phiên bản lược đồ dữ liệu thành phần & đồ thị
pub const SCHEMA_VERSION: u32 = 1;

/// Phiên bản thuật toán suy diễn đỉnh ảo và điểm bằng chứng (rv p3.md #4, #5)
pub const DERIVATION_VERSION: u32 = 1;

/// Phiên bản lược đồ trạng thái thiết bị (Tier 6 State Hash)
pub const STATE_SCHEMA_VERSION: u32 = 1;

// Domain Separators (Domain băm SHA-512 chống va chạm giữa các tầng mật mã)
/// Miền cho băm linh kiện phần cứng riêng lẻ (Tier 1 Component Hash)
pub const DOMAIN_COMPONENT: &[u8] = b"CYBERV/DBS/COMPONENT/v1";

/// Miền cho cam kết đỉnh đồ thị (Tier 2 Node Commitment)
pub const DOMAIN_NODE: &[u8] = b"CYBERV/DBS/NODE/v1";

/// Miền cho băm đỉnh suy diễn ảo (Tier 3 Virtual Node Hash)
pub const DOMAIN_VIRTUAL_NODE: &[u8] = b"CYBERV/DBS/VNODE/v1";

/// Miền cho cam kết gốc bằng chứng ảo (Tier 4 Evidence Root)
pub const DOMAIN_EVIDENCE: &[u8] = b"CYBERV/DBS/EVIDENCE/v1";

/// Miền cho băm cấu trúc toàn bộ đồ thị (Tier 5 Graph Hash)
pub const DOMAIN_GRAPH: &[u8] = b"CYBERV/DBS/GRAPH/v1";

/// Miền cho cam kết xác minh tổng hợp tối cao (Tier 5 Verification Hash)
pub const DOMAIN_VERIFICATION: &[u8] = b"CYBERV/DBS/VERIFICATION/v1";

/// Miền cho băm trạng thái toàn diện thiết bị (Tier 6 State Hash - rv4.md #9)
pub const DOMAIN_STATE: &[u8] = b"CYBERV/DBS/STATE/v1";

/// Miền cho payload ký thử thách xác thực thiết bị (rv4.md #13)
pub const DOMAIN_AUTH: &[u8] = b"CYBERV/DBS/AUTH/v1";

/// Miền cho yêu cầu tái cấp quyền (Re-enrollment - rv4.md #13)
pub const DOMAIN_REENROLL: &[u8] = b"CYBERV/DBS/REENROLL/v1";

/// Miền cho yêu cầu đăng ký thiết bị ban đầu (Initial Enrollment)
pub const DOMAIN_ENROLL: &[u8] = b"CYBERV/DBS/ENROLL/v1";

/// Miền cho yêu cầu quay vòng khóa định danh thiết bị (Key Rotation - Phase 8)
pub const DOMAIN_KEY_ROTATION: &[u8] = b"CYBERV/DBS/KEY_ROTATION/v1";

/// Miền cho dẫn xuất dữ liệu ràng buộc trạng thái qua HKDF-SHA-512 (rv4.md #1, #17)
pub const DOMAIN_HKDF_STATE_BOUND: &[u8] = b"CYBERV/HKDF/STATE_BOUND/v1";

/// Mục đích ký: Xác thực thiết bị định kỳ
pub const PURPOSE_DEVICE_AUTH: &str = "device-auth";

/// Mục đích ký: Đăng ký lại khi thay đổi phần cứng
pub const PURPOSE_REENROLLMENT: &str = "reenrollment";

/// Mục đích ký: Đăng ký thiết bị ban đầu
pub const PURPOSE_ENROLLMENT: &str = "device-enrollment";

/// Mục đích ký: Quay vòng cặp khóa định danh
pub const PURPOSE_KEY_ROTATION: &str = "key-rotation";

/// Thời gian sống tối đa của Nonce Challenge (giây)
pub const CHALLENGE_TTL_SECONDS: u64 = 60;
