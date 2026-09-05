//! Storage Telemetry Collector (HCE-5)
//!
//! Ref: Docs/rv10.md HCE-5 Section 14:
//! "NVMe SMART / Health log query via Windows storage APIs or mock collector."

use super::model::StorageTrajectory;
use std::collections::HashMap;

pub trait StorageTelemetryCollector: Send + Sync {
    fn collect_telemetry(&self, storage_id: &str) -> Option<StorageTrajectory>;
}

/// Bộ thu thập thực tế trên Windows
pub struct WindowsStorageCollector;

impl WindowsStorageCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsStorageCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageTelemetryCollector for WindowsStorageCollector {
    fn collect_telemetry(&self, storage_id: &str) -> Option<StorageTrajectory> {
        // Trên Windows, có thể gọi DeviceIoControl với IOCTL_STORAGE_QUERY_PROPERTY
        // Nếu không có quyền Admin hoặc ổ đĩa không hỗ trợ SMART, trả về None an toàn (Fail-Safe)
        let _ = storage_id;
        None
    }
}

/// Bộ giả lập Telemetry phục vụ kiểm thử ma trận thời gian
pub struct MockStorageCollector {
    records: HashMap<String, StorageTrajectory>,
}

impl Default for MockStorageCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MockStorageCollector {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    pub fn insert_trajectory(&mut self, trajectory: StorageTrajectory) {
        self.records
            .insert(trajectory.storage_id.clone(), trajectory);
    }
}

impl StorageTelemetryCollector for MockStorageCollector {
    fn collect_telemetry(&self, storage_id: &str) -> Option<StorageTrajectory> {
        self.records.get(storage_id).cloned()
    }
}
