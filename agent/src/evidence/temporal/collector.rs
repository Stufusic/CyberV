// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
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
