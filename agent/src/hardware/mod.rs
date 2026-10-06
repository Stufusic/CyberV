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
//! CyberV Hardware Collection Subsystem
//!
//! Layer A — Device Observation & Layer B — Device State Normalization
//! Ref: rv.md #12, rv plan1.md, và Rule.md Điều 4, 18, 23.

pub mod collector;
pub mod mock;
pub mod models;
pub mod normalizer;
pub mod windows;

pub use collector::{ComponentSummary, HardwareCollector, HardwareError, HardwareReport};
pub use mock::MockHardwareCollector;
pub use models::{
    CollectionSource, ComponentStatus, ComponentType, Confidence, HardwareSnapshot,
    NormalizedComponent, RawComponent, RawValue,
};
pub use normalizer::normalize_component;
pub use windows::{SysinfoFallbackCollector, WindowsWmiCollector};

/// Thu thập ảnh chụp phần cứng hệ thống tự động
///
/// Thử nghiệm thu thập qua WMI trước; nếu WMI bị lỗi hoặc không khả dụng,
/// tự động suy thoái êm thuận (graceful degradation) sang sysinfo fallback.
pub fn collect_hardware_snapshot() -> Result<HardwareSnapshot, HardwareError> {
    tracing::info!("Bắt đầu quan sát phần cứng qua Windows WMI...");
    let wmi_collector = WindowsWmiCollector::new();

    match wmi_collector.collect() {
        Ok(snapshot) => {
            tracing::info!(
                components_count = snapshot.components.len(),
                "Thu thập WMI thành công (High Confidence)"
            );
            Ok(snapshot)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "WMI không khả dụng hoặc lỗi quyền. Chuyển sang Sysinfo Fallback..."
            );
            let fallback = SysinfoFallbackCollector::new();
            fallback.collect()
        }
    }
}
