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
//! Temporal Drift & Hardware Trajectory Subsystem (HCE-5)

pub mod anomaly;
pub mod collector;
pub mod counters;
pub mod model;
pub mod trajectory;

pub use anomaly::TemporalAnomalyDetector;
pub use collector::{MockStorageCollector, StorageTelemetryCollector, WindowsStorageCollector};
pub use counters::MonotonicCounterChecker;
pub use model::{StorageTrajectory, TemporalAnomaly, TemporalEvaluation};
pub use trajectory::{
    TemporalTrajectoryEngine, TemporalTrajectoryReport, TEMPORAL_DERIVATION_VERSION,
};
