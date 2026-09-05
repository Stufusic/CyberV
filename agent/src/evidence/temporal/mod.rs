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
