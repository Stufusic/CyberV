//! CyberV Physical Constraints Subsystem (HCE-1)

pub mod board_memory;
pub mod cpu_board;
pub mod cpu_memory;
pub mod engine;
pub mod rule;
pub mod storage_bus;

pub use engine::{PhysicalConstraintEngine, PhysicalConstraintReport};
pub use rule::{ConstraintEvaluation, ConstraintEvaluator, ConstraintResult};
