//! CyberV Risk Engine Models & Policy Decision Enums
//!
//! Ref: Pipeline.md Section 29, Plan.md Section 19, rv p3.md #6

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Risk levels conforming to CyberV DB check constraints
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Policy decisions evaluated by the Decision Matrix
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// No hardware mutations detected, grant access immediately
    Trusted,
    /// Benign mutations (e.g. RAM upgrade, non-boot secondary SSD) automatically promoted
    AutoPromote,
    /// Noticeable mutations (e.g. Boot drive, CPU swap) requiring explicit user authorization
    RequiresUserApproval,
    /// Critical risk, impossible state jumps, rollback or platform cloning, immediately rejected
    Rejected,
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyDecision::Trusted => write!(f, "TRUSTED"),
            PolicyDecision::AutoPromote => write!(f, "AUTO_PROMOTE"),
            PolicyDecision::RequiresUserApproval => write!(f, "REQUIRES_USER_APPROVAL"),
            PolicyDecision::Rejected => write!(f, "REJECTED"),
        }
    }
}

/// An individual risk signal identified during evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskSignal {
    pub code: String,
    pub penalty: u32,
    pub description: String,
}

/// Complete risk assessment report
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub score: u32, // Integer score 0 to 10000 (0.00% to 100.00%)
    pub level: RiskLevel,
    pub decision: PolicyDecision,
    pub signals: Vec<RiskSignal>,
    pub breakdown: BTreeMap<String, u32>,
}

impl RiskAssessment {
    /// Formatted display string of percentage (e.g. "15.00%")
    pub fn percentage_string(&self) -> String {
        format!("{}.{:02}%", self.score / 100, self.score % 100)
    }
}
