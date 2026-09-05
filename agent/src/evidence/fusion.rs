//! Evidence Fusion Engine (HCE Section 52)
//!
//! Ref: Docs/rv10.md Section 52:
//! "Evidence Fusion:
//! Không dùng weighted score duy nhất.
//! Chia theo evidence classes: CRYPTOGRAPHIC, HARDWARE, STRUCTURAL, TEMPORAL, PLATFORM, BEHAVIORAL.
//! Đánh giá: Strong, Medium, Weak."

use super::unified::{EvidenceClass, EvidenceItem};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceRating {
    Strong,
    Medium,
    Weak,
}

impl std::fmt::Display for EvidenceRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceRating::Strong => write!(f, "STRONG"),
            EvidenceRating::Medium => write!(f, "MEDIUM"),
            EvidenceRating::Weak => write!(f, "WEAK"),
        }
    }
}

/// Báo cáo tổng hợp đánh giá bằng chứng đa chiều (Evidence Fusion Report)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFusionReport {
    pub items: Vec<EvidenceItem>,
    pub class_scores: BTreeMap<String, u32>,
    pub overall_rating: EvidenceRating,
    pub composite_score: u32,
    pub summary: String,
}

pub struct EvidenceFusionEngine;

impl EvidenceFusionEngine {
    /// Hợp nhất tất cả các bằng chứng từ 6 phân lớp
    pub fn fuse(items: Vec<EvidenceItem>) -> EvidenceFusionReport {
        if items.is_empty() {
            return EvidenceFusionReport {
                items: Vec::new(),
                class_scores: BTreeMap::new(),
                overall_rating: EvidenceRating::Weak,
                composite_score: 0,
                summary: "Không có bằng chứng nào được cung cấp".to_string(),
            };
        }

        let mut class_buckets: BTreeMap<EvidenceClass, Vec<u32>> = BTreeMap::new();
        for item in &items {
            class_buckets
                .entry(item.evidence_class)
                .or_default()
                .push(item.score);
        }

        let mut class_scores: BTreeMap<String, u32> = BTreeMap::new();
        let mut total_score: u64 = 0;
        let mut classes_evaluated: u64 = 0;

        for (class, scores) in &class_buckets {
            if !scores.is_empty() {
                let sum: u64 = scores.iter().map(|&s| s as u64).sum();
                let avg = (sum / scores.len() as u64) as u32;
                class_scores.insert(class.to_string(), avg);
                total_score += avg as u64;
                classes_evaluated += 1;
            }
        }

        let composite_score = total_score.checked_div(classes_evaluated).unwrap_or(0) as u32;

        // Đánh giá Evidence Rating theo phân lớp (Section 52):
        // Strong: Có ít nhất 4 phân lớp và composite_score >= 8000, không có phân lớp nào dưới 5000
        // Medium: Có ít nhất 2 phân lớp và composite_score >= 5000
        // Weak: Dưới 2 phân lớp hoặc composite_score < 5000
        let min_class_score = class_scores.values().min().copied().unwrap_or(0);
        let overall_rating =
            if classes_evaluated >= 4 && composite_score >= 8000 && min_class_score >= 5000 {
                EvidenceRating::Strong
            } else if classes_evaluated >= 2 && composite_score >= 5000 {
                EvidenceRating::Medium
            } else {
                EvidenceRating::Weak
            };

        let summary = format!(
            "Evidence Fusion hoàn tất: {} lớp bằng chứng, Composite Score {}/10000, Rating: {}",
            classes_evaluated, composite_score, overall_rating
        );

        EvidenceFusionReport {
            items,
            class_scores,
            overall_rating,
            composite_score,
            summary,
        }
    }
}
