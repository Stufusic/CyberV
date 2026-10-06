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
//! Incident Correlation & Suspect Ranking (NSG-3)
//!
//! Ref: plan v2 §7.2 — **đổi tên bắt buộc**: không dùng "hunting attacker".
//! Output là **chỉ báo điều tra có provenance**, KHÔNG phải quy kết:
//! `SuspectRank` mang confidence (per-mille, từ trọng số vote — KHÔNG phải
//! "% attacker"), evidence_count, independent_sources (5 điều kiện §5),
//! signal_classes, false_positive_indicators và trace event_id (audit MMR).
//! L2 kill KHÔNG BAO GIỜ xuất phát từ ranking — nó thuộc response ladder.
//!
//! IOC sweep: đối chiếu indicator của report với telemetry cục bộ — kết quả
//! chỉ là **gợi ý phát Vote** (caller gắn evidence_root cục bộ + ký).

use sha2::{Digest, Sha512};

use super::events::{EventKind, NsgEvent, SignalClass};
use super::graph::NodeId;
use super::quorum::{independent_accepted, Ballot, QuorumPolicy};
use super::reputation::ReputationLedger;

/// Miền cam kết indicator — bóc tách khỏi các domain băm khác.
pub const DOMAIN_MESH_INDICATOR: &[u8] = b"CYBERV/MESH/INDICATOR/v1";

/// Loại indicator được phép chia sẻ (plan §8 T6 — chỉ indicator, KHÔNG
/// telemetry thô, KHÔNG serial/phần cứng).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorKind {
    ProcessPath,
    Signer,
    Lineage,
    BehaviorHash,
}

/// Indicator một nguồn báo cáo. So khớp = (kind, value) exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub kind: IndicatorKind,
    pub value: String,
}

impl Indicator {
    /// Cam kết SHA-512/32 domain-separate — dùng làm evidence material
    /// (đi vào merkle root; value thô KHÔNG qua channel công khai nếu policy
    /// selective disclosure yêu cầu).
    pub fn commit(&self) -> [u8; 32] {
        let mut h = Sha512::new();
        h.update(DOMAIN_MESH_INDICATOR);
        h.update([0x00]);
        h.update(self.kind_as_str().as_bytes());
        h.update([0x00]);
        h.update(self.value.as_bytes());
        let out = h.finalize();
        let mut c = [0u8; 32];
        c.copy_from_slice(&out[..32]);
        c
    }

    const fn kind_as_str(&self) -> &'static str {
        match self.kind {
            IndicatorKind::ProcessPath => "process-path",
            IndicatorKind::Signer => "signer",
            IndicatorKind::Lineage => "lineage",
            IndicatorKind::BehaviorHash => "behavior-hash",
        }
    }
}

/// IOC sweep: indicator của report khớp telemetry CỤC BỘ ở đâu — trả danh sách
/// khớp (clone — caller tự quyết định có phát Vote hay không, gắn evidence
/// root cục bộ + ký). KHÔNG tự phát Vote từ đây.
pub fn sweep_indicators(report_indicators: &[Indicator], local_telemetry: &[Indicator]) -> Vec<Indicator> {
    report_indicators
        .iter()
        .filter(|r| local_telemetry.iter().any(|l| l == *r))
        .cloned()
        .collect()
}

/// Cờ cảnh báo FP — bắt buộc đi kèm mọi ranking (§7.2: output phải có
/// false_positive_indicators, không được chỉ trả "92% attacker").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpIndicator {
    /// Chỉ một nguồn độc lập — đủ mọi thứ trừ hành động.
    SingleSource,
    /// Không phiếu nào verified.
    NoVerifiedSignal,
    /// Toàn bộ nguồn đều cold-start (trọng số bị ghim).
    ColdStartSources,
    /// Có bằng chứng từ epoch cũ hơn — điều tra được, quyết định không.
    StaleEvidence,
}

/// Kết quả xếp hạng nghi phạm — chỉ báo điều tra, không phải kết luận.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspectRank {
    pub subject: NodeId,
    /// Per-mille (0..=1000), tổng trọng số các nguồn ĐỘC LẬP hiện hành.
    /// KHÔNG phải "% attacker" — nhãn bắt buộc khi hiển thị.
    pub confidence_per_mille: u32,
    pub evidence_count: usize,
    pub independent_sources: usize,
    /// Signal class của từng nguồn độc lập — không pha trộn khi trình bày.
    pub signal_classes: Vec<SignalClass>,
    pub false_positive_indicators: Vec<FpIndicator>,
    /// Chuỗi event_id — truy vết qua MMR (audit không xóa được).
    pub trace: Vec<[u8; 32]>,
}

/// Xếp hạng nghi phạm cho một subject từ các event Report/Vote đã xác thực
/// (đã qua EventLog/inbox — expiry/replay/epoch chặn tại ingress, §6.1).
/// Deterministic: sort theo (epoch, origin_seq, origin_id, event_id). Trả
/// None nếu không có event nào đủ provenance.
///
/// `events_with_path`: event kèm đường nhận (path_class) — điều kiện 5 của
/// independence; ranking tái dùng **cùng một** greedy independence với quorum
/// (`quorum::independent_accepted`) để con số independent_sources không lệch
/// giữa hai đường tính.
pub fn rank_suspect(
    subject: NodeId,
    events_with_path: &[(&NsgEvent, u64)],
    ledger: &ReputationLedger,
    current_epoch: u64,
    is_revoked: impl Fn(&NodeId) -> bool,
    policy: &QuorumPolicy,
) -> Option<SuspectRank> {
    // 1. Lọc event đúng subject + đủ provenance (evidence_root). Expiry đã
    //    bị EventLog chặn tại ingress — ranking không lọc lại (một nguồn sự
    //    thật về thời hạn, tránh lệch hai nơi).
    let mut relevant: Vec<(&NsgEvent, u64)> = events_with_path
        .iter()
        .filter(|(ev, _)| {
            (ev.kind == EventKind::Report || ev.kind == EventKind::Vote)
                && ev.subject == Some(subject)
                && ev.evidence_root.is_some()
        })
        .copied()
        .collect();
    if relevant.is_empty() {
        return None;
    }
    // Deterministic thứ tự điều tra.
    relevant.sort_by(|(a, _), (b, _)| {
        a.epoch
            .cmp(&b.epoch)
            .then_with(|| a.origin_seq.cmp(&b.origin_seq))
            .then_with(|| a.origin_id.cmp(&b.origin_id))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });

    let evidence_count = relevant.len();
    let trace: Vec<[u8; 32]> = relevant.iter().map(|(ev, _)| ev.event_id).collect();

    // 2. Dựng ballots (weight từ ledger — node lạ weight 0 tự loại) và chạy
    //    CÙNG greedy independence với quorum.
    let ballots: Vec<Ballot> = relevant
        .iter()
        .filter_map(|(ev, path)| Ballot::from_event(ev, ledger.weight_of(&ev.origin_id), *path))
        .collect();
    let accepted = independent_accepted(
        &ballots,
        subject,
        current_epoch,
        is_revoked,
        policy.max_ballots,
    );
    let independent_sources = accepted.len();
    let signal_classes: Vec<SignalClass> = accepted.iter().map(|b| b.signal_class).collect();
    let confidence = accepted.iter().fold(0u32, |acc, b| acc.saturating_add(b.weight));

    // 3. Cờ FP — mọi ranking phải tự khai điểm yếu của chính nó.
    let mut fp = Vec::new();
    if independent_sources < 2 {
        fp.push(FpIndicator::SingleSource);
    }
    if !signal_classes.contains(&SignalClass::Verified) {
        fp.push(FpIndicator::NoVerifiedSignal);
    }
    if !accepted.is_empty()
        && accepted.iter().all(|b| {
            ledger
                .peer(&b.origin_id)
                .map(|p| p.cold_start)
                .unwrap_or(true)
        })
    {
        fp.push(FpIndicator::ColdStartSources);
    }
    if relevant.iter().any(|(ev, _)| ev.epoch < current_epoch) {
        fp.push(FpIndicator::StaleEvidence);
    }

    Some(SuspectRank {
        subject,
        confidence_per_mille: confidence.min(1000),
        evidence_count,
        independent_sources,
        signal_classes,
        false_positive_indicators: fp,
        trace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keypair::DeviceIdentityKey;
    use crate::identity::rng::OsCryptoRng;
    use crate::mesh::events::ObsChannel;

    fn nid(seed: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    fn key() -> DeviceIdentityKey {
        DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap()
    }

    fn vote_ev(key: &DeviceIdentityKey, seq: u64, subject: NodeId, root: [u8; 32], class: SignalClass) -> NsgEvent {
        let mut ev = NsgEvent {
            event_id: [0; 32],
            origin_id: key.verifying_key().to_bytes(),
            origin_seq: seq,
            epoch: 0,
            causal_parents: vec![],
            evidence_root: Some(root),
            created_wall_ms: 1000,
            expiry_wall_ms: 3_600_000,
            kind: EventKind::Vote,
            signal_class: Some(class),
            subject: Some(subject),
            obs_channel: Some(ObsChannel::Kernel),
            signature: [0; 64],
        };
        ev.sign(key);
        ev
    }

    #[test]
    fn sweep_matches_only_exact_indicator_pairs() {
        let report = vec![
            Indicator { kind: IndicatorKind::ProcessPath, value: "C:\\evil\\x.exe".into() },
            Indicator { kind: IndicatorKind::Signer, value: "CN=bad".into() },
        ];
        let local = vec![
            Indicator { kind: IndicatorKind::ProcessPath, value: "C:\\evil\\x.exe".into() },
            Indicator { kind: IndicatorKind::ProcessPath, value: "C:\\safe\\y.exe".into() },
        ];
        let matched = sweep_indicators(&report, &local);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].value, "C:\\evil\\x.exe");
    }

    #[test]
    fn indicator_commit_is_domain_separated() {
        let a = Indicator { kind: IndicatorKind::ProcessPath, value: "x".into() };
        let b = Indicator { kind: IndicatorKind::Signer, value: "x".into() };
        // Cùng value khác kind → commit khác (không va chạm giữa các loại).
        assert_ne!(a.commit(), b.commit());
    }

    #[test]
    fn rank_single_source_flags_fp() {
        let mut ledger = ReputationLedger::default();
        let a = key();
        ledger.on_attested(a.verifying_key().to_bytes(), 0);
        let ev = vote_ev(&a, 1, nid(0xEE), [0xA1; 32], SignalClass::Verified);
        let rank = rank_suspect(
            nid(0xEE),
            &[(&ev, 1)],
            &ledger,
            0,
            |_| false,
            &QuorumPolicy::default(),
        )
        .unwrap();
        assert_eq!(rank.evidence_count, 1);
        assert_eq!(rank.independent_sources, 1);
        assert!(rank.false_positive_indicators.contains(&FpIndicator::SingleSource));
        assert!(rank.false_positive_indicators.contains(&FpIndicator::ColdStartSources));
        assert!(rank.confidence_per_mille < 1800);
    }

    #[test]
    fn rank_is_deterministic() {
        let mut ledger = ReputationLedger::default();
        let a = key();
        let b = key();
        ledger.on_attested(a.verifying_key().to_bytes(), 0);
        ledger.on_attested(b.verifying_key().to_bytes(), 0);
        let e1 = vote_ev(&a, 1, nid(0xEE), [0xA1; 32], SignalClass::Verified);
        let e2 = vote_ev(&b, 1, nid(0xEE), [0xA2; 32], SignalClass::Heuristic);
        let r1 = rank_suspect(nid(0xEE), &[(&e1, 1), (&e2, 2)], &ledger, 0, |_| false, &QuorumPolicy::default()).unwrap();
        let r2 = rank_suspect(nid(0xEE), &[(&e2, 2), (&e1, 1)], &ledger, 0, |_| false, &QuorumPolicy::default()).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn rank_empty_when_no_relevant_events() {
        let ledger = ReputationLedger::default();
        assert!(rank_suspect(nid(0xEE), &[], &ledger, 0, |_| false, &QuorumPolicy::default()).is_none());
    }
}
