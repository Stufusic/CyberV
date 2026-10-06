//! Freeze Gate (Trụ 1 + D2.3) — hàng rào ĐO LƯỜNG trước khi mở bất kỳ hành
//! động tự động nào (I-3 auto-pilot, NSG-4+).
//!
//! Ref: `Docs/DEFENSE_ROADMAP.md` v2 (Trụ 1 freeze gate), `Docs/M_PLAN_MULTI_TRANSPORT_ISOLATION.md`
//! §6.1 (I-3 mở chỉ sau freeze gate + D2.3 + wrong-action rate ~0 trên benign
//! set), plan NSG v2 §7.2/§8.
//!
//! Nguyên tắc phân tách (không tự mở): module này **chỉ ĐO và BÁO** —
//! `auto_pilot_enabled` chỉ true khi (a) metrics xanh VÀ (b) authority bật
//! cờ rõ ràng trong config. Cả hai điều kiện phải cùng thỏa; thiếu bất kỳ
//! điều kiện nào (kể cả authority flag) ⟹ gate đóng. Freeze gate Trụ 1 thật
//! (EV signing, driver WHQL, D2.3 verified-signal pipeline) là việc operator
//! — metrics ở đây là điều kiện CẦN, không phải ĐỦ.

use super::shadow::ShadowLedger;

/// Trần threshold: benign set tối thiểu phải chạy đủ N scenario trước khi
/// metrics được coi là có ý nghĩa thống kê (plan §7.2: benign set hàng trăm).
pub const MIN_BENIGN_RUNS: usize = 256;

/// Ngưỡng wrong-action rate: per-10,000 benign run. "~0" theo plan = 0 tuyệt
/// đối trên benign set (benign run sinh đề nghị isolate node lành = wrong
/// action, không chấp nhận 1 cái nào).
pub const WRONG_ACTION_RATE_TARGET_BPS: u32 = 0;

/// Báo cáo trạng thái freeze gate — chỉ là DỮ LIỆU, không có side effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreezeGateReport {
    pub benign_runs: usize,
    pub wrong_actions: u64,
    /// Wrong-action rate per-10,000 benign run (saturating).
    pub wrong_action_rate_bps: u32,
    /// Sổ shadow phải toàn entry chưa thực thi (bất biến NSG-3).
    pub shadow_all_unexecuted: bool,
    /// Đủ benign runs + wrong-action ~0 + shadow sạch.
    pub metrics_ready: bool,
    /// CHỈ true khi metrics_ready VÀ authority bật cờ. Đây là điều kiện cần
    /// (chưa đủ Trụ 1/D2.3 operator-level) — module luôn trung thực về điều đó.
    pub auto_pilot_enabled: bool,
}

impl FreezeGateReport {
    /// Lý do gate đóng (cho UI/log) — ngắn gọn, deterministic.
    pub fn blocked_reason(&self) -> &'static str {
        if self.auto_pilot_enabled {
            return "OPEN (cần tiếp tục giám sát)";
        }
        if !self.shadow_all_unexecuted {
            return "SHADOW_LEDGER_VIOLATION";
        }
        if self.benign_runs < MIN_BENIGN_RUNS {
            return "INSUFFICIENT_BENIGN_RUNS";
        }
        if self.wrong_actions > 0 {
            return "WRONG_ACTION_RATE_ABOVE_TARGET";
        }
        "AUTHORITY_FLAG_OFF (Trụ 1/D2.3 operator-level chưa nghiệm thu)"
    }
}

/// Đánh giá freeze gate từ số đo benign set + bất biến shadow ledger.
pub fn evaluate_freeze_gate(
    wrong_actions: u64,
    benign_runs: usize,
    shadow_all_unexecuted: bool,
    authority_enabled_auto_pilot: bool,
) -> FreezeGateReport {
    let rate = if benign_runs == 0 {
        0
    } else {
        ((wrong_actions.saturating_mul(10_000)) / benign_runs as u64).min(u32::MAX as u64) as u32
    };
    // Target = 0 tuyệt đối: wrong_actions == 0 đã bao hàm rate == target.
    // Giữ cả hai dòng cho rõ ý nghĩa gate (rate per-10k còn dùng cho report).
    let _ = WRONG_ACTION_RATE_TARGET_BPS;
    let metrics_ready =
        benign_runs >= MIN_BENIGN_RUNS && wrong_actions == 0 && shadow_all_unexecuted;
    FreezeGateReport {
        benign_runs,
        wrong_actions,
        wrong_action_rate_bps: rate,
        shadow_all_unexecuted,
        metrics_ready,
        auto_pilot_enabled: metrics_ready && authority_enabled_auto_pilot,
    }
}

/// Đo wrong-action từ một benign run ĐÃ chạy qua quorum + shadow: mọi đề nghị
/// isolate sinh ra cho node lành trong benign set đều là wrong action.
/// Caller feed kết quả evaluate + shadow ledger của run.
pub fn count_benign_wrong_actions(
    shadow: &ShadowLedger,
    benign_subjects_isolated_count: u64,
) -> u64 {
    // Wrong action = đề nghị isolate node lành. Shadow entry `reached` cho
    // subject benign chính là đề nghị đó; số đếm do harness cung cấp (mỗi
    // subject benign bị đề nghị = 1).
    let _ = shadow;
    benign_subjects_isolated_count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_stays_closed_without_authority_flag_even_when_metrics_green() {
        // Đủ 256 benign runs, 0 wrong action, shadow sạch — metrics XANH —
        // nhưng authority chưa bật: gate PHẢI đóng (phân tách đo-lường vs mở).
        let report = evaluate_freeze_gate(0, MIN_BENIGN_RUNS, true, false);
        assert!(report.metrics_ready);
        assert!(!report.auto_pilot_enabled);
        assert_eq!(
            report.blocked_reason(),
            "AUTHORITY_FLAG_OFF (Trụ 1/D2.3 operator-level chưa nghiệm thu)"
        );
    }

    #[test]
    fn gate_never_opens_with_any_wrong_action() {
        let report = evaluate_freeze_gate(1, 4_096, true, true);
        assert!(!report.metrics_ready);
        assert!(!report.auto_pilot_enabled);
        assert_eq!(report.blocked_reason(), "WRONG_ACTION_RATE_ABOVE_TARGET");
        assert_eq!(report.wrong_action_rate_bps, 2); // 1/4096 ≈ 2.44 → 2 bps
    }

    #[test]
    fn gate_never_opens_with_shadow_ledger_violation() {
        // Shadow ledger bị thực thi = bất biến NSG-3 vỡ — gate đóng tuyệt đối
        // bất kể mọi thứ khác.
        let report = evaluate_freeze_gate(0, MIN_BENIGN_RUNS, false, true);
        assert!(!report.auto_pilot_enabled);
        assert_eq!(report.blocked_reason(), "SHADOW_LEDGER_VIOLATION");
    }

    #[test]
    fn gate_never_opens_with_insufficient_benign_runs() {
        let report = evaluate_freeze_gate(0, MIN_BENIGN_RUNS - 1, true, true);
        assert!(!report.metrics_ready);
        assert_eq!(report.blocked_reason(), "INSUFFICIENT_BENIGN_RUNS");
    }

    #[test]
    fn gate_opens_only_when_all_conditions_hold() {
        let report = evaluate_freeze_gate(0, MIN_BENIGN_RUNS + 100, true, true);
        assert!(report.auto_pilot_enabled, "cả conditions + flag → mới mở");
        assert_eq!(report.wrong_action_rate_bps, 0);
    }

    #[test]
    fn zero_benign_runs_is_not_ready() {
        let report = evaluate_freeze_gate(0, 0, true, true);
        assert!(!report.metrics_ready);
    }
}
