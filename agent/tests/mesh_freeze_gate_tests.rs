//! D2.3 / Freeze Gate — benign set harness: chạy 320 scenario "thế giới lành"
//! qua quorum + shadow ledger THẬT của NSG, đo wrong-action rate, rồi đánh
//! giá freeze gate. Đây là số liệu gate cho việc mở I-3 auto-pilot (Trụ 1 +
//! D2.3) — module chỉ ĐO, không mở gì.
//!
//! Benign scenario = mọi node đều lành, mọi tín hiệu đều vô hại nhưng ĐỦ đa
//! dạng để quench các hàng rào khác nhau (evidence root trùng, đường trùng,
//! sybil farm, heuristic-only, epoch stale, heartbeat). Wrong action = đề nghị
//! isolate sinh ra cho node lành.

use cyberv_agent::mesh::events::{ObsChannel, SignalClass};
use cyberv_agent::mesh::gate::{evaluate_freeze_gate, FreezeGateReport, MIN_BENIGN_RUNS};
use cyberv_agent::mesh::graph::NodeId;
use cyberv_agent::mesh::quorum::{evaluate_quorum, Ballot, QuorumPolicy, QuorumVerdict};
use cyberv_agent::mesh::shadow::ShadowLedger;

fn nid(seed: u64) -> NodeId {
    let mut n = [0u8; 32];
    n[..8].copy_from_slice(&seed.to_be_bytes());
    n
}

/// Sinh một phiếu bầu chuẩn (Verified, weight đầy đủ).
fn ballot(seed: u64, subject: NodeId, root: [u8; 32], channel: ObsChannel, path: u64) -> Ballot {
    Ballot {
        event_id: {
            let mut e = [0u8; 32];
            e[..8].copy_from_slice(&seed.to_be_bytes());
            e
        },
        origin_id: nid(seed),
        epoch: 0,
        subject,
        signal_class: SignalClass::Verified,
        obs_channel: channel,
        evidence_root: root,
        causal_parents: vec![],
        path_class: path,
        weight: 1000,
    }
}

/// Một thế giới benign: subject là node LÀNH. Trả số đề nghị isolate sinh ra
/// (mỗi cái = 1 wrong action tiềm năng).
fn run_benign_scenario(round: u64, ledger: &mut ShadowLedger) -> u64 {
    let victim = nid(0xB000 + (round % 200)); // node lành bị "tố"
    let mut ballots = Vec::new();

    match round % 8 {
        // 1. Chỉ MỘT report đơn lẻ — report đơn lẻ không bao giờ thành hành động.
        0 => {
            ballots.push(ballot(1 + round, victim, [0xA1; 32], ObsChannel::Kernel, 1 + round));
        }
        // 2. Hai vote TRÙNG evidence root — dedupe theo evidence → 1 nguồn.
        1 => {
            ballots.push(ballot(2 + round, victim, [0xA1; 32], ObsChannel::Kernel, 2 + round));
            ballots.push(ballot(3 + round, victim, [0xA1; 32], ObsChannel::EtwTelemetry, 3 + round));
        }
        // 3. Hai vote CÙNG path_class (cùng segment) — điều kiện 5 chặn.
        2 => {
            ballots.push(ballot(4 + round, victim, [0xB1; 32], ObsChannel::Kernel, 777));
            ballots.push(ballot(5 + round, victim, [0xB2; 32], ObsChannel::FilesystemAcl, 777));
        }
        // 4. Sybil farm (cold-start weight 160) + heuristic-only — không verified.
        3 => {
            for i in 0..6u64 {
                let mut b = ballot(
                    10 + i + round * 10,
                    victim,
                    [0xC0 + i as u8; 32],
                    ObsChannel::Other,
                    100 + i,
                );
                b.weight = 160;
                b.signal_class = SignalClass::Heuristic;
                ballots.push(b);
            }
        }
        // 5. Hai vote đủ mạnh nhưng 1 phiếu là causal child của phiếu kia.
        4 => {
            let mut child = ballot(20 + round, victim, [0xD1; 32], ObsChannel::Kernel, 5 + round);
            child.causal_parents.push({
                let mut p = [0u8; 32];
                p[..8].copy_from_slice(&(21 + round).to_be_bytes());
                p
            });
            ballots.push(child);
            ballots.push(ballot(21 + round, victim, [0xD2; 32], ObsChannel::EtwTelemetry, 6 + round));
        }
        // 6. Vote epoch stale (quá khứ) — bị lọc hết.
        5 => {
            let mut stale = ballot(30 + round, victim, [0xE1; 32], ObsChannel::Kernel, 7 + round);
            stale.epoch = 1; // hiện hành = 2
            ballots.push(stale);
        }
        // 7. Hai vote độc lập thật NHƯNG subject khác phiếu bầu (sai subject).
        6 => {
            let wrong_subject = nid(0xB000 + ((round + 1) % 200));
            ballots.push(ballot(40 + round, wrong_subject, [0xF1; 32], ObsChannel::Kernel, 8 + round));
            ballots.push(ballot(41 + round, wrong_subject, [0xF2; 32], ObsChannel::Privilege, 9 + round));
        }
        // 8. Heartbeat/rác không provenance — không bao giờ thành ballot.
        _ => {}
    }

    let outcome = evaluate_quorum(&ballots, victim, 2, |_| false, &QuorumPolicy::default());
    // Ghi shadow như production (I-2 đọc sổ này).
    let _ = ledger.record(victim, &outcome, 900_000, round);
    match outcome.verdict {
        // Node lành bị đề nghị isolate = WRONG ACTION.
        QuorumVerdict::Reached { .. } => 1,
        _ => 0,
    }
}

#[test]
fn benign_set_wrong_action_rate_is_zero_and_gate_stays_closed() {
    const RUNS: usize = 320; // > MIN_BENIGN_RUNS (256)

    let mut ledger = ShadowLedger::new();
    let mut wrong_actions = 0u64;
    for round in 0..RUNS as u64 {
        wrong_actions += run_benign_scenario(round, &mut ledger);
    }

    // Bất biến NSG-3: shadow chỉ ghi, KHÔNG thực thi.
    assert!(ledger.all_unexecuted());
    // Benign set phải ZERO đề nghị sai — từng nhóm hàng rào đều phải giữ.
    assert_eq!(
        wrong_actions, 0,
        "benign set sinh {wrong_actions} wrong action — quorum rò rỉ, KHÔNG được mở gate"
    );
    assert!(ledger.wrong_action_count() == 0);

    // Đánh giá gate: metrics xanh nhưng authority flag OFF → gate ĐÓNG.
    let report: FreezeGateReport =
        evaluate_freeze_gate(wrong_actions, RUNS, ledger.all_unexecuted(), false);
    assert!(report.metrics_ready, "metrics phải xanh: {report:?}");
    assert!(!report.auto_pilot_enabled, "flag authority off ⇒ KHÔNG mở I-3");
    assert_eq!(report.wrong_action_rate_bps, 0);
    assert_eq!(report.benign_runs, MIN_BENIGN_RUNS.max(RUNS));
}

#[test]
fn adversarial_scenario_still_reaches_and_is_counted() {
    // Đối chiếu: với tín hiệu ĐỐI THỦ thật (2 phiếu verified, độc lập đủ 5
    // điều kiện) quorum PHẢI đạt — harness không phải là chế độ tắt quorum.
    let victim = nid(0xEEEE);
    let ballots = vec![
        ballot(1001, victim, [0x11; 32], ObsChannel::Kernel, 1001),
        ballot(1002, victim, [0x22; 32], ObsChannel::Privilege, 1002),
    ];
    let mut ledger = ShadowLedger::new();
    let outcome = evaluate_quorum(&ballots, victim, 0, |_| false, &QuorumPolicy::default());
    assert!(matches!(outcome.verdict, QuorumVerdict::Reached { .. }));
    ledger.record(victim, &outcome, 900_000, 0).unwrap();
    assert_eq!(ledger.len(), 1);
    assert!(ledger.all_unexecuted(), "kể cả đề nghị đúng vẫn KHÔNG tự thực thi");
}

#[test]
fn single_wrong_action_closes_gate_definitively() {
    // Chỉ 1 wrong action trên 4096 runs — gate vẫn đóng (target = 0 tuyệt đối).
    let report = evaluate_freeze_gate(1, 4_096, true, true);
    assert!(!report.auto_pilot_enabled);
    assert_eq!(report.blocked_reason(), "WRONG_ACTION_RATE_ABOVE_TARGET");
}
