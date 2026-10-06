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
//! Gossip Inbox — tiếp nhận sự kiện từ peer (NSG-3)
//!
//! Ref: plan v2 §6 (quy tắc xử lý event), §8 T5/T10 (flood + resource),
//! INV-010/015 planned. Inbox là lớp peer-facing phía trên `EventLog`:
//! flood-limit **per-peer** (một peer spam không được phép làm cạn log của
//! peer khác), ủy thác toàn bộ xác thực cho EventLog, và **mọi loại bỏ đều
//! được phân loại + đếm** — không có drop âm thầm nào.
//!
//! Phân loại tinh thần INV-010: Vote/Report là sự kiện mức quyết định — bị
//! từ chối phải trả `Err` rõ lý do; Heartbeat là L0 — drop khi flood được
//! phép NHƯNG vẫn đếm (`flood_dropped`). Inbox không tự hành động.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;

use super::events::{AcceptOutcome, EventLog, NsgEvent};
use super::graph::NodeId;
use super::MeshError;

/// Số sự kiện tối đa một peer được gửi trong một cửa sổ (placeholder policy
/// — NSG-3 chuyển signed policy sẽ do authority ký).
pub const DEFAULT_MAX_EVENTS_PER_PEER: u32 = 64;
/// Độ dài cửa sổ flood-limit (mono ms).
pub const DEFAULT_GOSSIP_WINDOW_MS: u64 = 60_000;
/// Trần số peer theo dõi đồng thời (INV-015).
pub const DEFAULT_MAX_GOSSIP_PEERS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipPolicy {
    pub max_events_per_peer_per_window: u32,
    pub window_ms: u64,
    pub max_peers: usize,
}

impl Default for GossipPolicy {
    fn default() -> Self {
        Self {
            max_events_per_peer_per_window: DEFAULT_MAX_EVENTS_PER_PEER,
            window_ms: DEFAULT_GOSSIP_WINDOW_MS,
            max_peers: DEFAULT_MAX_GOSSIP_PEERS,
        }
    }
}

/// Thống kê một peer — mọi con số đều truy vấn được, không có con số ẩn.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerGossipStats {
    pub accepted: u64,
    pub rejected_replay: u64,
    pub rejected_stale: u64,
    pub rejected_crypto: u64,
    pub flood_dropped: u64,
}

#[derive(Debug, Clone, Default)]
struct PeerWindow {
    window_start_mono_ms: u64,
    count_in_window: u32,
    stats: PeerGossipStats,
}

/// Inbox gossip: per-peer flood limiter + EventLog dùng chung.
#[derive(Debug)]
pub struct GossipInbox {
    policy: GossipPolicy,
    peers: HashMap<NodeId, PeerWindow>,
    log: EventLog,
}

impl Default for GossipInbox {
    fn default() -> Self {
        Self::with_log(GossipPolicy::default(), EventLog::default())
    }
}

impl GossipInbox {
    pub fn with_log(policy: GossipPolicy, log: EventLog) -> Self {
        Self { policy, peers: HashMap::new(), log }
    }

    pub fn policy(&self) -> &GossipPolicy {
        &self.policy
    }

    pub fn log(&self) -> &EventLog {
        &self.log
    }

    pub fn log_mut(&mut self) -> &mut EventLog {
        &mut self.log
    }

    pub fn tracked_peers(&self) -> usize {
        self.peers.len()
    }

    pub fn stats(&self, peer: &NodeId) -> Option<PeerGossipStats> {
        self.peers.get(peer).map(|w| w.stats)
    }

    /// Tổng flood drop toàn inbox — hiển thị được ở GetStatus (plan §6.2).
    pub fn total_flood_dropped(&self) -> u64 {
        self.peers.values().map(|w| w.stats.flood_dropped).sum()
    }

    /// Tiếp nhận một event từ peer. Thứ tự: peer bound → cửa sổ flood →
    /// ủy thác EventLog (verify/dedupe/replay/expiry/epoch/bound) → cập nhật
    /// thống kê. Trả `Err` cho MỌI loại bỏ — caller quyết định log/alert.
    pub fn ingest(
        &mut self,
        peer: NodeId,
        event: NsgEvent,
        vk: &VerifyingKey,
        now_mono_ms: u64,
        now_wall_ms: u64,
        current_epoch: u64,
    ) -> Result<AcceptOutcome, MeshError> {
        // 1. Bound số peer (INV-015) — peer mới vượt trần bị từ chối rõ ràng.
        if !self.peers.contains_key(&peer) && self.peers.len() >= self.policy.max_peers {
            return Err(MeshError::LimitExceeded { kind: "gossip-peer", dropped: self.policy.max_peers as u64 });
        }
        let entry = self.peers.entry(peer).or_default();

        // 2. Cửa sổ trượt — sang cửa sổ mới thì reset đếm (không reset stats).
        if now_mono_ms.saturating_sub(entry.window_start_mono_ms) >= self.policy.window_ms {
            entry.window_start_mono_ms = now_mono_ms;
            entry.count_in_window = 0;
        }

        // 3. Flood limit per-peer. L2+ (Vote/Report) và L0 (Heartbeat) đều bị
        //    từ chối RÕ RÀNG khi quá — chỉ khác ở chỗ L0 drop là hành vi
        //    chính đáng, L2+ drop phải nổi lên ở stats cho dashboard.
        if entry.count_in_window >= self.policy.max_events_per_peer_per_window {
            entry.stats.flood_dropped = entry.stats.flood_dropped.saturating_add(1);
            return Err(MeshError::LimitExceeded { kind: "gossip-flood", dropped: entry.stats.flood_dropped });
        }

        // 4. Ủy thác EventLog — ánh xạ lỗi vào thống kê theo phân loại.
        match self.log.accept(event, vk, now_wall_ms, current_epoch) {
            Ok(outcome) => {
                entry.count_in_window = entry.count_in_window.saturating_add(1);
                entry.stats.accepted = entry.stats.accepted.saturating_add(1);
                Ok(outcome)
            }
            Err(MeshError::ReplayRejected(_)) => {
                entry.stats.rejected_replay = entry.stats.rejected_replay.saturating_add(1);
                Err(MeshError::ReplayRejected("replay bị inbox ghi nhận".into()))
            }
            Err(MeshError::StaleEvent(m)) => {
                entry.stats.rejected_stale = entry.stats.rejected_stale.saturating_add(1);
                Err(MeshError::StaleEvent(m))
            }
            Err(MeshError::EventRejected(m)) => {
                entry.stats.rejected_crypto = entry.stats.rejected_crypto.saturating_add(1);
                Err(MeshError::EventRejected(m))
            }
            // LimitExceeded của EventLog (log đầy) — thông qua, không đếm flood.
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keypair::DeviceIdentityKey;
    use crate::identity::rng::OsCryptoRng;
    use crate::mesh::events::{EventKind, SignalClass};
    use crate::mesh::events::ObsChannel;

    fn key() -> DeviceIdentityKey {
        DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap()
    }

    fn vote(key: &DeviceIdentityKey, seq: u64, subject: NodeId) -> NsgEvent {
        let mut ev = NsgEvent {
            event_id: [0; 32],
            origin_id: key.verifying_key().to_bytes(),
            origin_seq: seq,
            epoch: 0,
            causal_parents: vec![],
            evidence_root: Some([0xAA; 32]),
            created_wall_ms: 1000,
            expiry_wall_ms: 3_600_000,
            kind: EventKind::Vote,
            signal_class: Some(SignalClass::Verified),
            subject: Some(subject),
            obs_channel: Some(ObsChannel::Kernel),
            signature: [0; 64],
        };
        ev.sign(key);
        ev
    }

    #[test]
    fn flood_from_one_peer_is_limited_and_counted() {
        let mut inbox = GossipInbox::with_log(
            GossipPolicy {
                max_events_per_peer_per_window: 4,
                window_ms: 60_000,
                max_peers: 16,
            },
            EventLog::new(1024),
        );
        let k = key();
        let peer = k.verifying_key().to_bytes();

        for seq in 1..=4u64 {
            inbox
                .ingest(peer, vote(&k, seq, [0xEE; 32]), k.verifying_key(), seq * 10, 2000, 0)
                .unwrap();
        }
        // Phiếu thứ 5 trong cửa sổ — bị flood-limit + đếm, KHÔNG âm thầm.
        let err = inbox
            .ingest(peer, vote(&k, 5, [0xEE; 32]), k.verifying_key(), 50, 2000, 0)
            .unwrap_err();
        assert!(matches!(err, MeshError::LimitExceeded { kind: "gossip-flood", dropped: 1 }));
        assert_eq!(inbox.stats(&peer).unwrap().flood_dropped, 1);
        assert_eq!(inbox.stats(&peer).unwrap().accepted, 4);

        // Cửa sổ mới (mono vượt window_ms) — đếm flood giữ nguyên, nhận tiếp.
        let outcome = inbox
            .ingest(peer, vote(&k, 6, [0xEE; 32]), k.verifying_key(), 60_100, 2000, 0)
            .unwrap();
        assert_eq!(outcome, AcceptOutcome::Accepted);
        assert_eq!(inbox.stats(&peer).unwrap().flood_dropped, 1);
        assert_eq!(inbox.stats(&peer).unwrap().accepted, 5);
    }

    #[test]
    fn flood_from_one_peer_does_not_starve_another() {
        let mut inbox = GossipInbox::with_log(
            GossipPolicy {
                max_events_per_peer_per_window: 2,
                window_ms: 60_000,
                max_peers: 16,
            },
            EventLog::new(1024),
        );
        let k1 = key();
        let k2 = key();
        let p1 = k1.verifying_key().to_bytes();
        let p2 = k2.verifying_key().to_bytes();

        for seq in 1..=2u64 {
            inbox.ingest(p1, vote(&k1, seq, [0xEE; 32]), k1.verifying_key(), seq * 10, 2000, 0).unwrap();
        }
        // p1 đã đầy cửa sổ — nhưng p2 phải nhận bình thường.
        inbox.ingest(p2, vote(&k2, 1, [0xEE; 32]), k2.verifying_key(), 30, 2000, 0).unwrap();
        assert_eq!(inbox.stats(&p2).unwrap().accepted, 1);
    }

    #[test]
    fn peer_bound_enforced_with_clear_error() {
        let mut inbox = GossipInbox::with_log(
            GossipPolicy {
                max_events_per_peer_per_window: 64,
                window_ms: 60_000,
                max_peers: 2,
            },
            EventLog::new(1024),
        );
        let keys: Vec<_> = (0..3).map(|_| key()).collect();
        for (i, k) in keys.iter().enumerate() {
            let peer = k.verifying_key().to_bytes();
            let res = inbox.ingest(peer, vote(k, 1, [0xEE; 32]), k.verifying_key(), i as u64, 2000, 0);
            if i < 2 {
                res.unwrap();
            } else {
                assert!(matches!(res, Err(MeshError::LimitExceeded { kind: "gossip-peer", .. })));
            }
        }
        assert_eq!(inbox.tracked_peers(), 2);
    }

    #[test]
    fn poison_event_counted_as_crypto_rejection() {
        let mut inbox = GossipInbox::default();
        let k = key();
        let peer = k.verifying_key().to_bytes();
        let mut ev = vote(&k, 1, [0xEE; 32]);
        ev.subject = Some([0x12; 32]); // sửa sau khi ký — poison
        let err = inbox
            .ingest(peer, ev, k.verifying_key(), 10, 2000, 0)
            .unwrap_err();
        assert!(matches!(err, MeshError::EventRejected(_)));
        assert_eq!(inbox.stats(&peer).unwrap().rejected_crypto, 1);
        assert_eq!(inbox.stats(&peer).unwrap().accepted, 0);
    }

    #[test]
    fn replay_event_counted_separately() {
        let mut inbox = GossipInbox::default();
        let k = key();
        let peer = k.verifying_key().to_bytes();
        inbox.ingest(peer, vote(&k, 5, [0xEE; 32]), k.verifying_key(), 10, 2000, 0).unwrap();
        // Cùng seq nội dung khác — replay riêng biệt với stale.
        let mut ev2 = vote(&k, 5, [0x11; 32]);
        ev2.sign(&k);
        let err = inbox
            .ingest(peer, ev2, k.verifying_key(), 20, 2000, 0)
            .unwrap_err();
        assert!(matches!(err, MeshError::ReplayRejected(_)));
        assert_eq!(inbox.stats(&peer).unwrap().rejected_replay, 1);
    }
}
