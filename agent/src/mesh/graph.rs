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
//! MeshGraph — đồ thị node/edge bounded + máy trạng thái fail-closed (NSG-1)
//!
//! Ref: plan v2 §3 (state machine một chiều, recovery có chữ ký) và §8 M10/M11
//! (bound cứng + accounting, edge GC). Thời gian là **mono ms do caller truyền**
//! — module không tự đọc đồng hồ, để test deterministic và đúng nguyên tắc
//! "nguồn monotonic" của roadmap v2 §4.

use std::collections::HashMap;

use super::MeshError;

/// Định danh node trong mesh = device_id canonical (SHA-512/32, đã có sẵn).
pub type NodeId = [u8; 32];

/// Giới hạn cứng đồ thị (plan §3, INV-015 planned).
/// Khi NSG-3 chuyển sang signed policy, các hằng này trở thành giá trị sở khởi
/// của policy có chữ ký — hiện ghi nhận trung thực là placeholder.
pub const MAX_NODES: usize = 256;
pub const MAX_EDGES: usize = 2048;

/// TTL edge: quá mốc này không có heartbeat → edge Stale, node về Unknown.
pub const EDGE_STALE_MS: u64 = 180_000; // 3 phút

/// TTL isolation mặc định (plan §9 — deadline tuyệt đối, reboot không reset).
pub const ISOLATION_TTL_MS: u64 = 900_000; // 15 phút

/// Trạng thái node trong mesh — máy trạng thái một chiều, trừ recovery ký.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Chưa từng thấy / mất dấu quá lâu. Giá trị XẤU NHẤT (fail-closed).
    Unknown,
    /// Chỉ thấy quảng bá — KHÔNG có giá trị tin cậy (khác `Attested`).
    Discovered,
    /// Đã bắt tay + attestation chữ ký thật.
    Attested,
    /// Bị nghi — có signal xấu nhưng chưa đủ quorum.
    Suspect,
    /// Bị cách ly (tự cách ly hoặc qua quorum) — có TTL bắt buộc.
    Isolated,
}

impl NodeState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            NodeState::Unknown => "Unknown",
            NodeState::Discovered => "Discovered",
            NodeState::Attested => "Attested",
            NodeState::Suspect => "Suspect",
            NodeState::Isolated => "Isolated",
        }
    }
}

/// Trạng thái một cạnh kết nối vật lý. Transport không nâng trust — chỉ
/// bắt tay + attestation chữ ký mới cho `Attested` (plan §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeState {
    Pending,
    Attested,
    Stale,
}

/// Bảng chuyển trạng thái hợp lệ (plan §3). Mọi cặp ngoài bảng = từ chối.
fn transition_allowed(from: NodeState, to: NodeState) -> bool {
    use NodeState::*;
    matches!(
        (from, to),
        (Unknown, Discovered)
            | (Discovered, Attested)
            // Probation sau cách ly (M-PLAN §6.3): node re-attest sau
            // isolation phải đi qua Suspect, K tick sạch mới lên Attested.
            // Chiều xấu-hơn nên không phá fail-closed.
            | (Discovered, Suspect)
            | (Discovered, Unknown) // stale
            | (Attested, Suspect)
            | (Attested, Unknown) // mất kết nối
            | (Suspect, Isolated)
            | (Suspect, Attested) // corroboration gỡ nghi
            | (Isolated, Unknown) // TTL hết — auto-lift (plan §9)
            | (Isolated, Attested) // recovery có chữ ký authority (INV-014)
            | (Isolated, Suspect) // merge reconcile phát hiện mâu thuẫn (plan §6.2b)
    )
}

#[derive(Debug, Clone)]
pub struct MeshNode {
    pub node_id: NodeId,
    pub state: NodeState,
    pub last_seen_mono_ms: u64,
    /// Deadline tuyệt đối hết hạn isolation. Lưu **mốc tuyệt đối** — reboot
    /// không reset vòng đời (plan §9 "persistence + reboot").
    pub isolated_until_mono_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct MeshEdge {
    /// Hai đầu đã chuẩn hóa: `a <= b` theo thứ tự byte — cạnh (a,b) == (b,a).
    pub a: NodeId,
    pub b: NodeId,
    pub state: EdgeState,
    pub last_heartbeat_mono_ms: u64,
}

/// Báo cáo một lượt GC — mọi loại bỏ đều đếm được (không drop âm thầm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcReport {
    pub lifted_isolations: usize,
    pub staled_nodes: usize,
    pub staled_edges: usize,
}

#[derive(Debug, Default)]
pub struct MeshGraph {
    nodes: HashMap<NodeId, MeshNode>,
    edges: HashMap<(NodeId, NodeId), MeshEdge>,
    dropped_nodes: u64,
    dropped_edges: u64,
}

impl MeshGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node(&self, id: &NodeId) -> Option<&MeshNode> {
        self.nodes.get(id)
    }

    pub fn edge(&self, a: &NodeId, b: &NodeId) -> Option<&MeshEdge> {
        self.edges.get(&normalize_edge(a, b)?)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn dropped_node_count(&self) -> u64 {
        self.dropped_nodes
    }

    pub fn dropped_edge_count(&self) -> u64 {
        self.dropped_edges
    }

    /// Node vừa được "thấy" (beacon discovery hoặc heartbeat). Node mới được
    /// tạo ở `Unknown` rồi chuyển ngay `Discovered` — **không bao giờ** tạo
    /// trực tiếp ở trạng thái cao hơn (plan §2.3: presence ≠ trust).
    pub fn observe(&mut self, id: NodeId, now_mono_ms: u64) -> Result<NodeState, MeshError> {
        match self.nodes.get_mut(&id) {
            Some(node) => {
                node.last_seen_mono_ms = now_mono_ms;
                // Chỉ nâng Unknown → Discovered; node Attested/isolated nhận
                // heartbeat giữ nguyên trạng thái (chuyển lùi là bất hợp lệ).
                if node.state == NodeState::Unknown {
                    node.state = NodeState::Discovered;
                }
                Ok(node.state)
            }
            None => {
                if self.nodes.len() >= MAX_NODES {
                    self.dropped_nodes = self.dropped_nodes.saturating_add(1);
                    return Err(MeshError::LimitExceeded { kind: "node", dropped: self.dropped_nodes });
                }
                let state = NodeState::Discovered;
                self.nodes.insert(
                    id,
                    MeshNode {
                        node_id: id,
                        state,
                        last_seen_mono_ms: now_mono_ms,
                        isolated_until_mono_ms: None,
                    },
                );
                Ok(state)
            }
        }
    }

    /// Áp một chuyển trạng thái qua bảng hợp lệ. Caller chịu trách nhiệm chứng
    /// minh điều kiện chuyển (vd. isolate chỉ sau khi quorum đạt — graph chỉ
    /// giữ bất biến trạng thái, không tự đánh giá quorum).
    ///
    /// Chuyển vào `Isolated` qua đường này để deadline trống — một isolation
    /// không có TTL là trạng thái **bất hợp lệ** (INV-014 cấm khóa vĩnh viễn)
    /// và tick_gc sẽ ép về `Unknown` ngay lượt GC kế tiếp. Đường chính thức
    /// là `isolate_with_ttl`.
    pub fn transition(&mut self, id: &NodeId, to: NodeState) -> Result<NodeState, MeshError> {
        let node = self
            .nodes
            .get_mut(id)
            .ok_or_else(|| MeshError::UnknownNode(hex_short(id)))?;
        let from = node.state;
        if !transition_allowed(from, to) {
            return Err(MeshError::IllegalTransition { from: from.as_str(), to: to.as_str() });
        }
        node.state = to;
        // Deadline isolation chỉ có ý nghĩa khi đang Isolated — rời khỏi trạng
        // thái nào cũng phải xóa (recover/merge-downgrade/GC không để lại TTL mồ côi).
        node.isolated_until_mono_ms = None;
        Ok(node.state)
    }

    /// Cách ly từ `Suspect` với TTL tùy chọn (ms). Deadline = now + ttl
    /// (saturating — không trần số học). Reboot không reset: deadline tuyệt đối.
    pub fn isolate_with_ttl(
        &mut self,
        id: &NodeId,
        now_mono_ms: u64,
        ttl_ms: u64,
    ) -> Result<NodeState, MeshError> {
        let state = self.transition(id, NodeState::Isolated)?;
        if let Some(node) = self.nodes.get_mut(id) {
            node.isolated_until_mono_ms =
                Some(now_mono_ms.saturating_add(ttl_ms));
        }
        Ok(state)
    }

    /// Recovery có chữ ký authority (INV-014) — caller verify chữ ký trước.
    pub fn recover(&mut self, id: &NodeId) -> Result<NodeState, MeshError> {
        self.transition(id, NodeState::Attested)
    }

    /// Heartbeat cục bộ từ node. Node ma (chưa từng thấy) bị từ chối —
    /// không tạo node ngầm từ heartbeat (chống ghost-node injection).
    pub fn heartbeat(&mut self, id: &NodeId, now_mono_ms: u64) -> Result<(), MeshError> {
        let node = self
            .nodes
            .get_mut(id)
            .ok_or_else(|| MeshError::UnknownNode(hex_short(id)))?;
        node.last_seen_mono_ms = now_mono_ms;
        Ok(())
    }

    /// Ghi một cạnh. Yêu cầu cả hai node đã tồn tại (discovery đi trước) và
    /// không tự tham chiếu. Gọi lại với cặp đã có = refresh trạng thái cạnh.
    pub fn link(&mut self, a: NodeId, b: NodeId, now_mono_ms: u64) -> Result<EdgeState, MeshError> {
        if a == b {
            return Err(MeshError::InvalidEdge("cạnh tự tham chiếu".into()));
        }
        if !self.nodes.contains_key(&a) || !self.nodes.contains_key(&b) {
            return Err(MeshError::UnknownNode("cạnh cần cả hai node có sẵn".into()));
        }
        let key = normalize_edge(&a, &b)
            .ok_or_else(|| MeshError::InvalidEdge("cạnh tự tham chiếu".into()))?;
        if !self.edges.contains_key(&key) && self.edges.len() >= MAX_EDGES {
            self.dropped_edges = self.dropped_edges.saturating_add(1);
            return Err(MeshError::LimitExceeded { kind: "edge", dropped: self.dropped_edges });
        }
        let state = match (
            self.nodes[&a].state,
            self.nodes[&b].state,
        ) {
            (NodeState::Attested, NodeState::Attested) => EdgeState::Attested,
            _ => EdgeState::Pending,
        };
        self.edges.insert(
            key,
            MeshEdge { a: key.0, b: key.1, state, last_heartbeat_mono_ms: now_mono_ms },
        );
        Ok(state)
    }

    /// GC định kỳ trong tick: (1) isolation quá deadline → auto-lift về
    /// `Unknown` (reversibility outranks persistence — INV-014), (2) node không
    /// thấy quá lâu → `Unknown`, (3) edge stale. Mọi chuyển đổi đều đếm.
    pub fn tick_gc(&mut self, now_mono_ms: u64) -> GcReport {
        let mut report = GcReport::default();

        for node in self.nodes.values_mut() {
            // 1. Auto-lift isolation hết hạn (trước kiểm tra stale — một node
            //    isolated "mất dấu" vẫn phải chờ đúng TTL của nó). Deadline là
            //    mốc hết hạn inclusively: `now >= until` → lift. Isolation
            //    KHÔNG deadline là bất hợp lệ (INV-014) → lift ngay — kể cả
            //    deadline bão hòa u64::MAX (reversibility outranks persistence).
            if node.state == NodeState::Isolated {
                let expired = match node.isolated_until_mono_ms {
                    Some(until) => now_mono_ms >= until,
                    None => true,
                };
                if expired {
                    node.state = NodeState::Unknown;
                    node.isolated_until_mono_ms = None;
                    report.lifted_isolations = report.lifted_isolations.saturating_add(1);
                    continue;
                }
            }
            // 2. Stale: Discovered/Attested/Suspect mất dấu quá EDGE_STALE_MS.
            let stale = now_mono_ms
                .saturating_sub(node.last_seen_mono_ms)
                > EDGE_STALE_MS;
            if stale
                && matches!(
                    node.state,
                    NodeState::Discovered | NodeState::Attested | NodeState::Suspect
                )
            {
                node.state = NodeState::Unknown;
                node.isolated_until_mono_ms = None;
                report.staled_nodes = report.staled_nodes.saturating_add(1);
            }
        }

        for edge in self.edges.values_mut() {
            if edge.state != EdgeState::Stale
                && now_mono_ms.saturating_sub(edge.last_heartbeat_mono_ms) > EDGE_STALE_MS
            {
                edge.state = EdgeState::Stale;
                report.staled_edges = report.staled_edges.saturating_add(1);
            }
        }

        report
    }
}

/// Chuẩn hóa cạnh: đầu nhỏ trước theo thứ tự byte. Trả None cho self-edge.
fn normalize_edge(a: &NodeId, b: &NodeId) -> Option<(NodeId, NodeId)> {
    if a == b {
        return None;
    }
    if a <= b {
        Some((*a, *b))
    } else {
        Some((*b, *a))
    }
}

/// Tóm tắt node id để log lỗi — chỉ 8 byte đầu, không phải định danh đầy đủ.
fn hex_short(id: &NodeId) -> String {
    id.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> NodeId {
        let mut nid = [0u8; 32];
        nid[0] = seed;
        nid
    }

    #[test]
    fn transition_table_is_fail_closed() {
        // Unknown là giá trị xấu nhất: mọi node đều có thể bị đẩy về Unknown
        // qua GC, nhưng KHÔNG ai được "nhảy cóc" lên trạng thái cao hơn.
        assert!(transition_allowed(NodeState::Unknown, NodeState::Discovered));
        assert!(!transition_allowed(NodeState::Unknown, NodeState::Attested));
        assert!(!transition_allowed(NodeState::Unknown, NodeState::Suspect));
        assert!(!transition_allowed(NodeState::Unknown, NodeState::Isolated));
        assert!(!transition_allowed(NodeState::Discovered, NodeState::Isolated));
        // Probation sau cách ly (M-PLAN §6.3): Discovered → Suspect được phép
        // (chiều xấu-hơn); node probation KHÔNG được nhảy thẳng Attested qua
        // đường engine (engine tự kiểm trước khi gọi transition Attested).
        assert!(transition_allowed(NodeState::Discovered, NodeState::Suspect));
        // Isolated có ĐÚNG MỘT đường hạ xuống: merge reconcile phát hiện
        // mâu thuẫn → Suspect (plan §6.2b). Không đường nào khác.
        assert!(transition_allowed(NodeState::Isolated, NodeState::Suspect));
        assert!(!transition_allowed(NodeState::Isolated, NodeState::Discovered));
        // Isolated thoát qua recovery (→ Attested), TTL (→ Unknown), hoặc
        // downgrade merge (→ Suspect).
        assert!(transition_allowed(NodeState::Isolated, NodeState::Attested));
        assert!(transition_allowed(NodeState::Isolated, NodeState::Unknown));
    }

    #[test]
    fn observe_never_creates_trusted_state() {
        let mut g = MeshGraph::new();
        let state = g.observe(id(1), 1000).unwrap();
        assert_eq!(state, NodeState::Discovered);
        assert_eq!(g.node(&id(1)).unwrap().state, NodeState::Discovered);
    }

    #[test]
    fn ttl_saturates_without_overflow() {
        let mut g = MeshGraph::new();
        g.observe(id(1), 0).unwrap();
        g.transition(&id(1), NodeState::Attested).unwrap();
        g.transition(&id(1), NodeState::Suspect).unwrap();
        // TTL gần trần — không panic, deadline bão hòa về giá trị finite.
        g.isolate_with_ttl(&id(1), u64::MAX - 20, u64::MAX).unwrap();
        assert_eq!(g.node(&id(1)).unwrap().state, NodeState::Isolated);
        // Deadline bão hòa finite → GC tại mốc đó lift đúng luật.
        let report = g.tick_gc(u64::MAX);
        assert_eq!(report.lifted_isolations, 1);
        assert_eq!(g.node(&id(1)).unwrap().state, NodeState::Unknown);
    }

    #[test]
    fn isolation_without_ttl_is_invalid_and_self_corrects() {
        // INV-014: không tồn tại isolation vĩnh viễn. transition(Isolated) để
        // deadline trống là trạng thái bất hợp lệ → GC đầu tiên phải lift.
        let mut g = MeshGraph::new();
        g.observe(id(1), 0).unwrap();
        g.transition(&id(1), NodeState::Attested).unwrap();
        g.transition(&id(1), NodeState::Suspect).unwrap();
        g.transition(&id(1), NodeState::Isolated).unwrap();
        assert_eq!(g.node(&id(1)).unwrap().isolated_until_mono_ms, None);
        let report = g.tick_gc(1);
        assert_eq!(report.lifted_isolations, 1);
        assert_eq!(g.node(&id(1)).unwrap().state, NodeState::Unknown);
    }
}
