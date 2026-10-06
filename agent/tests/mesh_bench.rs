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
//! NSG-3.5 — Benchmark bound tests
//!
//! Ref: plan v2 §11 — số liệu là gate phase, nhưng test CI chỉ khóa **trần
//! lỏng** (chống flaky trên runner chậm); số đo chính xác được ghi tại §11
//! qua `mesh-sim` mỗi release. Mỗi test in số đo thực tế qua eprintln để
//! trong log CI khi trần bị vượt.

use cyberv_agent::mesh::sim;

fn report_ms(name: &str, d: std::time::Duration) {
    eprintln!("[mesh-bench] {name}: {d:?}");
}

#[test]
fn bench_quorum_decision_256_ballots_within_bound() {
    let r = sim::run_full(50);
    report_ms("quorum_decision_256 (avg)", r.quorum_decision_256);
    assert!(
        r.quorum_decision_256.as_millis() < 20,
        "quorum 256 phiếu vượt trần 20ms: {:?}",
        r.quorum_decision_256
    );
}

#[test]
fn bench_handshake_within_bound() {
    let r = sim::run_full(50);
    report_ms("handshake (avg)", r.handshake_avg);
    assert!(
        r.handshake_avg.as_millis() < 50,
        "bắt tay vượt trần 50ms: {:?}",
        r.handshake_avg
    );
}

#[test]
fn bench_seal_open_within_bound() {
    let r = sim::run_full(50);
    report_ms("seal_open (avg)", r.seal_open_avg);
    assert!(
        r.seal_open_avg.as_micros() < 2000,
        "seal+open vượt trần 2ms: {:?}",
        r.seal_open_avg
    );
}

#[test]
fn bench_gossip_ingest_1000_within_bound() {
    let r = sim::run_full(10);
    report_ms("gossip_ingest_1000 (total)", r.gossip_ingest_1000);
    assert!(
        r.gossip_ingest_1000.as_millis() < 2000,
        "ingest 1000 event vượt trần 2s: {:?}",
        r.gossip_ingest_1000
    );
}

#[test]
fn bench_graph_fill_bound_within_bound() {
    let r = sim::run_full(10);
    report_ms("graph_fill_and_gc", r.graph_fill_and_gc);
    assert!(
        r.graph_fill_and_gc.as_millis() < 1000,
        "graph fill+GC vượt trần 1s: {:?}",
        r.graph_fill_and_gc
    );
}
