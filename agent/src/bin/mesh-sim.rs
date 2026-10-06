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
//! mesh-sim — CLI benchmark NSG-3.5 (plan §11)
//!
//! In bảng số liệu đo tầng pure của mesh (quorum/handshake/seal/ingest/graph)
//! trên máy dev. Số liệu ghi vào `Docs/NETWORK_SECURITY_GRAPH_PLAN.md` §11
//! mỗi release — là gate hiệu năng trước NSG-4.
//!
//! Dùng: `cargo run --release -p cyberv-agent --bin mesh-sim -- --rounds 200`

use cyberv_agent::mesh::sim;

fn main() {
    let mut rounds = 200usize;
    for arg in std::env::args().skip(1) {
        if let Some(value) = arg.strip_prefix("--rounds=") {
            // Đầu vào sai → về mặc định, không panic (CLI tiện dụng phải khoan dung).
            rounds = value.parse().unwrap_or(200);
        }
    }

    println!("CyberV mesh-sim — NSG-3.5 benchmark (rounds = {rounds})");
    println!("Nền tảng: pure-logic tier, single process, release build");
    println!("----------------------------------------------------------");

    let report = sim::run_full(rounds);

    println!(
        "{:<44} {:>12}",
        "metric", "measured"
    );
    println!(
        "{:<44} {:>12}",
        "quorum decision (256 ballots, avg/round)", format!("{:?}", report.quorum_decision_256)
    );
    println!(
        "{:<44} {:>12}",
        "handshake 3 bước trọn vẹn (avg)", format!("{:?}", report.handshake_avg)
    );
    println!(
        "{:<44} {:>12}",
        "seal + open frame 512B (avg/pair)", format!("{:?}", report.seal_open_avg)
    );
    println!(
        "{:<44} {:>12}",
        "gossip ingest 1000 event (đã ký sẵn)", format!("{:?}", report.gossip_ingest_1000)
    );
    println!(
        "{:<44} {:>12}",
        "graph fill bound + GC (256n / 2048e)", format!("{:?}", report.graph_fill_and_gc)
    );
    println!("----------------------------------------------------------");
    println!("Ghi nguồn khi công bố: single-process dev, không phải đo distributed");
    println!("(distributed latency/bandwidth là NSG-2b/NSG-7).");
}
