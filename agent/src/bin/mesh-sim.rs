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
