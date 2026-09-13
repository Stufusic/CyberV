//! CyberV Security Agent CLI Daemon

use cyberv_agent::fingerprint::{build_evidence_graph, hash_snapshot};
use cyberv_agent::hardware::{collect_hardware_snapshot, HardwareReport};
use cyberv_agent::identity::{DeviceSecureStorage, SecureRandom};
use cyberv_agent::protocol::*;

fn print_usage() {
    println!("CyberV Security Agent CLI & Service Controller");
    println!("Usage: cyberv-agent [COMMAND]");
    println!();
    println!("Commands:");
    println!("  run          Run interactive observation and graph engine demo (default)");
    println!("  install      Install CyberV Agent as a Windows Service (SCM)");
    println!("  uninstall    Uninstall CyberV Agent from Windows Service Manager");
    println!("  start        Start the CyberV Agent Windows Service");
    println!("  stop         Stop the CyberV Agent Windows Service");
    println!("  status       Query current status of the CyberV Agent Windows Service");
    println!("  --service    Entry point invoked by Windows SCM dispatcher");
    println!("  help         Display this help message");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("run");

    match command {
        "--service" | "service" => {
            println!("[*] Starting CyberV Agent under Windows Service Control Manager...");
            if let Err(e) = cyberv_agent::service::run_service_dispatcher() {
                eprintln!("[-] Service dispatcher failed: {}", e);
                std::process::exit(1);
            }
        }
        "install" => {
            println!("[*] Installing CyberV Agent Windows Service...");
            match cyberv_agent::service::install_service(None) {
                Ok(_) => {
                    println!("[+] CyberV Agent service installed successfully!");
                }
                Err(e) => {
                    eprintln!("[-] Failed to install service: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "uninstall" => {
            println!("[*] Uninstalling CyberV Agent Windows Service...");
            match cyberv_agent::service::uninstall_service() {
                Ok(_) => {
                    println!("[+] CyberV Agent service uninstalled successfully!");
                }
                Err(e) => {
                    eprintln!("[-] Failed to uninstall service: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "start" => {
            println!("[*] Starting CyberV Agent Windows Service...");
            match cyberv_agent::service::start_service() {
                Ok(_) => {
                    println!("[+] CyberV Agent service started successfully!");
                }
                Err(e) => {
                    eprintln!("[-] Failed to start service: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "stop" => {
            println!("[*] Stopping CyberV Agent Windows Service...");
            match cyberv_agent::service::stop_service() {
                Ok(_) => {
                    println!("[+] CyberV Agent service stopped successfully!");
                }
                Err(e) => {
                    eprintln!("[-] Failed to stop service: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "status" => {
            println!("[*] Querying CyberV Agent Windows Service status...");
            match cyberv_agent::service::query_service_status() {
                Ok(state) => {
                    println!("[+] Service Status: {}", state);
                }
                Err(e) => {
                    eprintln!("[-] Failed to query service status: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "--help" | "-h" | "help" => {
            print_usage();
        }
        "run" => {
            run_interactive_demo().await;
        }
        other => {
            eprintln!("[-] Unknown command: '{}'", other);
            print_usage();
            std::process::exit(1);
        }
    }
}

async fn run_interactive_demo() {
    // Khởi tạo tracing log chuẩn (Không bao giờ log secrets - Điều 6, 18, 19 Rule.md)
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    println!("================================================================================");
    println!("  CyberV Security Agent (v{})", PROTOCOL_VERSION);
    println!("  Protocol: {}", PROTOCOL_ID);
    println!("  Cryptographic Standard: SHA-512 (NSA CNSA Suite / FIPS 180-4)");
    println!("  Layer A: Hardware Observation | Layer B: Device Evidence Graph Engine");
    println!("================================================================================");

    match collect_hardware_snapshot() {
        Ok(snapshot) => {
            let report = HardwareReport::from_snapshot(&snapshot);
            println!("\n[+] 1. Quan sát phần cứng (Hardware Observation):");
            println!("    Nguồn thu thập:     {}", report.collector_source);
            println!("    Tổng số linh kiện:  {}", report.total_components);
            println!(
                "--------------------------------------------------------------------------------"
            );
            for summary in report.summaries {
                println!(
                    "    [{:<11}] {:<40} [{}]",
                    summary.component_type.to_string(),
                    summary.description,
                    summary.status
                );
            }
            println!(
                "--------------------------------------------------------------------------------"
            );

            // Phase 2: Băm linh kiện bằng SHA-512
            let hashed_components = hash_snapshot(&snapshot);
            println!("\n[+] 2. Băm linh kiện (Tier 1 Component Hashes):");
            println!(
                "--------------------------------------------------------------------------------"
            );
            for c in &hashed_components {
                let short_hash = format!(
                    "{}...{}",
                    &c.component_hash[..12],
                    &c.component_hash[c.component_hash.len() - 12..]
                );
                println!(
                    "    [{:<11}] {:<35} -> {}",
                    c.component_type.to_string(),
                    c.canonical_id,
                    short_hash
                );
            }
            println!(
                "--------------------------------------------------------------------------------"
            );

            // Phase 3: Xây dựng Đồ thị Bằng chứng Thiết bị (Device Evidence Graph Engine)
            let graph = build_evidence_graph(&hashed_components, 1);
            println!("\n[+] 3. Đồ thị Bằng chứng Thiết bị (Device Evidence Graph - Tier 2-5):");
            println!(
                "--------------------------------------------------------------------------------"
            );
            println!(
                "    Real Nodes:          {} (Root + Physical Components)",
                graph.nodes.len()
            );
            println!("    Topological Edges:   {}", graph.edges.len());
            println!(
                "    Virtual Nodes:       {} (Platform, Memory, Storage Topology)",
                graph.virtual_nodes.len()
            );
            for v in &graph.virtual_nodes {
                println!(
                    "      ├─ [{:<22}] inputs: {:<2} -> vhash: {}...{}",
                    v.virtual_type,
                    v.input_commitments.len(),
                    &v.virtual_hash[..10],
                    &v.virtual_hash[v.virtual_hash.len() - 10..]
                );
            }
            println!(
                "    Virtual Points:      {} (Deterministic Evidence Ratios)",
                graph.virtual_points.len()
            );
            for p in &graph.virtual_points {
                println!("      ├─ [{:<26}] Score: {}", p.id, p.to_display_string());
            }
            println!(
                "--------------------------------------------------------------------------------"
            );
            println!(
                "    Evidence Root:       {}...{}",
                &graph.evidence_root[..16],
                &graph.evidence_root[graph.evidence_root.len() - 16..]
            );
            println!(
                "    Graph Hash:          {}...{}",
                &graph.graph_hash[..16],
                &graph.graph_hash[graph.graph_hash.len() - 16..]
            );
            println!(
                "    Verification Hash:   {}...{}",
                &graph.verification_hash[..16],
                &graph.verification_hash[graph.verification_hash.len() - 16..]
            );
            println!(
                "--------------------------------------------------------------------------------"
            );
            println!("    Đồ thị bằng chứng đã hoàn thiện và được cam kết qua Verification Hash (SHA-512)!");

            // Phase 4: Danh tính Thiết bị (Ed25519), State Hash (Tier 6) & Giao thức Thử thách
            println!("\n[+] 4. Danh tính Mật mã học & Lưu trữ Bản sắc (Device Identity & DPAPI Storage):");
            println!(
                "--------------------------------------------------------------------------------"
            );

            // Khởi tạo lưu trữ Vault được bảo vệ bởi Windows DPAPI
            let storage = match cyberv_agent::identity::WindowsDpapiStorage::default_path() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("    [-] Không thể truy cập DPAPI vault: {}", e);
                    return;
                }
            };

            let identity = match storage.load_identity() {
                Ok(Some(id)) => {
                    println!("    [+] Đã tải danh tính thiết bị hiện hữu từ DPAPI Vault.");
                    id
                }
                _ => {
                    println!("    [*] Khởi tạo danh tính thiết bị mới qua CSPRNG...");
                    let mut rng = cyberv_agent::identity::OsCryptoRng;
                    let key = cyberv_agent::identity::DeviceIdentityKey::generate(&mut rng)
                        .expect("Tạo khóa thất bại");
                    let mut seed_bytes = [0u8; 32];
                    rng.fill(&mut seed_bytes).expect("Sinh seed thất bại");
                    let seed = cyberv_agent::identity::Secret32::new(seed_bytes);
                    let dev_id = uuid::Uuid::new_v4().to_string();

                    let new_id = cyberv_agent::identity::PersistedIdentity::new(
                        dev_id,
                        seed,
                        key.secret_bytes(),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    );
                    storage.save_identity(&new_id).expect("Lưu vault thất bại");
                    println!("    [+] Đã lưu danh tính thiết bị an toàn vào Windows DPAPI Vault.");
                    new_id
                }
            };

            let keypair =
                cyberv_agent::identity::DeviceIdentityKey::from_secret_bytes(&identity.signing_key)
                    .expect("Nạp khóa signing thất bại");

            println!("    Device ID (UUIDv4):  {}", identity.device_id);
            println!("    Public Key (Ed25519): {}", keypair.public_key_hex());
            println!(
                "    Vault Path:          {}",
                storage.vault_path().display()
            );
            println!(
                "--------------------------------------------------------------------------------"
            );

            // Phase 4 - Bước 2: Đánh giá State Hash (Tier 6 Final State Hash)
            println!("\n[+] 5. Trạng thái Thiết bị Toàn diện (Tier 6 State Hash - SHA-512):");
            let mut context_attrs = std::collections::BTreeMap::new();
            context_attrs.insert("os".to_string(), std::env::consts::OS.to_string());
            context_attrs.insert("arch".to_string(), std::env::consts::ARCH.to_string());
            context_attrs.insert(
                "agent_ver".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
            );

            let device_state = cyberv_agent::fingerprint::state_hasher::evaluate_device_state(
                &identity.device_id,
                1,
                &graph.verification_hash,
                &context_attrs,
            );

            println!(
                "--------------------------------------------------------------------------------"
            );
            println!(
                "    State Schema Ver:    {}",
                device_state.state_schema_version
            );
            println!("    Graph Version:       {}", device_state.graph_version);
            println!(
                "    Final State Hash:    {}...{}",
                &device_state.state_hash[..16],
                &device_state.state_hash[device_state.state_hash.len() - 16..]
            );
            println!(
                "--------------------------------------------------------------------------------"
            );

            // Phase 4 - Bước 3: Diễn tập Giao thức Thử Thách (Challenge-Response Proof-of-Possession)
            println!("\n[+] 6. Giao thức Thử Thách & Chứng Minh Quyền Sở Hữu (Challenge-Response Proof):");
            println!(
                "--------------------------------------------------------------------------------"
            );
            let mut nonce_bytes = [0u8; 32];
            let mut rng = cyberv_agent::identity::OsCryptoRng;
            rng.fill(&mut nonce_bytes).unwrap();
            let nonce_hex: String = nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect();

            let sample_challenge = cyberv_agent::protocol::challenge::ChallengeObject {
                challenge_id: uuid::Uuid::new_v4().to_string(),
                nonce: nonce_hex,
                device_id: identity.device_id.clone(),
                purpose: cyberv_agent::protocol::constants::PURPOSE_DEVICE_AUTH.to_string(),
                issued_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                expires_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 60,
            };

            println!("    [Server] Phát sinh Thử thách:");
            println!("      ├─ Challenge ID:  {}", sample_challenge.challenge_id);
            println!(
                "      ├─ Nonce (256-b): {}...",
                &sample_challenge.nonce[..24]
            );
            println!("      ├─ Purpose:       {}", sample_challenge.purpose);
            println!("      └─ TTL:           60s (Chống Replay Attack)");

            let proof = cyberv_agent::protocol::challenge::create_challenge_proof(
                &keypair,
                &sample_challenge,
                &device_state.state_hash,
                device_state.graph_version,
            )
            .expect("Ký proof thất bại");

            println!("    [Agent] Ký Payload chính tắc bằng Ed25519 Private Key:");
            println!("      └─ Chữ ký Proof:  {}...", &proof.signature_hex[..32]);

            let verify_ok = cyberv_agent::protocol::challenge::verify_challenge_proof(
                keypair.verifying_key(),
                &proof,
            );
            assert!(verify_ok.is_ok());
            println!("    [Server] Thẩm định chữ ký Ed25519: THÀNH CÔNG (AUTHENTICATED)!");
            println!(
                "--------------------------------------------------------------------------------"
            );

            // Phase 4 - Bước 4: Minh họa Bất biến "Identity Sống Lâu — State Sống Ngắn" (rv4.md #15, #16)
            println!("\n[+] 7. Thử nghiệm Bất biến: Thay đổi Phần cứng (Hardware State Mutation):");
            println!(
                "--------------------------------------------------------------------------------"
            );
            // Giả lập thay đổi linh kiện (Nâng cấp mô-đun RAM từ 8GB lên 16GB)
            let mut snap_ram = snapshot.clone();
            for comp in &mut snap_ram.components {
                if comp.component_type == cyberv_agent::hardware::models::ComponentType::Memory {
                    comp.canonical_id = format!("{}:upgraded", comp.canonical_id);
                    comp.attributes
                        .insert("capacity_bytes".to_string(), "17179869184".to_string());
                    break;
                }
            }
            let h_ram = cyberv_agent::fingerprint::hash_snapshot(&snap_ram);
            let g_ram = cyberv_agent::fingerprint::build_evidence_graph(&h_ram, 2);
            let state_ram = cyberv_agent::fingerprint::state_hasher::evaluate_device_state(
                &identity.device_id,
                2,
                &g_ram.verification_hash,
                &context_attrs,
            );

            println!("    [!] Phát hiện thay đổi linh kiện (RAM Upgrade):");
            println!(
                "      ├─ Verification Hash cũ -> mới: {}... -> {}...",
                &graph.verification_hash[..8],
                &g_ram.verification_hash[..8]
            );
            println!(
                "      ├─ State Hash cũ -> mới:        {}... -> {}...",
                &device_state.state_hash[..8],
                &state_ram.state_hash[..8]
            );
            println!(
                "      ├─ Device ID vẫn giữ nguyên:    {} (STABLE)",
                identity.device_id
            );
            println!(
                "      ├─ Ed25519 Public Key nguyên:   {}... (STABLE)",
                &keypair.public_key_hex()[..16]
            );
            println!(
                "--------------------------------------------------------------------------------"
            );

            // Phase 5: Động Cơ Đánh Giá Rủi Ro Đa Tín Hiệu & Ma Trận Quyết Định (Risk Engine & Decision Matrix)
            println!("\n[+] 8. Động Cơ Đánh Giá Rủi Ro Đa Tín Hiệu (Phase 5 - Multi-Signal Risk Engine):");
            println!(
                "--------------------------------------------------------------------------------"
            );

            // Kịch bản A: Nâng cấp RAM (v1 -> v2)
            let diff_ram = cyberv_agent::fingerprint::diff_evidence_graphs(&graph, &g_ram);
            let risk_ram =
                cyberv_agent::risk::engine::evaluate_risk(&diff_ram, &graph, &g_ram, 1, 2);
            println!("    [Kịch bản 1] Nâng cấp RAM (RAM Upgrade v1 -> v2):");
            println!(
                "      ├─ Điểm số nguyên:  {}/10000 ({:.2}%)",
                risk_ram.score,
                risk_ram.score as f64 / 100.0
            );
            println!("      ├─ Mức độ rủi ro:   {}", risk_ram.level);
            println!(
                "      ├─ Quyết định:      {:?} (Lành tính, tự động phê duyệt)",
                risk_ram.decision
            );
            for sig in &risk_ram.signals {
                println!(
                    "      └─ Tín hiệu:        [{}] +{} pts - {}",
                    sig.code, sig.penalty, sig.description
                );
            }

            // Kịch bản B: Thay đổi Bo Mạch Chủ (Motherboard swap)
            let mut snap_board = snapshot.clone();
            for comp in &mut snap_board.components {
                if comp.component_type == cyberv_agent::hardware::models::ComponentType::Motherboard
                {
                    comp.canonical_id = "board:msi:swapped-board".to_string();
                    comp.attributes
                        .insert("serial".to_string(), "msi-swap-999".to_string());
                }
            }
            let h_board = cyberv_agent::fingerprint::hash_snapshot(&snap_board);
            let g_board = cyberv_agent::fingerprint::build_evidence_graph(&h_board, 2);
            let diff_board = cyberv_agent::fingerprint::diff_evidence_graphs(&graph, &g_board);
            let risk_board =
                cyberv_agent::risk::engine::evaluate_risk(&diff_board, &graph, &g_board, 1, 2);
            println!("\n    [Kịch bản 2] Thay đổi Bo Mạch Chủ (Motherboard Swap v1 -> v2):");
            println!(
                "      ├─ Điểm số nguyên:  {}/10000 ({:.2}%)",
                risk_board.score,
                risk_board.score as f64 / 100.0
            );
            println!("      ├─ Mức độ rủi ro:   {}", risk_board.level);
            println!(
                "      ├─ Quyết định:      {:?} (Yêu cầu người dùng duyệt)",
                risk_board.decision
            );
            for sig in &risk_board.signals {
                println!(
                    "      └─ Tín hiệu:        [{}] +{} pts - {}",
                    sig.code, sig.penalty, sig.description
                );
            }

            // Kịch bản C: Tấn công Rollback phiên bản (v2 -> v1)
            let risk_rollback =
                cyberv_agent::risk::engine::evaluate_risk(&diff_ram, &g_ram, &graph, 2, 1);
            println!("\n    [Kịch bản 3] Tấn công Quay lui Phiên bản (Rollback Attack v2 -> v1):");
            println!(
                "      ├─ Điểm số nguyên:  {}/10000 (TỐI ĐA)",
                risk_rollback.score
            );
            println!("      ├─ Mức độ rủi ro:   {}", risk_rollback.level);
            println!(
                "      ├─ Quyết định:      {:?} (Khóa chặn vi phạm bảo mật)",
                risk_rollback.decision
            );
            for sig in &risk_rollback.signals {
                println!(
                    "      └─ Tín hiệu:        [{}] +{} pts - {}",
                    sig.code, sig.penalty, sig.description
                );
            }
            println!(
                "--------------------------------------------------------------------------------"
            );

            // Phase 5 - Bước 2: Giao thức Tái Cấp Quyền Động (Dynamic Re-enrollment Pipeline)
            println!("\n[+] 9. Giao Thức Tái Cấp Quyền Động (Dynamic Re-enrollment Protocol):");
            println!(
                "--------------------------------------------------------------------------------"
            );
            let reenroll_req = cyberv_agent::protocol::reenroll::create_reenrollment_request(
                &keypair,
                &identity.device_id,
                &device_state.state_hash,
                &state_ram.state_hash,
                &g_ram.graph_hash,
                2,
                "Authorized RAM upgrade to 64GB DDR5",
            )
            .expect("Tạo yêu cầu re-enrollment thất bại");

            println!("    [Agent] Tạo Re-enrollment Request với chữ ký số Ed25519:");
            println!("      ├─ Device ID:            {}", reenroll_req.device_id);
            println!(
                "      ├─ Previous State Hash:  {}...",
                &reenroll_req.previous_state_hash[..16]
            );
            println!(
                "      ├─ New State Hash:       {}...",
                &reenroll_req.new_state_hash[..16]
            );
            println!(
                "      ├─ New Graph Version:    {} (Tăng đơn điệu v1 -> v2)",
                reenroll_req.new_graph_version
            );
            println!("      ├─ Reason:               {}", reenroll_req.reason);
            println!(
                "      └─ Ed25519 Proof Sig:    {}...",
                &reenroll_req.proof_signature[..32]
            );

            // Thẩm định chữ ký tại Server/Cloud
            let reenroll_verify = cyberv_agent::protocol::reenroll::verify_reenrollment_request(
                keypair.verifying_key(),
                &reenroll_req,
            );
            assert!(reenroll_verify.is_ok());
            println!("\n    [Server] Thẩm định chữ ký Re-enrollment chính tắc: HỢP LỆ!");
            println!(
                "--------------------------------------------------------------------------------"
            );

            // Phase 6: Giao Tiếp Mạng Thực Tế & Tiến Trình Tự Hành (Phase 6 - Live Transport & Autonomous Daemon)
            println!("\n[+] 10. Giao Tiếp Mạng & Tiến Trình Tự Hành (Phase 6 - Live Transport & Autonomous Daemon):");
            println!(
                "--------------------------------------------------------------------------------"
            );

            let mock_transport = cyberv_agent::transport::client::MockDeviceTransport::new();
            let mut daemon = cyberv_agent::daemon::AgentDaemon::new(
                mock_transport.clone(),
                cyberv_agent::hardware::mock::MockHardwareCollector::baseline().unwrap(),
                keypair.clone(),
                identity.device_id.clone(),
                "sample_user_jwt_session_token",
            );

            println!("    [Daemon] Khởi tạo Agent Daemon:");
            println!("      ├─ Trạng thái ban đầu:   {:?}", daemon.state());
            println!("      ├─ Device ID:            {}", daemon.device_id());
            println!("      └─ Transport:            MockDeviceTransport (TLS / Backoff Ready)");

            // Bước 1: Tự động Đăng ký Ban Đầu (Auto-Enrollment qua mạng)
            let state_after_enroll = daemon.tick().await.expect("Daemon enroll tick failed");
            println!("\n    [Daemon] Nhịp 1: Đăng ký Thiết bị ban đầu qua mạng (POST /enroll):");
            println!("      ├─ Ký số Ed25519 với miền: CYBERV/DBS/ENROLL/v1");
            println!("      └─ Trạng thái mới:       {:?}", state_after_enroll);

            // Bước 2: Chứng thực Định kỳ (Periodic Attestation qua mạng)
            let state_after_attest = daemon.tick().await.expect("Daemon attest tick failed");
            println!("\n    [Daemon] Nhịp 2: Chứng thực Định kỳ Trạng thái (POST /challenge -> /verify-state):");
            println!("      ├─ Thử thách & Nonce:    HỢP LỆ (60s TTL)");
            println!("      └─ Trạng thái mới:       {:?}", state_after_attest);

            // Bước 3: Phát hiện biến động phần cứng (RAM upgrade) & Tự động Re-enroll
            daemon.set_collector(
                cyberv_agent::hardware::mock::MockHardwareCollector::ram_upgrade().unwrap(),
            );
            let state_after_mutation = daemon.tick().await.expect("Daemon mutation tick failed");
            println!("\n    [Daemon] Nhịp 3: Phát hiện biến động phần cứng (RAM Upgrade) & Tự động Tái Cấp Quyền:");
            println!("      ├─ Biến động:            Phát hiện State Hash thay đổi!");
            println!("      ├─ Tự động tạo:          ReenrollmentRequest (DOMAIN_REENROLL)");
            println!("      ├─ Gửi Server:           POST /re-enroll -> AUTO_PROMOTE");
            println!("      └─ Trạng thái thăng cấp: {:?}", state_after_mutation);
            println!(
                "--------------------------------------------------------------------------------"
            );
            println!(
                "  TẤT CẢ CHỐT CHẶN AN NINH & GIAO TIẾP MẠNG CỦA PHASE 6 ĐÃ HOÀN TẤT XUẤT SẮC!"
            );
        }
        Err(e) => {
            eprintln!("\n[-] Lỗi khi quan sát và xây dựng đồ thị: {}", e);
        }
    }
}
