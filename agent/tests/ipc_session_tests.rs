//! P1-1 — IPC session tests: pipe thật trên Windows, handshake 2 bước +
//! phiên AEAD.
//!
//! Ref: PHASE1_2 plan P1-1, INV-012. Suite chứng minh: phiên AEAD trọn vẹn
//! trên pipe thật (GetStatus/HeartbeatPing có server_seen_client_pid từ
//! kernel); server KHÔNG có khóa identity → fail-closed; frame replay → đóng
//! kết nối; frame quá hạn mức → đóng; hello sai version → từ chối.

#![cfg(windows)]

use cyberv_agent::defense::passive::ipc::server::win_server::NamedPipeServer;
use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::{OsCryptoRng, SecureRandom};
use cyberv_agent::mesh::pipe_session::{
    client_finish_pipe_handshake, PipeHello, PipeHelloAck,
};
use cyberv_agent::mesh::session::{MeshSession, MESH_WIRE_VERSION};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ClientOptions;
use x25519_dalek::{PublicKey, StaticSecret};

/// Tên pipe duy nhất mỗi test (cùng process chạy song song).
fn unique_pipe_name(label: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!(r"\\.\pipe\CyberVTest-{}-{label}-{n}", std::process::id())
}

/// Spawn server KHÔNG khóa identity — chỉ test_02 dùng (fail-closed path).
fn spawn_server(name: &str) -> (Arc<NamedPipeServer>, tokio::task::JoinHandle<()>) {
    let server = Arc::new(NamedPipeServer::new(name).with_identity_key_opt(None));
    let s2 = server.clone();
    let handle = tokio::spawn(async move {
        let _ = s2.run_server().await;
    });
    (server, handle)
}

fn spawn_server_with_key(
    name: &str,
) -> (DeviceIdentityKey, Arc<NamedPipeServer>, tokio::task::JoinHandle<()>) {
    let key = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
    let server = Arc::new(NamedPipeServer::new(name).with_identity_key_opt(Some(key.clone())));
    let s2 = server.clone();
    let handle = tokio::spawn(async move {
        let _ = s2.run_server().await;
    });
    (key, server, handle)
}

async fn connect_pipe(name: &str) -> tokio::net::windows::named_pipe::NamedPipeClient {
    for _ in 0..150 {
        if let Ok(c) = ClientOptions::new().open(name) {
            return c;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("không kết nối được pipe {name} sau 3 giây");
}

/// Đọc 1 frame wire: len(4 BE) || body.
async fn read_frame(
    c: &mut (impl tokio::io::AsyncReadExt + Unpin),
) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    c.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    c.read_exact(&mut body).await?;
    let mut full = len_buf.to_vec();
    full.extend_from_slice(&body);
    Ok(full)
}

/// Bắt tay 2 bước phía client — trả phiên AEAD.
async fn client_handshake(
    c: &mut (impl tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin),
    agent_vk: &ed25519_dalek::VerifyingKey,
) -> MeshSession {
    let mut seed = [0u8; 32];
    OsCryptoRng.fill(&mut seed).unwrap();
    let client_eph = StaticSecret::from(seed);
    let client_pk = PublicKey::from(&client_eph).to_bytes();

    let hello = PipeHello { version: MESH_WIRE_VERSION, pk_ephemeral: client_pk };
    c.write_all(&hello.encode()).await.unwrap();

    let ack_bytes = read_frame(c).await.unwrap();
    let ack = PipeHelloAck::decode(&ack_bytes).unwrap();
    client_finish_pipe_handshake(&ack, agent_vk, &client_eph, &client_pk).unwrap()
}

fn get_status_envelope() -> Vec<u8> {
    // Envelope JSON khớp schema `IpcMessageEnvelope` — sender_pid tự khai là
    // 0 CỐ Ý: phản hồi phải mang server_seen_client_pid do KERNEL xác nhận.
    br#"{"message_id":"m1","command":"GetStatus","sender_pid":0,"timestamp":1}"#.to_vec()
}

// ====================================================================
// Nhóm 1: Phiên AEAD trọn vẹn trên pipe thật
// ====================================================================

#[tokio::test]
async fn test_01_secure_session_roundtrip_getstatus_and_ping() {
    let name = unique_pipe_name("happy");
    let (agent_key, server, _handle) = spawn_server_with_key(&name);
    let mut client = connect_pipe(&name).await;

    let mut session = client_handshake(&mut client, agent_key.verifying_key()).await;

    // GetStatus qua phiên AEAD — sender_pid tự khai 0 nhưng phản hồi phải
    // mang server_seen_client_pid do kernel xác nhận (== PID test process).
    let frame = session.seal(1, &get_status_envelope()).unwrap();
    client.write_all(&frame).await.unwrap();
    let resp_frame = read_frame(&mut client).await.unwrap();
    let (_t, payload) = session.open(&resp_frame).unwrap();
    let resp = String::from_utf8(payload).unwrap();
    assert!(resp.contains("\"success\":true"), "phản hồi: {resp}");
    assert!(resp.contains("server_seen_client_pid"), "phải có PID kernel: {resp}");
    assert!(
        resp.contains(&format!("\"server_seen_client_pid\":{}", std::process::id())),
        "PID kernel phải là PID test process: {resp}"
    );

    // HeartbeatPing — nhiều lượt trên cùng một phiên (sequence tăng).
    let ping = br#"{"message_id":"m2","command":{"HeartbeatPing":{"timestamp":42}},"sender_pid":0,"timestamp":2}"#;
    let frame = session.seal(1, ping).unwrap();
    client.write_all(&frame).await.unwrap();
    let resp_frame = read_frame(&mut client).await.unwrap();
    let (_t, payload) = session.open(&resp_frame).unwrap();
    let resp = String::from_utf8(payload).unwrap();
    assert!(resp.contains("\"pong\":true"), "phản hồi: {resp}");

    server.stop();
}

// ====================================================================
// Nhóm 2: Fail-closed + tấn công bị chặn
// ====================================================================

#[tokio::test]
async fn test_02_server_without_identity_fails_closed() {
    let name = unique_pipe_name("noid");
    let (server, _handle) = spawn_server(&name);
    let mut client = connect_pipe(&name).await;

    // Gửi hello hợp lệ — server không có khóa → chỉ ERR plaintext rồi đóng.
    let mut seed = [0u8; 32];
    OsCryptoRng.fill(&mut seed).unwrap();
    let client_pk = PublicKey::from(&StaticSecret::from(seed)).to_bytes();
    let hello = PipeHello { version: MESH_WIRE_VERSION, pk_ephemeral: client_pk };
    client.write_all(&hello.encode()).await.unwrap();

    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf);
    assert!(resp.contains("fail-closed"), "phản hồi: {resp}");
    server.stop();
}

#[tokio::test]
async fn test_03_replayed_frame_closes_connection() {
    let name = unique_pipe_name("replay");
    let (agent_key, server, _handle) = spawn_server_with_key(&name);
    let mut client = connect_pipe(&name).await;
    let mut session = client_handshake(&mut client, agent_key.verifying_key()).await;

    // Frame hợp lệ lần 1 → có phản hồi.
    let frame = session.seal(1, &get_status_envelope()).unwrap();
    client.write_all(&frame).await.unwrap();
    let resp_frame = read_frame(&mut client).await.unwrap();
    assert!(session.open(&resp_frame).is_ok());

    // Gửi LẠI đúng frame đó (replay) — server phát hiện và đóng, không phản hồi.
    client.write_all(&frame).await.unwrap();
    let mut eof_buf = [0u8; 16];
    let n = client.read(&mut eof_buf).await.unwrap_or(0);
    assert_eq!(n, 0, "server phải đóng kết nối sau replay, không gửi gì thêm");
    server.stop();
}

#[tokio::test]
async fn test_04_oversized_frame_closes_connection() {
    let name = unique_pipe_name("big");
    let (agent_key, server, _handle) = spawn_server_with_key(&name);
    let mut client = connect_pipe(&name).await;
    // Vẫn bắt tay đủ để ở trạng thái phiên — frame quá hạn mức xảy ra SAU handshake.
    let _session = client_handshake(&mut client, agent_key.verifying_key()).await;

    // Prefix gian lận: khai body ~4GB — server chặn bound TRƯỚC khi cấp phát
    // và đóng kết nối.
    let bogus: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0];
    client.write_all(&bogus).await.unwrap();
    let mut eof_buf = [0u8; 16];
    let n = client.read(&mut eof_buf).await.unwrap_or(0);
    assert_eq!(n, 0, "server phải đóng kết nối sau frame quá hạn mức");
    server.stop();
}

#[tokio::test]
async fn test_05_handshake_wrong_version_rejected() {
    let name = unique_pipe_name("ver");
    let (_agent_key, server, _handle) = spawn_server_with_key(&name);
    let mut client = connect_pipe(&name).await;

    let mut seed = [0u8; 32];
    OsCryptoRng.fill(&mut seed).unwrap();
    let client_pk = PublicKey::from(&StaticSecret::from(seed)).to_bytes();
    let old_hello = PipeHello { version: MESH_WIRE_VERSION - 1, pk_ephemeral: client_pk };
    client.write_all(&old_hello.encode()).await.unwrap();

    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf);
    assert!(resp.contains("Handshake rejected"), "phản hồi: {resp}");
    server.stop();
}
