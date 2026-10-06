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
//! TCP-LAN transport — Tier A của mesh (M-PLAN M-1, plan §10)
//!
//! Frame = wire format có sẵn của lớp trên (u32 BE length prefix):
//! bắt tay `HandshakeMessage::encode` hoặc `MeshSession::seal` truyền thẳng
//! qua link, transport không biết gì về mật mã. Đọc frame **cancel-safe**:
//! buffer bán phần nằm trong `TcpLink` (không trong future), nên hủy
//! `read_frame` giữa chừng (timeout/idle poll) không mất byte.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::super::discovery::MeshBeacon;
use super::super::MeshError;
use super::{ConnectFuture, Endpoint, InboundLinks, MeshLink, MeshTransport, TransportId};

/// Trần đọc kinh điển mỗi lần đợi socket — buffer nội bộ gom cho đủ frame.
const READ_CHUNK: usize = 8 * 1024;

fn map_io(e: std::io::Error, context: &str) -> MeshError {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::BrokenPipe => MeshError::LinkClosed(format!("{context}: {e}")),
        _ => MeshError::TransportIo(format!("{context}: {e}")),
    }
}

/// Transport Tier A: TCP trên LAN. Listener bind ngay khi dựng để caller biết
/// cổng (port 0 = hệ điều hành chọn); `listen()` bật accept loop.
pub struct TcpLanTransport {
    listener: Option<std::sync::Arc<TcpListener>>,
    listening: bool,
    advertised: Option<MeshBeacon>,
    connect_timeout: Duration,
}

impl TcpLanTransport {
    /// Dựng transport chưa bind — chỉ dùng cho outbound thuần.
    pub fn new(connect_timeout: Duration) -> Self {
        Self { listener: None, listening: false, advertised: None, connect_timeout }
    }

    /// Bind listener ngay (đồng bộ qua runtime hiện hành) — port 0 để HĐH chọn.
    pub async fn bind(addr: SocketAddr, connect_timeout: Duration) -> Result<Self, MeshError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| MeshError::TransportIo(format!("bind mesh TCP {addr}: {e}")))?;
        Ok(Self {
            listener: Some(std::sync::Arc::new(listener)),
            listening: false,
            advertised: None,
            connect_timeout,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.as_ref().and_then(|l| l.local_addr().ok())
    }
}

impl MeshTransport for TcpLanTransport {
    fn id(&self) -> TransportId {
        TransportId::TcpLan
    }

    fn advertise(&mut self, beacon: &MeshBeacon) -> Result<(), MeshError> {
        // TCP thuần KHÔNG có kênh quảng bá riêng — beacon chỉ được lưu để tầng
        // discovery (M-2, mDNS) phát hộ. Ghi nhận cấu hình, không giả vờ phát.
        self.advertised = Some(*beacon);
        Ok(())
    }

    fn browse(&mut self) -> Vec<(MeshBeacon, Endpoint)> {
        // TCP không tự discovery — M-2 (mDNS) bổ sung nguồn endpoint.
        Vec::new()
    }

    fn connect(&mut self, ep: Endpoint) -> ConnectFuture<'_> {
        Box::pin(async move {
            if ep.transport != TransportId::TcpLan {
                return Err(MeshError::InvalidEndpoint(format!(
                    "TCP không nhận endpoint của transport khác: {:?}",
                    ep.transport
                )));
            }
            let connect = TcpStream::connect(ep.addr);
            let stream = if self.connect_timeout.is_zero() {
                connect.await
            } else {
                timeout(self.connect_timeout, connect)
                    .await
                    .map_err(|_| {
                        MeshError::InvalidEndpoint(format!("hết giờ kết nối {}", ep.addr))
                    })?
            }
            .map_err(|e| MeshError::TransportIo(format!("kết nối TCP {}: {e}", ep.addr)))?;
            // Nodelay: frame mesh nhỏ, tránh trễ Nagle — lỗi không chí mạng.
            stream.set_nodelay(true).ok();
            Ok(Box::new(TcpLink::new(stream, ep.addr)) as Box<dyn MeshLink>)
        })
    }

    fn listen(&mut self) -> Result<InboundLinks, MeshError> {
        if self.listening {
            return Err(MeshError::InvalidEndpoint("mesh TCP đã lắng nghe".into()));
        }
        let listener = self
            .listener
            .clone()
            .ok_or_else(|| MeshError::InvalidEndpoint("chưa bind listener".into()))?;
        let (tx, rx) = mpsc::unbounded_channel();
        self.listening = true;
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        stream.set_nodelay(true).ok();
                        let link = Box::new(TcpLink::new(stream, peer)) as Box<dyn MeshLink>;
                        // Receiver sống cùng node — nếu đã drop thì task kết thúc.
                        if tx.send(link).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        // Lỗi accept của listener: nguồn link mới đứt hẳn —
                        // kết thúc task, receiver nhận None (caller biết rõ).
                        tracing::warn!(error = %e, "mesh TCP accept lỗi — dừng nhận inbound");
                        break;
                    }
                }
            }
        });
        Ok(InboundLinks { rx })
    }
}

/// Link TCP với đọc frame cancel-safe: buffer bán phần nằm trong struct,
/// hủy future ở bất kỳ await point nào không làm mất byte đã nhận.
pub struct TcpLink {
    stream: TcpStream,
    peer: SocketAddr,
    class: u64,
    rx_buf: Vec<u8>,
    /// Độ dài thân đã parse từ header (None = chưa đủ 4 byte header).
    rx_frame_len: Option<usize>,
}

impl TcpLink {
    pub fn new(stream: TcpStream, peer: SocketAddr) -> Self {
        Self::new_with_transport(stream, peer, TransportId::TcpLan)
    }

    /// Link TCP cho dữ liệu chạy trên carrier khác (WFD — M-3): socket là
    /// TCP thuần nhưng path_class theo transport thật ⇒ quorum thấy đa dạng
    /// đường (plan §10 Tier B).
    pub fn new_with_transport(stream: TcpStream, peer: SocketAddr, transport: TransportId) -> Self {
        let class = super::path_class(transport, super::subnet_scope(peer.ip()));
        Self { stream, peer, class, rx_buf: Vec::new(), rx_frame_len: None }
    }
}

impl MeshLink for TcpLink {
    fn transport_id(&self) -> TransportId {
        TransportId::TcpLan
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    fn path_class(&self) -> u64 {
        self.class
    }

    fn read_frame(&mut self) -> super::LinkFuture<'_, Vec<u8>> {
        Box::pin(async move {
            loop {
                // 1. Parse header khi đủ 4 byte — bounds TRƯỚC khi cấp phát thân.
                if self.rx_frame_len.is_none() && self.rx_buf.len() >= 4 {
                    let len = u32::from_be_bytes(
                        self.rx_buf[..4].try_into().expect("đã đủ 4 byte header"),
                    ) as usize;
                    if len == 0 {
                        return Err(MeshError::Frame("frame rỗng".into()));
                    }
                    if len > super::super::session::MAX_FRAME_SIZE {
                        return Err(MeshError::Frame(format!(
                            "frame vượt giới hạn: {len} > {}",
                            super::super::session::MAX_FRAME_SIZE
                        )));
                    }
                    self.rx_frame_len = Some(len);
                }
                // 2. Thân đủ → nhả frame (kèm 4 byte prefix như wire format).
                if let Some(len) = self.rx_frame_len {
                    if self.rx_buf.len() >= 4 + len {
                        self.rx_frame_len = None;
                        return Ok(self.rx_buf.drain(..4 + len).collect::<Vec<u8>>());
                    }
                }
                // 3. Đợi thêm byte. Buffer không thể vượt 4 + MAX_FRAME_SIZE:
                //    header rác (len quá trần/rỗng) đã trả lỗi ở bước 1.
                let mut chunk = [0u8; READ_CHUNK];
                let n = self
                    .stream
                    .read(&mut chunk)
                    .await
                    .map_err(|e| map_io(e, "đọc frame TCP"))?;
                if n == 0 {
                    return Err(MeshError::LinkClosed("peer đóng kết nối".into()));
                }
                self.rx_buf.extend_from_slice(&chunk[..n]);
            }
        })
    }

    fn write_frame(&mut self, frame: &[u8]) -> super::LinkFuture<'_, ()> {
        if frame.len() > 4 + super::super::session::MAX_FRAME_SIZE {
            let err = MeshError::Frame(format!("frame ghi vượt giới hạn: {}", frame.len()));
            return Box::pin(async move { Err(err) });
        }
        // Copy ≤ 64KB — hợp đồng trait: future chỉ mượn &mut self.
        let owned = frame.to_vec();
        Box::pin(async move {
            self.stream
                .write_all(&owned)
                .await
                .map_err(|e| map_io(e, "ghi frame TCP"))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tcp_path_class;

    async fn linked_pair() -> (TcpLink, TcpLink) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let server_stream = server.await.unwrap();
        let (a, b) = (client, server_stream);
        (TcpLink::new(a, addr), TcpLink::new(b, "127.0.0.1:1".parse().unwrap()))
    }

    #[tokio::test]
    async fn frame_roundtrip_respects_length_prefix() {
        let (mut a, mut b) = linked_pair().await;
        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&[1, 2, 3, 4, 5]);
        frame[..4].copy_from_slice(&5u32.to_be_bytes());
        a.write_frame(&frame).await.unwrap();
        let got = b.read_frame().await.unwrap();
        assert_eq!(got, frame);
        assert_eq!(got.len(), 9);
    }

    #[tokio::test]
    async fn many_frames_survive_coalesced_tcp_segments() {
        // Nhiều frame trong một segment TCP — reader phải tách đúng từng frame.
        let (mut a, mut b) = linked_pair().await;
        let mut wire = Vec::new();
        for i in 0..10u32 {
            let mut f = vec![0u8; 4];
            f.extend_from_slice(&i.to_be_bytes());
            f[..4].copy_from_slice(&4u32.to_be_bytes());
            wire.extend_from_slice(&f);
        }
        a.stream.write_all(&wire).await.unwrap();
        for i in 0..10u32 {
            let got = b.read_frame().await.unwrap();
            assert_eq!(&got[4..8], &i.to_be_bytes());
        }
    }

    #[tokio::test]
    async fn oversized_length_rejected_without_allocation() {
        // Peer gian lận khai 4GB — phải từ chối TRƯỚC khi cấp phát.
        let (mut a, mut b) = linked_pair().await;
        a.stream.write_all(&0xFFFF_FFFFu32.to_be_bytes()).await.unwrap();
        let err = b.read_frame().await.unwrap_err();
        assert!(matches!(err, MeshError::Frame(_)));
    }

    #[tokio::test]
    async fn empty_frame_rejected() {
        let (mut a, mut b) = linked_pair().await;
        a.stream.write_all(&0u32.to_be_bytes()).await.unwrap();
        assert!(matches!(b.read_frame().await.unwrap_err(), MeshError::Frame(_)));
    }

    #[tokio::test]
    async fn cancelled_read_resumes_without_byte_loss() {
        // read_frame bị hủy giữa chừng (giả lập timeout) → gọi lại phải khôi
        // phục đúng frame — cancel-safe là hợp đồng của MeshLink.
        let (mut a, mut b) = linked_pair().await;
        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&[0xAB; 32]);
        frame[..4].copy_from_slice(&32u32.to_be_bytes());
        // Gửi TỪNG MIẾNG nhỏ, hủy đọc ở giữa các miếng. Kết quả của lần hủy
        // KHÔNG được vứt đi vô ý thức — frame có thể hoàn tất đúng lần đó.
        let mut got: Option<Vec<u8>> = None;
        for chunk in frame.chunks(10) {
            a.stream.write_all(chunk).await.unwrap();
            a.stream.flush().await.unwrap();
            if let Ok(res) =
                tokio::time::timeout(std::time::Duration::from_millis(1), b.read_frame()).await
            {
                got = Some(res.expect("read_frame phải thành công khi hoàn tất"));
                break;
            }
        }
        let got = match got {
            Some(f) => f,
            None => b.read_frame().await.expect("frame phải về trọn vẹn"),
        };
        assert_eq!(got, frame);
    }

    #[tokio::test]
    async fn eof_maps_to_link_closed() {
        let (a, mut b) = linked_pair().await;
        drop(a);
        let err = b.read_frame().await.unwrap_err();
        assert!(matches!(err, MeshError::LinkClosed(_)));
    }

    #[tokio::test]
    async fn path_class_derived_from_remote_subnet() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        let client = TcpStream::connect(addr).await.unwrap();
        // accept() trả (stream, addr-đối-tác) — tên biến theo đúng thứ tự đó.
        let (server_stream, accepted_peer) = server.await.unwrap();
        let link = TcpLink::new(server_stream, accepted_peer);
        assert_eq!(link.path_class(), tcp_path_class(accepted_peer.ip()));
        assert_eq!(link.transport_id(), TransportId::TcpLan);
        drop(client);
    }
}
