# CyberV — Gate 0: Security Contract Freeze

> **EN: Security Contract Freeze Specification. Defines the canonical trust,
> identity, evidence, protocol, ABI, and state machine models before any
> implementation code is written. Invariants INV-001..008 govern all rules.**

---

## 1. Identity Model vs Evidence Model (Phân định Danh tính & Bằng chứng)

### 1.1 Cryptographic Identity (Danh tính Mật mã — Bất biến)
- **Thiết bị hợp lệ** chỉ được định danh bởi cặp khóa mật mã:
  1. `DeviceIdentityKey` (Ed25519): Lưu trong DPAPI Vault với `Secret32` (ZeroizeOnDrop), dùng cho ký giao thức, request lên Cloud, và bắt tay Mesh.
  2. `PcpAttestationKey` (TPM 2.0 P-256): Sinh và lưu trong TPM qua Microsoft Platform Crypto Provider (CNG/PCP). Khóa riêng không bao giờ rời chip TPM. Dùng để chứng minh "khóa neo trong phần cứng thật".
- **Không có chữ ký hợp lệ** $\implies$ Không có danh tính. Không một thuộc tính phần cứng nào (serial, MAC, UUID) được phép đại diện thay thế cho danh tính.

### 1.2 Evidence Model & 5-State Taxonomy (Phân loại Bằng chứng Phần cứng)
Mọi quan sát phần cứng (Hardware Observation) từ mọi sensor được chuẩn hóa thành 5 trạng thái phân loại:

| Trạng thái | Điều kiện nhận diện | Hành vi Policy Engine |
|---|---|---|
| `PHYSICAL` | TPM 2.0 phần cứng + IOMMU bật + Kernel Bus trực tiếp khớp danh sách thiết bị. | Đủ điều kiện xét duyệt mức bảo vệ cao nhất (`AssuranceLevel::HardwareProtected`). |
| `VIRTUAL` | Nhận diện cờ Hypervisor hợp lệ (CPUID leaf hypervisor, vTPM 2.0, synthetic bus). | Áp mức `AssuranceLevel::VirtualProtected`, không giả mạo thành máy vật lý. |
| `UNKNOWN` | Probe không thể chạy hoặc thiết bị không phản hồi (INV-007). | Báo `is_hardware_verified = false`, điểm tin cậy = 0, không bao giờ bịa dữ liệu. |
| `UNAVAILABLE` | Cổng I/O hoặc thiết bị phần cứng bị ngắt kết nối vật lý. | Ghi nhận sự vắng mặt, không đánh đồng với giả mạo. |
| `CONFLICTED` | Mâu thuẫn chéo giữa các tầng (Ví dụ: WMI báo serial X, Kernel Bus báo serial Y). | Kích hoạt cảnh báo Spoofer / Tamper $\rightarrow$ Điểm tin cậy rơi về 0, chuyển `ISOLATE`. |

### 1.3 Evidence Confidence Scoring Matrix
Mọi bằng chứng đưa vào Policy Engine mang trọng số tin cậy tương ứng với khả năng chống giả mạo của tầng thu thập:

| Nguồn bằng chứng | Trọng số tin cậy tối đa | Rủi ro bị tấn công |
|---|:---:|---|
| **TPM 2.0 Quote** | `10000 / 10000` | Cần chip physical exploit / probe glitch. |
| **Kernel Bus (Type 0 Config)** | `8500 / 10000` | Cần Ring-0 DKOM / fake driver đã ký. |
| **Storage PnP Descriptor** | `7000 / 10000` | Cần filter driver / IOCTL hooking. |
| **Mesh Quorum Corroboration** | `6000 / 10000` | Cần Sybil attack / chiếm đa số node độc lập. |
| **User-mode WMI / Registry** | `2000 / 10000` | Dễ bị DLL injection, hook API, WMI spoofer. |

---

## 2. Kernel ABI Specification (Đặc tả ABI Có Phiên bản)

Giao tiếp IOCTL giữa Ring-0 (`CyberVProbe.sys`) và Ring-3 (`cyberv-agent`) bắt buộc có Header kiểm tra phiên bản:

```c
#define CYBERV_ABI_MAGIC   0x56594243 // 'CYBV'
#define CYBERV_ABI_VERSION 0x00020001 // v2.1

typedef struct _CYBERV_ABI_HEADER {
    ULONG Magic;            // CYBERV_ABI_MAGIC
    ULONG AbiVersion;       // CYBERV_ABI_VERSION
    ULONG HeaderSize;       // sizeof(CYBERV_ABI_HEADER)
    ULONG TotalPayloadSize; // Toàn bộ kích thước struct IOCTL
    ULONG Flags;            // Cờ tính năng mở rộng
    ULONG Reserved[4];      // Dự phòng tương thích tương lai (phải bằng 0)
} CYBERV_ABI_HEADER, *PCYBERV_ABI_HEADER;
```

**Quy tắc tương thích ABI (INV-004):**
1. Nếu `Magic != CYBERV_ABI_MAGIC` hoặc `AbiVersion` không tương thích $\implies$ Trả lỗi `STATUS_REVISION_MISMATCH` ngay tại IOCTL Dispatch.
2. `TotalPayloadSize` không được nhỏ hơn `sizeof(CYBERV_ABI_HEADER)` hoặc lớn hơn trần `64KB`.
3. Kiểm tra bounds cho mọi mảng thiết bị (`DeviceCount <= 32`).

---

## 3. Protocol Contracts (Hợp đồng Giao thức Mạng & Đám mây)

### 3.1 DNS-SD & Mesh Protocol (RFC 6763)
- **Service Type chuẩn:** `_cyberv-mesh._tcp.local.` (sửa lỗi `_udp` vì transport thực tế là TCP).
- **TXT Record:**
  - `v`: Phiên bản protocol (hiện tại `1`).
  - `beacon`: Chuỗi hex của `MeshBeacon` (Node ID 32-byte, Public Key 32-byte).

### 3.2 Mesh Handshake Transcript Binding
Bắt tay 3 bước giữa 2 node trên TCP:
1. `Hello(InitiatorEphemPk, Challenge)`
2. `Ack(ResponderEphemPk, ResponderSig, ResponderChallenge)`
3. `Confirm(InitiatorSig)`

**Bất biến:** Chữ ký `ResponderSig` và `InitiatorSig` **bắt buộc ký trên Transcript Digest**:
$$\text{TranscriptDigest} = \text{SHA-512}(\text{DOMAIN} \parallel \text{Version} \parallel \text{InitNodeId} \parallel \text{RespNodeId} \parallel \text{InitEphemPk} \parallel \text{RespEphemPk} \parallel \text{Challenge} \parallel \text{PolicyEpoch})$$

### 3.3 Cloud Authentication & Key Strategy 2026
1. **Khóa Supabase:**
   - Client (`cyberv-agent`) chỉ giữ **Publishable Key** (định tuyến dự án).
   - Backend Edge Function giữ **Secret Key** (`service_role`).
2. **Device Request Signing:**
   Mọi HTTP request từ Agent bắt buộc mang các headers xác thực:
   - `X-CyberV-Device-ID`: UUID thiết bị.
   - `X-CyberV-Timestamp`: Unix timestamp (giây).
   - `X-CyberV-Nonce`: Nonce nhận từ server (nếu trong luồng verify).
   - `X-CyberV-Signature`: Chữ ký Ed25519 trên canonical payload:
     $$\text{SignaturePayload} = \text{SHA-512}(\text{"CYBERV/CLOUD/REQUEST/v1"} \parallel \text{Timestamp} \parallel \text{Nonce} \parallel \text{HTTP\_Method} \parallel \text{Path} \parallel \text{RequestBody})$$
3. **Nonce Security:**
   - Nonce TTL: **Tối đa 60 giây**.
   - Mỗi thiết bị chỉ có **tối đa 1 active nonce** tại một thời điểm.
   - Nonce được tiêu thụ nguyên tử (Atomic consume-on-verify) qua PostgreSQL function.

---

## 4. State Machine Semantics (Ngữ nghĩa Máy Trạng thái)

```text
       ┌───────────┐
       │    OFF    │
       └─────┬─────┘
             │ Bật cấu hình mesh.enabled = true
             ▼
       ┌───────────┐
       │ DISCOVERY │ ◄── mDNS duyệt peer candidates
       └─────┬─────┘
             │ Bắt tay AEAD + Admission Gate thông qua
             ▼
       ┌───────────┐
       │  SHADOW   │ ◄── Ghi nhận quorum, KHÔNG thực thi cách ly (mặc định)
       └─────┬─────┘
             │ Chuyển sang chế độ Enforce chủ động
             ▼
       ┌───────────┐   Mất quorum / Mạng chập chờn
       │  ENFORCE  │ ──────────────────────────────┐
       └─────┬─────┘                               │
             │ Phát hiện Contradiction / Tấn công  │
             ▼                                     ▼
       ┌───────────┐                         ┌───────────┐
       │ ISOLATED  │                         │ DEGRADED  │ (Liveness degraded,
       └───────────┘                         └─────┬─────┘  KHÔNG tự isolate)
             ▲                                     │
             └─────────────────────────────────────┘
                 Phát hiện thêm bằng chứng giả mạo
```

### 4.1 Quy tắc Phân định Rạch ròi
1. **Mất Quorum (Quorum Unavailable):**
   - Không đủ node độc lập hoặc rớt cáp mạng $\implies$ Trạng thái chuyển sang `DEGRADED`.
   - **Tuyệt đối KHÔNG tự động chuyển sang `ISOLATED`** (ngăn chặn DoS tự sát nội bộ).
2. **Kích hoạt Isolate (Active Contradiction Required):**
   - Chỉ chuyển sang `ISOLATED` khi có:
     - TPM counter nhảy lùi (`ContradictionDetected`).
     - Chữ ký giả mạo trên phiên làm việc.
     - Đa số Quorum độc lập (> ngưỡng tin cậy) gửi phiếu tố cáo có bằng chứng Ring-0 hợp lệ.

---

## 5. Clock Semantics (Chống Thao túng Đồng hồ)

1. Mọi tính toán thời hạn Grace Period (mặc định 300s) bắt buộc dùng **Monotonic Clock** (`Instant::now()` / `QueryPerformanceCounter`).
2. Nếu `SystemTime` (Wall clock) nhảy lùi nhiều hơn 5 giây trong khi Monotonic Clock tiếp tục tăng $\implies$ Ghi nhận sự kiện `ClockTamperDetected` và hạ mức tin cậy của bằng chứng về 0.
