# AGENTS.md — Hướng dẫn cho AI Coding Assistant

> **EN: Ground rules for AI assistants working on CyberV. Build/test commands,
> code conventions, and hard prohibitions that protect security invariants.
> Read this BEFORE proposing changes. Related: Docs/CONTEXT_MAP.md (module map),
> Docs/INVARIANTS.md (security invariants), Docs/DOCUMENTATION_PLAN.md.**

---

## 1. Lệnh chính xác (chạy đúng lệnh này, không chế lại)

```bash
# Build + toàn bộ test (BẮT BUỘC xanh trước khi kết thúc bất kỳ task nào)
cargo test --workspace --release

# Lint — mọi warning là lỗi
cargo clippy --workspace --all-targets -- -D warnings

# Test UI Python (chạy TỪ REPO ROOT — pyproject.toml đã cấu hình)
python -m pytest -q

# Build driver (cần WDK — máy dev/CI; KHÔNG có ở môi trường thường)
msbuild driver\CyberVProbe\CyberVProbe.sln /p:Configuration=Release /p:Platform=x64 /m

# Test một target cụ thể (nhanh khi lặp)
cargo test --release --test phase24h
cargo test --release --lib update::
```

Lưu ý môi trường:
- Toolchain pin tại `rust-toolchain.toml` (1.98.1) — không bump trong PR không liên quan.
- `.cargo/config.toml` bật Control Flow Guard cho MSVC — đừng xóa.
- Driver C **không compile được ở máy không có WDK**: mọi change trong
  `driver/` phải ghi rõ trong PR rằng job CI `driver-build` phải xanh.

## 2. Quy ước code

- **Ngôn ngữ**: comment + log + message lỗi tiếng Việt; identifier/type tên tiếng Anh. Tài liệu mới theo phương án song song nhẹ (viết tiếng Việt + 1 dòng `> EN:` tóm tắt — xem `Docs/DOCUMENTATION_PLAN.md` §7).
- **Số học trên counter/dữ liệu ngoài**: luôn `saturating_add/mul` — không `+`/`*` trần.
- **Input từ ngoài (IPC, HTTP, driver, file)**: validate bounds trước, không `unwrap()`/`expect()` trên dữ liệu không tin cậy; hex decode qua các helper an toàn byte (`decode_hex` ở `isolation/admission.rs`).
- **Signature payload**: luôn length-prefixed + domain separator (`DOMAIN_*`), không nối chuỗi `format!("{}:{}")`.
- **So sánh bí mật/tag**: constant-time (`constant_time_eq` pattern); so sánh hash công khai thì `==` được.
- **Trạng thái bảo vệ**: fail-closed. `unwrap_or_default()` phải là giá trị XẤU NHẤT, không phải tốt nhất.
- **Log**: `tracing` (info/warn/error), không `println!`/`eprintln!` trong production path; không log bí mật/serial/nonce.
- **Mỗi change an ninh đi kèm test**: test chứng minh nhánh bị tấn công bị từ chối, không chỉ happy path.

## 3. ⛔ DANH SÁCH CẤM (vi phạm = revert, không thương lượng)

1. **Đưa mock vào production path**: `MockDeviceTransport`, `MockHardwareCollector`,
   `MockTpmProvider`, fixture chỉ được dùng trong `#[cfg(test)]`/tests. Đường
   `run`/service không được tham chiếu mock (xem P1-2 — đang dọn nốt).
2. **Hạ fail-closed**: thêm `unwrap_or(true)`, default `PROTECT/verified/10000`,
   bắt exception rồi trả "OK", tăng TTL/threshold không có rationale + test.
3. **Sửa `driver/CyberVProbe/ioctl.h` mà không sửa mirror Rust**
   (`agent/src/kernel/client.rs`) cùng PR — và ngược lại. Test
   `kernel_abi_sync_tests.rs` sẽ chặn.
4. **Ghi "verified/hardware-backed" cho thứ đang mô phỏng**: probe stub phải
   báo `is_verified: false`; TPM class phải báo `SoftwareFallback`/software flag
   (INV-007). Đọc `Docs/THREAT_MODEL.md` trước khi claim bất kỳ điều gì.
5. **Giữ private key/seed trong log, file, Debug output, test fixture thật** —
   test dùng key cứng hợp lệ (`[0x42;32]` kiểu demo) là được; khóa thật sinh qua
   `cyberv-keygen` và KHÔNG BAO GIỜ commit share/public-file trừ khi là key
   public cố ý pin.
6. **Thêm dependency mới mà không qua cargo-machete/cargo-deny check** + ghi
   rationale trong PR (từng có `keyring` chết bị loại).
7. **`panic = "abort"` hoặc xóa catch_unwind**: INV-006 (poison recovery) phụ
   thuộc unwinding — quyết định đã ghi trong root `Cargo.toml`.
8. **Xóa/đổi tên test được liệt kê trong `Docs/INVARIANTS.md`** mà không có
   rationale + chấp thuận CODEOWNERS.
9. **Commit secret**: `.gitignore` đã chặn `.env/*.key/*.pem` — đừng "giúp"
   inline secret vào code/config. Update authority share là giấy in/offline.

## 4. Khi chạm một module

1. Tra `Docs/CONTEXT_MAP.md` → xác định module + test entry + trạng thái thật/mô phỏng.
2. Tra `Docs/INVARIANTS.md` → INV nào chi phối file đó, mục "Vi phạm nếu".
3. Change xong → chạy test đúng entry đó + toàn bộ trước khi kết thúc.
4. PR mô tả: cái gì đổi, INV nào bị ảnh hưởng, test nào chứng minh.

## 5. Trạng thái dự án đang mở (đừng "sửa hộ" mà không hiểu kế hoạch)

Các mục sau là **đã có kế hoạch**, nằm trong `Docs/PHASE1_2_IMPLEMENTATION_PLAN.md`
và `Docs/PIPELINE_SECURITY_PLAN.md` — nếu muốn làm, làm theo scope đã ghi:
- P1-1: AEAD X25519/ChaCha20 + DACL thật cho pipe (hiện HMAC-only là chủ ý)
- P1-2: wire AgentDaemon thật vào service (hiện service chỉ keep-alive IPC)
- P1-3: probe Win32 thật thay stub (hiện stub báo fail-closed là CHUẨN)
- P2-1/2: TBS/PCP thật, kernel PCI/storage thật
- H5: policy metadata None → decay (cần đồng bộ ~6 test phase20)
