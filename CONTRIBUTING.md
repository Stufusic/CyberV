# CyberV — Hướng Dẫn Đóng Góp (Contributing)

> **EN: How to contribute — build/test gates, code conventions, review
> checklist for security invariants.**
>
> M-D3 theo `Docs/DOCUMENTATION_PLAN.md`. Luật đầy đủ: `AGENTS.md`.

---

## 1. Cổng merge (bắt buộc xanh trước khi PR)

```powershell
cargo test --workspace --release                 # ~750 test, 50 binary
cargo clippy --workspace --all-targets -- -D warnings
python -m pytest -q                              # UI: 43 test
```

Driver C: mọi thay đổi trong `driver/` phải ghi rõ trong PR rằng job CI
`driver-build` phải xanh (không build được local nếu thiếu WDK).

## 2. Quy ước code

- **Ngôn ngữ**: comment/log/message lỗi tiếng Việt; identifier tiếng Anh.
  Tài liệu mới: tiếng Việt + 1 dòng `> EN:` tóm tắt.
- **Số học trên dữ liệu ngoài**: `saturating_add/mul` — cấm `+`/`*` trần.
- **Input ngoài (IPC/HTTP/driver/file)**: bounds trước, không `unwrap()`/
  `expect()` trên dữ liệu không tin cậy.
- **Chữ ký payload**: length-prefixed + domain separator riêng — cấm nối chuỗi.
- **So sánh bí mật**: constant-time; **fail-closed**: `unwrap_or_default`
  phải là giá trị xấu nhất.
- **Log**: `tracing`; không log secret/serial/nonce.
- **Mỗi change an ninh kèm test** chứng minh nhánh tấn công bị từ chối.

## 3. Checklist review an ninh

Reviewer PR phải xác nhận từng mục:

- [ ] Có đường nào **fail-open** mới không? (mọi nhánh lỗi phải từ chối)
- [ ] Có claim "verified/hardware-backed" cho thứ đang mô phỏng không? (cấm — INV-007)
- [ ] Mock có lọt vào production path không? (chỉ `#[cfg(test)]`)
- [ ] `ioctl.h` ⟷ `kernel/client.rs` đổi cùng PR? (test ABI sync chặn)
- [ ] Dependency mới có rationale Phụ lục B + deny/machete chưa?
- [ ] Secret có lọt log/Debug/fixture không?
- [ ] Test nào chứng minh nhánh bị tấn công bị từ chối?

## 4. Quy trình đề xuất tính năng

1. Đọc `Docs/CONTEXT_MAP.md` → xác định module + trạng thái thật/mô phỏng.
2. Đọc `Docs/INVARIANTS.md` → INV nào chi phối.
3. PR mô tả: cái gì đổi, INV nào ảnh hưởng, test nào chứng minh.
4. Tính năng tự động hóa (auto-pilot): PHẢI qua freeze gate — xem
   `mesh/gate.rs` + `Docs/TRANSPORT_ISOLATION_PLAN.md` §10.

## 5. Báo cáo lỗ hổng

Riêng tư qua `SECURITY.md` — KHÔNG mở public issue cho lỗ hổng.
