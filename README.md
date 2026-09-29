# E-Connect Extensions Marketplace

Kho lưu trữ phân phối chính thức các gói tiện ích mở rộng (Extensions) cho hệ sinh thái **E-Connect Smart Home**.

---

## 📦 Danh Sách Tiện Ích Hiện Tại

| Tên Tệp | Extension ID | Phiên Bản | Mô Tả |
|---|---|---|---|
| `Yeelight_control.zip` | `yeelight_control` | `1.4.2` | Điều khiển hệ thống đèn thông minh Yeelight (Wi-Fi LAN) |
| `devkit_extension.zip` | `devkit_debug` | `1.0.0` | Tiện ích thử nghiệm và debug phần cứng DevKit |
| `zigbee_manager.zip` | `zigbee-manager` | `1.0.0` | Quản lý mạng và thiết bị Zigbee qua coordinator |

---

## 🛠 Quy Chuẩn Đóng Gói (Packaging Standards)

Kho lưu trữ này được cấu hình CI tự động và `.gitignore` nghiêm ngặt:
- **Chỉ chấp nhận tệp nén `*.zip`** hợp lệ.
- Xem chi tiết quy chuẩn đóng gói và hướng dẫn lệnh nén tại [PACKAGING_STANDARD.md](PACKAGING_STANDARD.md).

### Kiểm tra gói tiện ích tại local:
```bash
python3 .github/scripts/validate_extensions.py .
```

---

## 🚀 Kiểm Tra Tự Động (CI/CD)

Mọi thay đổi trên nhánh `main` và `dev` đều được kiểm duyệt tự động thông qua GitHub Action:
- [.github/workflows/validate-extensions.yml](.github/workflows/validate-extensions.yml)
- Kiểm tra toàn vẹn định dạng zip, cấu trúc thư mục, UTF-8, JSON schema của `manifest.json`, tính hợp lệ của mã nguồn Python và tuyệt đối không cho phép lọt các file rác như `.DS_Store` hay `__MACOSX/`.
