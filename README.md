# E-Connect Extensions Marketplace

Kho lưu trữ phân phối chính thức các tiện ích mở rộng (Extensions) cho hệ sinh thái **E-Connect Smart Home**.

---

## 📦 Danh Sách Tiện Ích Hiện Tại

| Thư Mục Tiện Ích | Extension ID | Phiên Bản | Tác Giả | Mô Tả |
|---|---|---|---|---|
| [`Yeelight_control/`](Yeelight_control/) | `yeelight_control` | `1.4.2` | Experience | Điều khiển hệ thống đèn thông minh Yeelight (Wi-Fi LAN) |
| [`devkit_extension/`](devkit_extension/) | `devkit_debug` | `1.0.0` | Experience | Tiện ích thử nghiệm và debug phần cứng DevKit |
| [`zigbee_manager/`](zigbee_manager/) | `zigbee-manager` | `1.0.0` | E-Connect Team | Quản lý mạng và thiết bị Zigbee qua coordinator |

---

## 🛠 Cấu Trúc Tiện Ích (Folder-Based Architecture)

Kho lưu trữ sử dụng cấu trúc thư mục mở rộng trực tiếp (uncompressed folders):
- Mỗi tiện ích được tổ chức trong một thư mục riêng biệt tại thư mục gốc.
- Tệp `manifest.json` nằm tại cấp gốc của thư mục tiện ích để hệ sinh thái E-Connect quét và nhận diện tự động.
- **Không sử dụng tệp nén (`*.zip`)**.
- Xem chi tiết quy chuẩn kỹ thuật tại [PACKAGING_STANDARD.md](PACKAGING_STANDARD.md).

### Kiểm tra tiện ích tại local:
```bash
# Kiểm tra toàn bộ tiện ích trong repository
python3 .github/scripts/validate_extensions.py --all

# Hoặc chỉ kiểm tra các tiện ích có thay đổi
python3 .github/scripts/validate_extensions.py --changed-only
```

---

## 🚀 Kiểm Duyệt Tự Động (CI/CD)

Mọi thay đổi trên nhánh `main` và `dev` đều được kiểm duyệt tự động thông qua GitHub Action:
- [.github/workflows/validate-extensions.yml](.github/workflows/validate-extensions.yml)
- Kiểm tra tính hợp lệ của `manifest.json`, định danh tác giả từ danh bạ tin cậy, phân tích cú pháp AST chống mã độc/subprocess/backdoor, quét lỗ hổng Bandit, và đảm bảo không có file rác hệ điều hành.
