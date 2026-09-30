# Quy Chuẩn Cấu Trúc & Bảo Mật Tiện Ích Mở Rộng (E-Connect Extension Standard)

Tài liệu này xác định quy chuẩn kỹ thuật bắt buộc đối với cấu trúc thư mục, tệp định danh `manifest.json`, và kiểm tra an toàn bảo mật (anti-malware) cho các tiện ích mở rộng (extensions) trên E-Connect Marketplace (`econnectrelease/marketplace`).

---

## 1. Nguyên Tắc Cốt Lõi

1. **Cấu trúc dạng thư mục giải nén (Folder-Based Architecture)**:
   - Toàn bộ tiện ích mở rộng phải được lưu trữ trực tiếp dưới dạng thư mục (uncompressed folder) tại thư mục gốc của repository.
   - **Tuyệt đối không lưu trữ tệp nén (`*.zip`, `*.tar`, `*.rar`, ...)**. Hệ thống Marketplace và máy chủ E-Connect đọc trực tiếp tệp `manifest.json` từ cấu trúc thư mục để xác định danh mục và thông tin tiện ích.
2. **Tự động nhận diện qua `manifest.json`**:
   - Mỗi thư mục tiện ích bắt buộc phải chứa một tệp `manifest.json` hợp lệ ở cấp gốc của thư mục đó.
   - Hệ thống quét qua các thư mục trong repository, đọc `manifest.json` để trích xuất `extension_id`, `version`, `author`, `provider`, `device_schemas` và `package.entrypoint`.
3. **Cơ chế Selective Audit trên CI**:
   - Khi có commit hoặc Pull Request, GitHub Actions tự động phát hiện các thư mục tiện ích có tệp được thêm mới hoặc sửa đổi và chỉ kích hoạt kiểm tra chuyên sâu trên các tiện ích đó.
4. **Xác thực tác giả (`author`)**:
   - Trường `author` trong `manifest.json` là bắt buộc, không được sử dụng các giá trị ẩn danh / placeholder, và được đối chiếu với danh bạ tác giả tin cậy tại [`.github/trusted_authors.json`](.github/trusted_authors.json).
5. **Chống mã độc và cô lập Sandbox (Anti-Malware Policy)**:
   - Toàn bộ mã nguồn Python (`*.py`) trong thư mục tiện ích đều được phân tích AST (Abstract Syntax Tree) và quét tĩnh (Bandit) để ngăn chặn mã độc nhúng vào hệ điều hành host.
6. **Vệ sinh thư mục & không chứa file rác**:
   - Tuyệt đối cấm commit các tệp rác hệ điều hành (`.DS_Store`, `__MACOSX/`, `Thumbs.db`) hoặc cache mã nguồn (`__pycache__/`, `*.pyc`).
7. **Giới hạn dung lượng an toàn**:
   - Dung lượng toàn bộ thư mục tiện ích tối đa **25 MB**.

---

## 2. Cấu Trúc Thư Mục Chuẩn

Mỗi tiện ích mở rộng là một thư mục độc lập:

```text
econnect_extensions/
├── .github/
│   ├── workflows/validate-extensions.yml
│   ├── scripts/validate_extensions.py
│   └── trusted_authors.json
│
├── Yeelight_control/                 <-- Thư mục Extension 1
│   ├── manifest.json                 <-- Bắt buộc: Định danh & metadata
│   ├── main.py                       <-- File entrypoint chỉ định trong manifest
│   └── yeelight_control.py           <-- Code logic / thư viện nội bộ
│
├── zigbee_manager/                   <-- Thư mục Extension 2
│   ├── manifest.json
│   └── main.py
│
├── devkit_extension/                 <-- Thư mục Extension 3
│   ├── manifest.json
│   └── main.py
│
├── README.md
└── PACKAGING_STANDARD.md
```

> **LƯU Ý:** 
> - Tệp `manifest.json` phải nằm ngay tại cấp gốc của thư mục tiện ích (ví dụ: `Yeelight_control/manifest.json`).
> - File entrypoint chỉ định tại `package.entrypoint` (thường là `main.py`) phải tồn tại trong thư mục.

---

## 3. Quy Chuẩn `manifest.json` (Phiên Bản 1.0)

Hệ thống E-Connect đọc tệp `manifest.json` để xác định tiện ích:

```json
{
  "manifest_version": "1.0",
  "extension_id": "yeelight_control",
  "name": "Yeelight LAN Lights",
  "version": "1.4.2",
  "author": "Experience",
  "contributor": "ryzen30xx",
  "icon": "lightbulb",
  "categories": [
    "light",
    "3rd party"
  ],
  "description": "An extension for controlling Yeelight devices on local LAN.",
  "provider": {
    "key": "yeelight",
    "display_name": "Yeelight"
  },
  "package": {
    "runtime": "python",
    "entrypoint": "main.py",
    "hooks": {
      "validate_command": "validate_command",
      "execute_command": "execute_command",
      "probe_state": "probe_state",
      "discover_devices": "discover_devices"
    }
  },
  "device_schemas": [
    {
      "schema_id": "yeelight_white_light",
      "device_type": "light",
      "name": "Yeelight White Light",
      "default_name": "Yeelight White Light",
      "description": "Power and brightness control for single-tone Yeelight lamps.",
      "display": {
        "card_type": "light",
        "capabilities": ["power", "brightness"]
      },
      "config_schema": {
        "fields": [
          {
            "key": "ip_address",
            "label": "IP Address",
            "type": "string",
            "required": true
          }
        ]
      }
    }
  ]
}
```

### Các trường bắt buộc:
* `manifest_version`: Chuỗi `"1.0"`.
* `extension_id`: Slug định danh duy nhất (chữ thường, số, dấu gạch dưới hoặc gạch ngang, 2-120 ký tự).
* `name`: Tên hiển thị của tiện ích.
* `version`: Phiên bản theo Semantic Versioning (ví dụ: `1.0.0`).
* `author`: Tên tác giả hoặc tổ chức phát triển (bắt buộc, đối chiếu danh bạ tin cậy).
* `description`: Mô tả chi tiết chức năng tiện ích.
* `provider.key`: Khóa định danh của nhà cung cấp thiết bị (slug chữ thường).
* `provider.display_name`: Tên hiển thị của nhà cung cấp.
* `package.runtime`: Môi trường thực thi (bắt buộc là `"python"`).
* `package.entrypoint`: Tên tệp script chính (ví dụ: `main.py`).
* `package.hooks`: Định nghĩa các hàm hook bắt buộc (`validate_command`, `execute_command`, `probe_state`).
* `device_schemas`: Danh sách ít nhất 1 schema thiết bị được tiện ích hỗ trợ.

### Các trường tùy chọn / mở rộng:
* `contributor`: GitHub username của người đóng góp (ví dụ: `ryzen30xx`).
* `icon`: Mã định danh icon Material Symbols (ví dụ: `lightbulb`, `hub`, `developer_board`, `sensors`).
* `categories`: Danh sách các phân loại tiện ích (ví dụ: `["light", "3rd party"]`, `["hub"]`, `["system"]`, `["switch"]`, `["sensor"]`).
* `package.hooks.discover_devices`: Hàm quét tự động phát hiện thiết bị trên mạng LAN.

---

## 4. Quy Chuẩn Tác Giả (`author`)

Tệp `manifest.json` bắt buộc khai báo trường `author` hợp lệ:
- **Độ dài**: Từ 2 đến 100 ký tự.
- **Nghiêm cấm placeholder**: Cấm các giá trị ẩn danh hoặc giả mạo (`unknown`, `null`, `undefined`, `anonymous`, `test`, `admin`, `root`, `n/a`, `placeholder`).
- **Phân loại tác giả**:
  - `VERIFIED ORGANIZATION (Official)`: Tổ chức chính thức (`E-Connect`, `E-Connect Team`).
  - `VERIFIED DEVELOPER (Partner)`: Các nhà phát triển đối tác đã qua xác minh (`Experience`, `Furuhonya`, `ryzen30xx`).
  - `COMMUNITY DEVELOPER (Unverified)`: Tác giả tự do trong cộng đồng (phải vượt qua toàn bộ các bài kiểm tra bảo mật nghiêm ngặt).

---

## 5. Quy Chuẩn Bảo Mật & Chống Mã Độc (Anti-Malware Policy)

Tiện ích E-Connect được thiết kế để điều khiển và giám sát thiết bị IoT qua giao thức mạng (LAN socket, HTTP, MQTT, CoAP, BLE/Zigbee qua serial/coordinator). Tiện ích **KHÔNG ĐƯỢC PHÉP** can thiệp vào máy chủ host.

Bộ quét AST và Bandit sẽ tự động đánh trượt nếu phát hiện:

| Danh Mục Nguy Hiểm | Hành Vi Bị Cấm Tuyệt Đối | Lý Do Cấm |
|---|---|---|
| **Thực thi lệnh hệ điều hành** | `subprocess` (`Popen`, `run`, `call`), `os.system()`, `os.popen*()`, `os.spawn*()`, `os.exec*()`, `pty.spawn()` | Ngăn chặn mã độc mở terminal shell hoặc chạy lệnh Linux tùy ý trên máy chủ. |
| **Thực thi mã động** | `eval()`, `exec()`, `compile()`, `__import__()` động | Ngăn chặn kỹ thuật làm rối mã (obfuscation) để nạp payload độc hại. |
| **Đánh cắp dữ liệu máy chủ** | Chuỗi đường dẫn nhắm vào `/etc/passwd`, `/etc/shadow`, `/etc/econnect`, `/var/lib/econnect`, `/var/run/docker.sock`, `.ssh/` | Bảo vệ tài khoản đăng nhập, token JWT và khóa SSH của máy chủ E-Connect. |
| **Reverse Shell** | Sử dụng `os.dup2()` nối socket với stdin/stdout | Ngăn chặn mở cổng kết nối ngầm (backdoor) ra ngoài. |
| **Can thiệp bộ nhớ & Keylogger** | `ctypes`, `pynput`, `keyboard`, `scapy` | Tránh can thiệp kernel, rà quét bàn phím hoặc tiêm gói tin nguy hiểm. |
| **Tệp nén trong repo** | Commit tệp `.zip`, `.tar.gz`, ... | Toàn bộ tiện ích phải ở dạng thư mục giải nén để hệ thống đọc trực tiếp `manifest.json`. |

---

## 6. Hướng Dẫn Tự Kiểm Tra Trước Khi Đẩy Lên Repo

Chạy trực tiếp công cụ kiểm tra tại máy phát triển:

```bash
# Chỉ kiểm tra các thư mục tiện ích vừa chỉnh sửa hoặc thêm mới:
python3 .github/scripts/validate_extensions.py --changed-only

# Hoặc kiểm tra một thư mục tiện ích cụ thể:
python3 .github/scripts/validate_extensions.py Yeelight_control

# Hoặc quét toàn bộ repository:
python3 .github/scripts/validate_extensions.py --all
```
