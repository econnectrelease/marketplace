# Quy Chuẩn Đóng Gói & Bảo Mật Tiện Ích Mở Rộng (E-Connect Extension Standard)

Tài liệu này xác định quy chuẩn kỹ thuật bắt buộc để đóng gói, kiểm tra bảo mật và phòng chống mã độc (anti-malware) đối với các tiện ích mở rộng (extensions) trước khi đưa lên E-Connect Marketplace (`econnectrelease/marketplace`).

---

## 1. Nguyên Tắc Cốt Lõi

1. **Chỉ đẩy tệp nén (`*.zip`)**: Kho lưu trữ Marketplace chỉ chấp nhận các tệp tiện ích đã được đóng gói dưới định dạng `*.zip`. Mã nguồn giải nén trên máy phát triển được tự động loại bỏ thông qua [`.gitignore`](.gitignore).
2. **Cơ chế Selective Unpack trên CI**: Mỗi khi có commit hoặc Pull Request, GitHub Runner **chỉ unpack các extensions mới hoặc có sửa đổi** để kiểm tra, tránh tốn tài nguyên và hạn chế rủi ro mở rộng.
3. **Kiểm tra tác giả (`author`) bắt buộc**: Trường `author` phải có thực, không dùng placeholder ẩn danh, và được đối chiếu với cơ sở dữ liệu tác giả tin cậy [`.github/trusted_authors.json`](.github/trusted_authors.json).
4. **Chống mã độc và cô lập Sandbox (Anti-Malware Sandbox)**: Mọi tệp Python trong gói nén đều được phân tích AST (Abstract Syntax Tree) để phát hiện và ngăn chặn mã độc nhúng vào hệ điều hành.
5. **Không chứa rác hệ điều hành & cache**: Tuyệt đối không để lọt tệp siêu dữ liệu macOS (`.DS_Store`, `__MACOSX/`, `._*`) hoặc Windows (`Thumbs.db`), `__pycache__/`, `*.pyc`.
6. **Giới hạn dung lượng an toàn**: Dung lượng tệp `.zip` tối đa **5 MB**, dung lượng giải nén tối đa **25 MB**, tỷ lệ nén chống Zip-Bomb tối đa **100x**.

---

## 2. Quy Chuẩn Tác Giả (`author`)

Tệp `manifest.json` bắt buộc khai báo trường `author` hợp lệ:
- **Độ dài**: Từ 2 đến 100 ký tự.
- **Nghiêm cấm placeholder**: Tuyệt đối cấm các giá trị ẩn danh hoặc giả mạo như `unknown`, `null`, `undefined`, `anonymous`, `test`, `admin`, `root`, `n/a`, `placeholder`.
- **Phân loại tác giả**:
  - `VERIFIED ORGANIZATION (Official)`: Tổ chức chính thức (`E-Connect`, `E-Connect Team`).
  - `VERIFIED DEVELOPER (Partner)`: Các nhà phát triển đối tác đã qua xác minh (`Experience`, `Furuhonya`, `ryzen30xx`).
  - `COMMUNITY DEVELOPER (Unverified)`: Tác giả tự do trong cộng đồng. Được chấp nhận nhưng phải vượt qua toàn bộ các bài kiểm tra bảo mật nghiêm ngặt.

---

## 3. Quy Chuẩn Bảo Mật & Chống Mã Độc (Anti-Malware Policy)

Tiện ích E-Connect được thiết kế để giao tiếp với thiết bị IoT (qua HTTP, LAN socket, MQTT, Serial). Tiện ích **KHÔNG ĐƯỢC PHÉP** can thiệp vào hệ thống máy chủ host. Bộ quét AST sẽ tự động đánh trượt và từ chối gói nếu phát hiện:

| Danh Mục Nguy Hiểm | Hành Vi Bị Cấm Tuyệt Đối | Lý Do Cấm |
|---|---|---|
| **Thực thi lệnh hệ điều hành** | `subprocess` (`Popen`, `run`, `call`), `os.system()`, `os.popen*()`, `os.spawn*()`, `os.exec*()`, `pty.spawn()` | Ngăn chặn mã độc mở terminal shell hoặc chạy lệnh Linux tùy ý trên máy chủ. |
| **Thực thi mã động** | `eval()`, `exec()`, `compile()`, `__import__()` động | Ngăn chặn kỹ thuật làm rối mã (obfuscation) để tải payload độc hại từ xa. |
| **Đánh cắp dữ liệu máy chủ** | Chuỗi đường dẫn nhắm vào `/etc/passwd`, `/etc/shadow`, `/etc/econnect`, `/var/lib/econnect`, `/var/run/docker.sock`, `.ssh/` | Bảo vệ thông tin đăng nhập, token JWT và khóa SSH của máy chủ TV Box / Home Server. |
| **Reverse Shell** | Sử dụng `os.dup2()` nối socket với stdin/stdout | Ngăn chặn mở cổng kết nối ngầm (backdoor) ra máy chủ của hacker. |
| **Can thiệp bộ nhớ & Keylogger** | `ctypes`, `pynput`, `keyboard`, `scapy` | Tránh can thiệp kernel, rà quét bàn phím hoặc tiêm gói tin nguy hiểm. |
| **Zip-Slip & Path Traversal** | Tệp nén chứa tên đường dẫn dạng `../../` hoặc đường dẫn tuyệt đối | Ngăn chặn ghi đè tệp hệ thống ngoài thư mục giải nén. |

---

## 4. Cấu Trúc Đóng Gói Chuẩn Trong Tệp ZIP

Hệ thống E-Connect hỗ trợ 2 mô hình đóng gói sau:

### Dạng 1: Thư mục đơn cấp (Khuyến nghị cho Marketplace)
```text
my_extension.zip
└── my_extension/
    ├── manifest.json
    ├── main.py
    └── helper.py
```

### Dạng 2: Gốc trực tiếp (Flat Root)
```text
my_extension.zip
├── manifest.json
├── main.py
└── helper.py
```

> **LƯU Ý:** Gói ZIP phải chứa **duy nhất 1 tệp `manifest.json`**. Tệp chỉ định tại `package.entrypoint` bắt buộc phải tồn tại trong gói.

---

## 5. Quy Chuẩn `manifest.json` (Phiên Bản 1.0)

```json
{
  "manifest_version": "1.0",
  "extension_id": "my_extension",
  "name": "My Extension Name",
  "version": "1.0.0",
  "author": "E-Connect Team",
  "description": "Mô tả ngắn gọn chức năng của tiện ích",
  "provider": {
    "key": "my_provider",
    "display_name": "My Provider Display"
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
      "schema_id": "my_device_card",
      "name": "My Smart Device",
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

---

## 6. Hướng Dẫn Đóng Gói Bằng Dòng Lệnh (CLI)

### Trên macOS (Bắt buộc dùng cờ `-X` để loại bỏ `__MACOSX/`)
```bash
# Cách 1: Nén từ thư mục cha
zip -r -X my_extension.zip my_extension/ -x "*.DS_Store" -x "__MACOSX*" -x "*/__pycache__/*" -x "*.pyc"

# Cách 2: Nén từ bên trong thư mục
cd my_extension
zip -r -X ../my_extension.zip . -x "*.DS_Store" -x "__MACOSX*" -x "*/__pycache__/*" -x "*.pyc"
```

### Trên Linux:
```bash
zip -r my_extension.zip my_extension/ -x "*.DS_Store" -x "*/__pycache__/*" -x "*.pyc"
```

---

## 7. Tự Kiểm Tra & Audit Trước Khi Đẩy Lên Repo

Chạy trực tiếp công cụ kiểm tra bảo mật và unpack tại local:

```bash
# Chỉ unpack và audit các tiện ích vừa sửa đổi/thêm mới (giống cơ chế GitHub Actions):
python3 .github/scripts/validate_extensions.py --changed-only

# Hoặc kiểm tra một tệp zip cụ thể:
python3 .github/scripts/validate_extensions.py my_extension.zip

# Hoặc kiểm tra toàn bộ:
python3 .github/scripts/validate_extensions.py --all
```
