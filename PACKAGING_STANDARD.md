# Quy Chuẩn Đóng Gói Tiện Ích Mở Rộng (E-Connect Extension Packaging Standard)

Tài liệu này xác định quy chuẩn kỹ thuật bắt buộc để đóng gói các tiện ích mở rộng (extensions) trước khi đưa lên E-Connect Marketplace (`econnectrelease/marketplace`).

---

## 1. Nguyên Tắc Cốt Lõi

1. **Chỉ đẩy tệp nén (`*.zip`)**: Kho lưu trữ Marketplace chỉ chấp nhận các tệp tiện ích đã được đóng gói dưới định dạng `*.zip`. Mã nguồn giải nén trên máy phát triển được tự động loại bỏ thông qua [`.gitignore`](.gitignore).
2. **Không chứa rác hệ điều hành**: Tuyệt đối không để lọt tệp siêu dữ liệu macOS (`.DS_Store`, `__MACOSX/`, `._*`) hoặc Windows (`Thumbs.db`).
3. **Không chứa cache/build artifacts**: Không chứa `__pycache__/`, `*.pyc`, `.pytest_cache/`, `.vscode/`, `.idea/`.
4. **Giới hạn dung lượng**: Dung lượng tệp `.zip` không được vượt quá **5 MB** (`MAX_EXTENSION_ARCHIVE_BYTES`).
5. **CI Tự động kiểm duyệt**: Mọi Pull Request hoặc commit lên Marketplace bắt buộc phải vượt qua GitHub Action `validate-extensions.yml`.

---

## 2. Cấu Trúc Đóng Gói Chuẩn Trong Tệp ZIP

Hệ thống E-Connect hỗ trợ 2 mô hình đóng gói sau:

### Dạng 1: Thư mục đơn cấp (Khuyến nghị cho Marketplace)
Tất cả mã nguồn nằm bên trong một thư mục mang tên tiện ích:
```text
my_extension.zip
└── my_extension/
    ├── manifest.json
    ├── main.py
    └── helper.py (nếu có)
```

### Dạng 2: Gốc trực tiếp (Flat Root)
Các tệp nằm trực tiếp tại thư mục gốc của tệp ZIP:
```text
my_extension.zip
├── manifest.json
├── main.py
└── helper.py (nếu có)
```

> **LƯU Ý:** Gói ZIP phải chứa **duy nhất 1 tệp `manifest.json`**. Không được lồng sâu quá 1 cấp thư mục.

---

## 3. Quy Chuẩn `manifest.json` (Phiên Bản 1.0)

Tệp `manifest.json` bắt buộc mã hóa UTF-8 và tuân thủ schema:

```json
{
  "manifest_version": "1.0",
  "extension_id": "my_extension",
  "name": "My Extension Name",
  "version": "1.0.0",
  "author": "Author Name",
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

### Các trường bắt buộc:
| Trường | Kiểu dữ liệu | Ràng buộc |
|---|---|---|
| `manifest_version` | String | Bắt buộc `"1.0"` |
| `extension_id` | String | Lowercase slug `^[a-z0-9][a-z0-9_-]{1,119}$` |
| `name` | String | Không được rỗng |
| `version` | String | Chuẩn Semantic Versioning (ví dụ: `1.0.0`) |
| `description` | String | Không được rỗng |
| `provider.key` | String | Lowercase slug |
| `provider.display_name` | String | Tên nhà cung cấp hiển thị trên WebApp |
| `package.runtime` | String | Bắt buộc `"python"` |
| `package.entrypoint` | String | Tên tệp script khởi chạy (phải tồn tại thực tế trong zip) |
| `package.hooks` | Object | Tên hàm Python: `validate_command`, `execute_command`, `probe_state` |
| `device_schemas` | Array | Tối thiểu 1 schema thiết bị hợp lệ |

---

## 4. Hướng Dẫn Đóng Gói Bằng Dòng Lệnh (CLI)

### Trên macOS (Cực kỳ quan trọng: Dùng cờ `-X`)
Khi nén trên macOS, tiện ích `zip` mặc định sẽ đính kèm siêu dữ liệu HFS+ (tạo ra thư mục rác `__MACOSX/` và các file `._*`). Bắt buộc sử dụng cờ `-X` để loại bỏ:

```bash
# Cách 1: Nén thư mục my_extension thành my_extension.zip
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

## 5. Tự Kiểm Tra Trước Khi Commit (Local Validation)

Chạy trực tiếp công cụ kiểm tra tự động trước khi commit:

```bash
python3 .github/scripts/validate_extensions.py .
```

Nếu kết quả hiển thị:
```text
🎉 All X extension package(s) PASSED validation! Ready for Marketplace.
```
Bạn đã hoàn tất quy chuẩn và an toàn đẩy lên kho lưu trữ.
