# E-Connect Extensions Marketplace

Kho lưu trữ phân phối chính thức và tài liệu hướng dẫn phát triển các tiện ích mở rộng (**Extensions**) cho hệ sinh thái nhà thông minh **E-Connect Smart Home**.

E-Connect áp dụng mô hình **Folder-Based Architecture** (thư mục không nén) kết hợp với cơ chế **Auto-Discovery** trực tiếp qua tệp định danh `manifest.json`.

---

## 🏗️ Cấu Trúc Phân Cấp Thư Mục (File Hierarchy Standard)

Mỗi tiện ích mở rộng trong E-Connect là **một thư mục độc lập** nằm ngay tại cấp gốc của repository `econnect_extensions/`. Hệ thống E-Connect Marketplace quét và nhận diện tự động (Auto-Discovery) thông qua sự hiện diện của tệp `manifest.json`.

### 1. Cây thư mục tổng thể của Repository
```text
econnect_extensions/
├── .github/
│   ├── workflows/
│   │   └── validate-extensions.yml      <-- Pipeline CI/CD tự động kiểm duyệt
│   ├── scripts/
│   │   └── validate_extensions.py       <-- Script CLI thẩm định quy chuẩn & bảo mật
│   └── trusted_authors.json             <-- Danh bạ tác giả tin cậy (Official / Partner)
│
├── <extension_name_1>/                  <-- Thư mục Extension 1 (ví dụ: smart_lighting)
│   ├── manifest.json                    <-- [Bắt buộc] Metadata, schemas, hooks
│   ├── main.py                          <-- [Bắt buộc] File entrypoint thực thi
│   └── driver.py                        <-- Logic nội bộ / giao tiếp thiết bị
│
├── <extension_name_2>/                  <-- Thư mục Extension 2 (ví dụ: zigbee_gateway)
│   ├── manifest.json
│   └── main.py
│
├── PACKAGING_STANDARD.md                <-- Đặc tả kỹ thuật chi tiết
└── README.md                            <-- Tài liệu quy chuẩn phát triển này
```

### 2. Cấu trúc nội bộ của một Extension chuẩn
```text
<ten_extension_folder>/
├── manifest.json        <-- [BẮT BUỘC] Tệp định danh metadata, schema và hooks (nằm tại root của extension)
├── main.py              <-- [BẮT BUỘC] File entrypoint chỉ định trong manifest.json
├── driver.py            <-- [TÙY CHỌN] Các module Python hỗ trợ giao tiếp thiết bị
└── assets/              <-- [TÙY CHỌN] Tài nguyên bổ trợ (nếu có)
```

### 3. Quy chuẩn vệ sinh tệp tin (File Hygiene)
> [!IMPORTANT]
> Toàn bộ extension phải được lưu trữ dưới dạng **thư mục mở (uncompressed folder)**.
> - **Nghiêm cấm** commit các tệp lưu trữ nén: `*.zip`, `*.tar`, `*.tar.gz`, `*.rar`, `*.7z`.
> - **Nghiêm cấm** các tệp rác hệ điều hành: `.DS_Store`, `Thumbs.db`, `__MACOSX/`, `._*`.
> - **Nghiêm cấm** thư mục cache mã nguồn: `__pycache__/`, `*.pyc`, `*.pyo`.
> - **Nghiêm cấm** tệp cấu hình IDE hoặc Git: `.git/`, `.vscode/`, `.idea/`.
> - **Giới hạn dung lượng**: Toàn bộ thư mục tiện ích không được vượt quá **25 MB**.

---

## ⚙️ Kiến Trúc Tiện Ích & Các Hooks Bắt Buộc (Extension Architecture)

Môi trường thực thi của Extension là **Python 3.11+**. Khi máy chủ E-Connect vận hành, hệ thống sẽ nạp module được chỉ định tại `package.entrypoint` (mặc định là `main.py`) và điều phối tương tác thông qua các hàm **Hook**.

### 1. Chi tiết 3 Hooks bắt buộc

```python
# main.py
from __future__ import annotations
from typing import Any

def validate_command(device: dict[str, Any], command: dict[str, Any]) -> None:
    """
    [BẮT BUỘC] Xác thực cú pháp và giá trị của lệnh trước khi thực thi.
    
    :param device: Thông tin thiết bị gồm config người dùng nhập, schema_snapshot.
    :param command: Lệnh gồm tên command và tham số args.
    :raises ValueError: Ném ngoại lệ nếu tham số hoặc giá trị không hợp lệ.
    """
    cmd = command.get("command")
    args = command.get("args", {})
    if cmd == "set_brightness":
        brightness = args.get("brightness")
        if brightness is None or not (0 <= brightness <= 100):
            raise ValueError("Độ sáng 'brightness' phải nằm trong khoảng 0 đến 100.")


def execute_command(device: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    """
    [BẮT BUỘC] Gửi tín hiệu điều khiển tới thiết bị qua LAN socket, HTTP REST, Zigbee/MQTT hoặc Serial.
    
    :param device: Context thiết bị và cấu hình kết nối (ví dụ: device["config"]["ip_address"]).
    :param command: Lệnh và tham số thực thi.
    :return: Dictionary chứa trạng thái và thông báo kết quả.
    """
    cmd = command.get("command")
    # Thực hiện giao tiếp với thiết bị phần cứng...
    return {
        "status": "success",
        "message": f"Đã thực thi thành công lệnh {cmd}."
    }


def probe_state(device: dict[str, Any]) -> dict[str, Any]:
    """
    [BẮT BUỘC] Thăm dò trạng thái phần cứng thời gian thực (online/offline, trạng thái bật/tắt, giá trị cảm biến).
    
    :param device: Context thiết bị, cấu hình kết nối và trạng thái gần nhất (last_state).
    :return: Dictionary chuẩn định dạng: {"connected": bool, "state": {...}}
    """
    # Gửi gói tin ping / query trạng thái thiết bị...
    return {
        "connected": True,
        "state": {
            "power": "on",
            "brightness": 85,
            "color_temperature": 4000
        }
    }
```

### 2. Hook tùy chọn: Tự động tìm kiếm thiết bị (`discover_devices`)

```python
def discover_devices(timeout: float = 3.0) -> list[dict[str, Any]]:
    """
    [TÙY CHỌN] Tự động quét và phát hiện các thiết bị tương thích trên mạng LAN (SSDP, mDNS, UDP Broadcast).
    
    :return: Danh sách thiết bị tìm thấy kèm cấu hình ban đầu để người dùng ghép nối nhanh.
    """
    return [
        {
            "schema_id": "yeelight_white_light",
            "name": "Yeelight Lamp (192.168.1.105)",
            "config": {"ip_address": "192.168.1.105"}
        }
    ]
```

### 3. Cấu trúc tham số Context

* **`device`**:
  * `device["config"]`: Dữ liệu người dùng cấu hình theo `config_schema` (ví dụ: `ip_address`, `port`, `ieee_address`, `token`).
  * `device["schema_snapshot"]`: Bản sao schema của thiết bị (`display.card_type`, `display.capabilities`, v.v.).
  * `device["last_state"]`: Trạng thái thiết bị được ghi nhận gần nhất.
* **`command`**:
  * `command["command"]`: Tên hành động (`"turn_on"`, `"turn_off"`, `"set_brightness"`, `"set_rgb"`, `"set_color_temperature"`, ...).
  * `command["args"]`: Đối số truyền vào (ví dụ: `{"brightness": 75}`).

---

## 📄 Hướng Dẫn Viết `manifest.json` Chuẩn (Specification v1.0)

Tệp `manifest.json` là trái tim của mỗi tiện ích, cung cấp định danh, thông tin nhà sản xuất, cấu hình hook thực thi và các schema thiết bị hiển thị lên giao diện Web UI / Mobile App.

### 1. Tệp `manifest.json` mẫu hoàn chỉnh

```json
{
  "manifest_version": "1.0",
  "extension_id": "smart_lighting_pro",
  "name": "Smart Lighting Pro",
  "version": "1.0.0",
  "author": "Experience",
  "contributor": "ryzen30xx",
  "icon": "lightbulb",
  "categories": [
    "light",
    "3rd party"
  ],
  "description": "Tiện ích điều khiển hệ thống chiếu sáng thông minh thế hệ mới qua mạng nội bộ LAN.",
  "provider": {
    "key": "smart_lighting",
    "display_name": "Smart Lighting"
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
      "schema_id": "rgb_ambient_light",
      "device_type": "light",
      "name": "Đèn RGB Ambient",
      "default_name": "Đèn RGB Thông Minh",
      "description": "Điều khiển bật/tắt, độ sáng, dải màu RGB và nhiệt độ màu.",
      "display": {
        "card_type": "light",
        "capabilities": [
          "power",
          "brightness",
          "rgb",
          "color_temperature"
        ],
        "temperature_range": {
          "min": 1700,
          "max": 6500
        }
      },
      "config_schema": {
        "fields": [
          {
            "key": "ip_address",
            "label": "Địa chỉ IP",
            "type": "string",
            "required": true
          },
          {
            "key": "port",
            "label": "Cổng kết nối (Port)",
            "type": "number",
            "required": false,
            "default": 55443
          }
        ]
      }
    }
  ]
}
```

### 2. Bảng giải thích chi tiết các trường trong `manifest.json`

| Tên Trường | Kiểu Dữ Liệu | Bắt Buộc | Ràng Buộc & Quy Chuẩn | Mô Tả & Ví Dụ |
|---|---|---|---|---|
| `manifest_version` | String | Có | Phải là `"1.0"` | Phiên bản đặc tả kỹ thuật manifest |
| `extension_id` | String | Có | Slug chữ thường `^[a-z0-9][a-z0-9_-]{1,119}$` | Định danh duy nhất trên Marketplace, ví dụ: `yeelight_control` |
| `name` | String | Có | 1 - 100 ký tự | Tên hiển thị người dùng nhìn thấy trên chợ ứng dụng |
| `version` | String | Có | Chuỗi Semantic Versioning (`x.y.z`) | Phiên bản tiện ích, ví dụ: `1.0.0` |
| `author` | String | Có | 2 - 100 ký tự, không dùng placeholder | Tên tổ chức hoặc cá nhân phát triển (VD: `E-Connect Team`, `Experience`) |
| `contributor` | String | Không | Định dạng username GitHub | Tài khoản GitHub của người lập trình chính, ví dụ: `ryzen30xx` |
| `icon` | String | Không | Tên icon Material Symbols | Icon hiển thị trên giao diện (VD: `lightbulb`, `hub`, `developer_board`, `sensors`) |
| `categories` | Array[String] | Không | Mảng chuỗi phân loại | Danh mục tiện ích: `["light", "3rd party"]`, `["hub"]`, `["system"]`, `["switch"]`, `["sensor"]` |
| `description` | String | Có | Chuỗi không rỗng | Tóm tắt chức năng và hướng dẫn sơ lược |
| `provider.key` | String | Có | Slug chữ thường | Khóa định danh nhà cung cấp thiết bị (VD: `yeelight`, `zigbee2mqtt`) |
| `provider.display_name` | String | Có | Chuỗi không rỗng | Tên thương hiệu hiển thị (VD: `Yeelight`, `Zigbee2MQTT`) |
| `package.runtime` | String | Có | Bắt buộc là `"python"` | Môi trường máy ảo thực thi |
| `package.entrypoint` | String | Có | Tệp Python nội bộ (VD: `main.py`) | Đường dẫn tệp chứa các hàm hooks |
| `package.hooks` | Object | Có | Ánh xạ tên hook -> tên hàm Python | Phải chứa: `validate_command`, `execute_command`, `probe_state`. Tùy chọn: `discover_devices` |
| `device_schemas` | Array[Object]| Có | Danh sách ít nhất 1 schema | Danh mục các mẫu thiết bị mà tiện ích cung cấp |

### 3. Chi tiết cấu hình `device_schemas`

Mỗi phần tử trong mảng `device_schemas` định nghĩa giao diện điều khiển và biểu mẫu cấu hình thiết bị:

* **`schema_id`**: Mã định danh schema dạng slug chữ thường (VD: `yeelight_white_light`).
* **`device_type`**: Phân loại thiết bị (`light`, `switch`, `sensor`, `hub`). Nếu không khai báo sẽ kế thừa từ `display.card_type`.
* **`name` / `default_name`**: Tên hiển thị của schema thiết bị.
* **`display.card_type`**: Loại thẻ hiển thị trên Dashboard (`light`, `switch`, `sensor`).
* **`display.capabilities`**: Mảng các tính năng điều khiển:
  * Đèn (`light`): `["power", "brightness", "rgb", "color_temperature"]`
  * Công tắc (`switch`): `["power"]`
  * Cảm biến (`sensor`): `["value"]`
* **`display.temperature_range`**: *(Chỉ dành cho `card_type: light` khi có `color_temperature`)*:
  * `{"min": 1700, "max": 6500}` (đơn vị Kelvin, yêu cầu `min < max`).
* **`config_schema.fields`**: Danh sách các trường cấu hình người dùng nhập khi thêm mới thiết bị:
  * `key`: Slug định danh trường (VD: `ip_address`, `port`).
  * `label`: Nhãn hiển thị trên form giao diện (VD: `"Địa chỉ IP thiết bị"`).
  * `type`: Kiểu dữ liệu, gồm: `"string"`, `"number"`, `"boolean"`, `"password"`.
  * `required`: Boolean (`true` hoặc `false`).
  * `default`: Giá trị mặc định ban đầu (tùy chọn).

---

## 🛡️ Quy Chuẩn Bảo Mật & Chống Mã Độc (Anti-Malware Policy)

Tiện ích mở rộng E-Connect chỉ được phép giao tiếp phần cứng qua giao thức mạng hoặc cổng truyền thông chuyên dụng. Hệ thống CI/CD sử dụng cơ chế **AST (Abstract Syntax Tree) Static Analysis** và bộ quét lỗ hổng **Bandit** để tự động kiểm duyệt.

> [!CAUTION]
> Các hành vi sau đây bị **CẤM TUYỆT ĐỐI** và sẽ khiến quy trình CI/CD đánh trượt ngay lập tức:
>
> 1. **Thực thi tiến trình hệ điều hành**:
>    - Cấm import hoặc gọi: `subprocess` (`Popen`, `run`, `call`), `os.system()`, `os.popen*()`, `os.spawn*()`, `os.exec*()`, `pty.spawn()`.
> 2. **Thực thi mã động & Obfuscation**:
>    - Cấm gọi: `eval()`, `exec()`, `compile()`, `__import__()` động.
> 3. **Truy cập tệp tin nhạy cảm của máy chủ host**:
>    - Cấm truy vấn chuỗi đường dẫn nhắm vào: `/etc/passwd`, `/etc/shadow`, `/etc/econnect`, `/var/lib/econnect`, `/var/run/docker.sock`, `.ssh/`, `.bash_history`.
> 4. **Tạo kết nối ngầm & Reverse Shell**:
>    - Cấm sử dụng `os.dup2()` hoặc kỹ thuật gắn socket trực tiếp vào stdin/stdout.
> 5. **Thư viện can thiệp bộ nhớ & bắt phím (Keylogger)**:
>    - Cấm các module: `ctypes`, `pynput`, `keyboard`, `scapy`.

---

## 🧪 Hướng Dẫn Kiểm Thử Tại Local (Validation CLI)

Trước khi commit mã nguồn hoặc tạo Pull Request, nhà phát triển hãy tự kiểm tra tiện ích tại máy cục bộ bằng công cụ thẩm định đi kèm:

### 1. Cài đặt môi trường kiểm thử
```bash
# Cài đặt công cụ quét bảo mật tĩnh Bandit
python3 -m pip install bandit
```

### 2. Chạy lệnh kiểm tra

```bash
# 1. Kiểm tra một thư mục tiện ích cụ thể:
python3 .github/scripts/validate_extensions.py smart_lighting_pro

# 2. Kiểm tra chỉ các tiện ích có thay đổi (so với commit trước hoặc working tree):
python3 .github/scripts/validate_extensions.py --changed-only

# 3. Quét toàn bộ repository:
python3 .github/scripts/validate_extensions.py --all
```

Khi kiểm tra thành công, kết quả hiển thị dạng:
```text
======================================================================
🛡️  E-CONNECT MARKETPLACE: EXTENSION VALIDATOR & SECURITY AUDITOR
    Target Extensions: 1 folder(s) selected for audit
======================================================================

📂 [1/1] Auditing Extension Folder: smart_lighting_pro
  ------------------------------------------------------------------
  ✓ Manifest: manifest.json parsed directly from folder
  ✓ Format: E-Connect v1.0 Standard
  ✓ Identity: id='smart_lighting_pro' | version='1.0.0'
  ✓ Author: 'Experience' -> VERIFIED DEVELOPER (Partner)
  ✓ Contributor: @ryzen30xx
  ✓ Icon: lightbulb
  ✓ Categories: light, 3rd party
  ✓ Entrypoint: 'main.py' verified
  ✓ Codebase: 2 Python file(s) parsed & audited
  ✓ Security AST: No shell/subprocess, no eval/exec, no host tampering
  ✓ Device Schemas: 1 schema(s) verified
  ✅ VERDICT: PASS (Authentic, compliant & safe)

======================================================================
🎉 AUDIT PASSED: All 1 extension(s) verified 100% compliant and secure!
```

---

## 🚀 Quy Trình Tự Động Hóa (CI/CD Pipeline) & Đóng Góp Tiện Ích

Hệ thống CI/CD được thiết lập qua GitHub Actions tại [`.github/workflows/validate-extensions.yml`](.github/workflows/validate-extensions.yml):

* **Khi có Pull Request**: CI tự động phát hiện các thư mục tiện ích mới hoặc được sửa đổi và chạy chế độ `--changed-only` để đảm bảo tốc độ phản hồi nhanh.
* **Khi Push vào `main`**: CI tự động kiểm tra toàn diện 100% tiện ích (`--all`) nhằm đảm bảo tính toàn vẹn tuyệt đối trên nhánh chính.
* **Báo cáo trực quan**: Tự động xuất bảng tổng kết trạng thái thẩm định vào GitHub Actions Step Summary.

### Các bước đóng góp một Extension mới:

1. **Fork** repository `econnect_extensions` về tài khoản GitHub cá nhân.
2. Tạo một thư mục mới tại thư mục gốc với tên tiện ích (ví dụ: `my_sensor_extension/`).
3. Khởi tạo tệp `manifest.json` theo đúng [đặc tả kỹ thuật](#-hướng-dẫn-viết-manifestjson-chuẩn-specification-v10).
4. Viết mã xử lý logic trong `main.py` thực hiện đầy đủ 3 hooks bắt buộc (`validate_command`, `execute_command`, `probe_state`).
5. Kiểm tra vệ sinh thư mục (xóa bỏ file cache `__pycache__`, file ẩn `.DS_Store`).
6. Chạy công cụ kiểm thử:
   ```bash
   python3 .github/scripts/validate_extensions.py my_sensor_extension
   ```
7. Commit thay đổi, push lên GitHub và tạo **Pull Request** vào nhánh `main` hoặc `dev`. Hệ thống CI/CD sẽ tự động phân tích và phản hồi kết quả trong vòng vài giây.
