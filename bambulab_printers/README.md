# Bambu Lab 3D Printers Extension for E-Connect

Tích hợp toàn diện các dòng máy in 3D của **Bambu Lab** (A1, A1 Mini, P1P, P1S, X1 Carbon, X1E) vào hệ sinh thái nhà thông minh E-Connect.

---

## 1. Tính Năng Chính

- **Hỗ trợ toàn diện 6 dòng máy in**: A1, A1 Mini, P1P, P1S, X1C, X1E với thuật toán nhận diện tự động dựa trên telemetry và số sê-ri.
- **Chuẩn Manifest v2.0**: Cung cấp thẻ cảm biến 6 chỉ số thời gian thực:
  1. `status`: Trạng thái lệnh in (`IDLE`, `RUNNING`, `PAUSE`, `FINISH`, `FAILED`).
  2. `progress`: Tiến độ in theo phần trăm (`%`).
  3. `remaining_time`: Thời gian in còn lại tính theo phút (`phút`).
  4. `subtask_name`: Tên file / mô hình 3D đang in.
  5. `nozzle_temp`: Nhiệt độ đầu đùn hiện tại (`°C`).
  6. `bed_temp`: Nhiệt độ bàn in hiện tại (`°C`).
- **Giao thức MQTT qua TLS Port 8883**: Kết nối an toàn với máy in trong mạng nội bộ LAN, không phụ thuộc Bambu Cloud. Tự động nhận diện `serial_number` từ chứng chỉ TLS (Subject CN) trên Port 8883 hoặc qua SSDP (UDP 2021/1900), người dùng chỉ cần nhập IP và Access Code.
- **Hệ thống thông báo tức thì (NotificationService)**: Tự động cảnh báo qua E-Connect khi bản in hoàn thành (`FINISH`), bị dừng (`PAUSE`), hoặc gặp lỗi (`FAILED`).
- **Zero-Disk Cache 3MF Streaming**: Đẩy file `.3mf` trực tiếp từ bộ nhớ đệm RAM lên thẻ nhớ SD của máy in qua `ImplicitFTP_TLS` (Port 990) với cơ chế bắt buộc TLS Session Reuse, tuyệt đối không tạo tệp tạm lưu trên ổ cứng E-Connect server.
- **Chamber Camera đa luồng**:
  - Dòng A1, P1: Kết nối Port 6000 TLS, gửi gói xác thực 80 bytes và xuất luồng MJPEG / snapshot với timeout giới hạn theo deadline.
  - Dòng X1: Kết nối RTSPS Port 322 (`rtsps://bblp:{access_code}@{ip}:322/streaming/live/1`).
- **Tự động quét SSDP & mDNS fallback**: Dò tìm máy in trong mạng nội bộ qua SSDP (`urn:bambulab-com:device:3dprinter:1` trên UDP 2021/1900) và fallback mDNS `_bambulab._tcp.local`.

---

## 2. Cấu Trúc Gói Tiện Ích

```text
econnect_extensions/bambulab_printers/
├── manifest.json              # Khai báo metadata v2.0, device schemas, capabilities
├── assets/
│   └── bambulab.svg           # Logo vector nhận diện chính thức Bambu Lab
├── __init__.py                # Khởi tạo package
├── bambu_mqtt.py              # Kết nối MQTT TLS 8883, parse telemetry, NotificationService
├── bambu_ftps.py              # ImplicitFTP_TLS, Zero-Disk Cache 3MF stream
├── bambu_camera.py            # Camera adapter (Port 6000 TLS & Port 322 RTSPS)
├── driver.py                  # Bộ điều khiển phần cứng trung tâm
├── main.py                    # Điểm vào (entrypoint) cung cấp 4 hooks E-Connect
├── GEMINI.md                  # Bản đồ module GEB Fractal L2
└── README.md                  # Hướng dẫn kỹ thuật
```

---

## 3. Cấu Hình Thiết Bị (Config Schema)

| Trường | Kiểu | Bắt buộc | Mô tả |
|---|---|---|---|
| `ip_address` | String | Có | Địa chỉ IP nội bộ của máy in (VD: `192.168.1.150`) |
| `access_code` | Password | Có | Mã LAN Access Code hiển thị trên màn hình máy in |

> **Tự động nhận diện Serial Number:** Trường `serial_number` được hệ thống tự động giải mã từ Subject CN của chứng chỉ TLS (Port 8883) hoặc gói SSDP (UDP 2021/1900) khi kết nối lần đầu (vẫn hỗ trợ tương thích ngược nếu truyền `serial_number` trực tiếp qua API/simulator).

---

## 4. Các Lệnh Điều Khiển Được Hỗ Trợ

- `pause`: Tạm dừng lệnh in hiện tại.
- `resume`: Tiếp tục lệnh in đang tạm dừng.
- `stop`: Hủy bỏ và dừng hẳn lệnh in.
- `set_power` / `chamber_light` / `power` / Automation Toggle (`{"kind": "action", "pin": 0, "value": 0|1}`): Bật / tắt đèn buồng in.
- `snapshot`: Chụp ảnh buồng in tức thì.
- `upload_3mf`: Truyền tệp in 3MF từ RAM buffer lên thẻ SD máy in.
