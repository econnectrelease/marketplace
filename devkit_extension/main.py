import sys
import threading
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

LATEST_DEBUG_DATA = {
    "validate_command": None,
    "execute_command": None,
    "probe_state": None
}

html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>E-Connect Extension DevKit</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #38bdf8; padding: 20px; line-height: 1.6; }
        .grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
        @media (max-width: 1000px) { .grid { grid-template-columns: 1fr; } }
        .box { background: #1e293b; border: 1px solid #334155; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
        pre { white-space: pre-wrap; word-wrap: break-word; color: #fbbf24; background: #000; padding: 15px; border-radius: 5px; font-size: 14px; overflow-x: auto; max-height: 400px; }
        h1 { border-bottom: 2px solid #334155; padding-bottom: 10px; margin-bottom: 30px; font-weight: 600; color: #f8fafc; }
        h3 { color: #f8fafc; margin-top: 0; }
        .blink { animation: blinker 1s linear infinite; }
        @keyframes blinker { 50% { opacity: 0; } }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; background: #16a34a; color: white; font-size: 12px; font-weight: bold; margin-bottom: 15px;}
    </style>
</head>
<body>
    <h1>🛠️ E-Connect <span style="color:#38bdf8;">DevKit Debugger</span></h1>
    <p>Trang này tự động làm mới polling mỗi <strong class="blink">1 giây</strong> để fetch live raw data từ Backend truyền xuống.</p>
    
    <div class="grid">
        <div class="box">
            <h3>🟡 validate_command</h3>
            <div class="badge" style="background:#ca8a04;">Validation</div>
            <pre id="validate_data">Waiting...</pre>
        </div>

        <div class="box">
            <h3>🔴 execute_command</h3>
            <div class="badge" style="background:#dc2626;">Live Events</div>
            <pre id="execute_data">Waiting for Main WebUI trigger...</pre>
        </div>

        <div class="box">
            <h3>🔵 probe_state</h3>
            <div class="badge" style="background:#2563eb;">Background Checks</div>
            <pre id="probe_data">Waiting...</pre>
        </div>
    </div>

    <script>
        setInterval(() => {
            fetch(window.location.pathname.replace(/\\/$/, '') + '/data')
                .then(res => res.json())
                .then(data => {
                    if(data.validate_command) {
                        document.getElementById('validate_data').innerText = JSON.stringify(data.validate_command, null, 2);
                    }
                    if(data.execute_command) {
                        document.getElementById('execute_data').innerText = JSON.stringify(data.execute_command, null, 2);
                    }
                    if(data.probe_state) {
                        document.getElementById('probe_data').innerText = JSON.stringify(data.probe_state, null, 2);
                    }
                })
                .catch(console.error);
        }, 1000);
    </script>
</body>
</html>
"""

# =========================================================
# Gắn UI DevKit trực tiếp vào App gốc để bỏ qua Docker Port
# =========================================================
fastapi_app = None

fastapi_app = None

import gc
for obj in gc.get_objects():
    try:
        if obj.__class__.__name__ == "FastAPI" and getattr(obj, "title", "") == "E-Connect Server":
            fastapi_app = obj
            print(f"[DevKit] Found E-Connect Server FastAPI app via GC (Routes: {len(obj.routes)})")
            break
    except Exception:
        pass

if fastapi_app:
    print("[DevKit] Found Server FastAPI instance. Injecting routes directly into port 8000!")
    from fastapi.responses import HTMLResponse, JSONResponse
    
    @fastapi_app.get("/devkit")
    async def get_devkit_ui():
        return HTMLResponse(content=html_content)

    @fastapi_app.get("/devkit/data")
    async def get_devkit_data():
        return JSONResponse(content=LATEST_DEBUG_DATA)

else:
    # Dự phòng: Chạy HTTP Server riêng biệt
    class DevKitHTTPRequestHandler(BaseHTTPRequestHandler):
        def end_headers(self):
            # Mở khoá CORS hoàn toàn
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type')
            super().end_headers()

        def do_OPTIONS(self):
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            if self.path == '/devkit':
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(html_content.encode('utf-8'))
            elif self.path == '/devkit/data':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(LATEST_DEBUG_DATA).encode('utf-8'))
            else:
                self.send_response(302)
                self.send_header('Location', '/devkit')
                self.end_headers()

    def start_server(port):
        server_address = ('0.0.0.0', port)
        try:
            httpd = HTTPServer(server_address, DevKitHTTPRequestHandler)
            print(f"[DevKit] Standalone WebUI started on http://0.0.0.0:{port}/devkit")
            httpd.serve_forever()
        except OSError:
            print(f"[DevKit] Port {port} is occupied.")

    server_thread = threading.Thread(target=start_server, args=(9999,), daemon=True)
    server_thread.start()

# =========================================================
# XỬ LÝ HOOKS
# =========================================================

SIMULATED_STATE = {
    "power": "on",
    "brightness": 75,
    "rgb": "#ff5500",
    "color_temperature": 5000
}

def on_validate_command(device_context, command_context):
    LATEST_DEBUG_DATA["validate_command"] = {
        "device": device_context,
        "command": command_context
    }
    return True

def on_execute_command(device_context, command_context):
    LATEST_DEBUG_DATA["execute_command"] = {
        "device": device_context,
        "command": command_context
    }
    print(f"[DevKit] Executing Command received from E-Connect Core: {command_context['command']}")
    
    cmd = command_context.get("command")
    args = command_context.get("args", {})
    
    if cmd == "turn_on":
        SIMULATED_STATE["power"] = "on"
    elif cmd == "turn_off":
        SIMULATED_STATE["power"] = "off"
    elif cmd == "set_brightness":
        if "brightness" in args:
            SIMULATED_STATE["brightness"] = args["brightness"]
        elif "level" in args:
            SIMULATED_STATE["brightness"] = args["level"]
    elif cmd == "set_rgb":
        if "rgb" in args:
            SIMULATED_STATE["rgb"] = args["rgb"]
        elif "color" in args:
            SIMULATED_STATE["rgb"] = args["color"]
    elif cmd == "set_color_temperature":
        if "color_temperature" in args:
            SIMULATED_STATE["color_temperature"] = args["color_temperature"]
        elif "temperature" in args:
            SIMULATED_STATE["color_temperature"] = args["temperature"]
            
    return {
        "status": "success", 
        "message": "DevKit intercepted and logged raw execution payload"
    }

def on_probe_state(device_context):
    LATEST_DEBUG_DATA["probe_state"] = device_context
    return {
        "connected": True,
        "state": SIMULATED_STATE
    }
