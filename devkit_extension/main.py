"""Per-device E-Connect DevKit simulator sharing a single LAN port."""
from __future__ import annotations

import hashlib
import html
import json
import ipaddress
import re
import socket
import threading
from datetime import UTC, datetime
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import quote, unquote, urlparse

MAX_EVENTS = 50
MAX_REQUEST_BYTES = 16 * 1024
DEFAULT_SIMULATOR_PORT = 18080
TYPES = {"light", "switch", "fan", "sensor"}
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
SECRET = re.compile(r"password|secret|token|api[_-]?key|credential", re.I)
LOCK = threading.RLock()
SESSIONS: dict[str, dict[str, Any]] = {}
SERVERS: dict[int, ThreadingHTTPServer] = {}


def _safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): "***" if SECRET.search(str(k)) else _safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe(v) for v in value]
    return value if isinstance(value, (str, int, float, bool)) or value is None else str(value)


def _id(context: dict[str, Any]) -> str:
    config = context.get("config") if isinstance(context.get("config"), dict) else {}
    for value in (context.get("device_id"), context.get("id"), config.get("device_id")):
        if isinstance(value, str) and SAFE_ID.fullmatch(value.strip()):
            return value.strip()
    digest = hashlib.sha256(json.dumps(_safe(context), sort_keys=True, default=str).encode()).hexdigest()[:16]
    return f"unknown-{digest}"


def _type(context: dict[str, Any]) -> str:
    schema = context.get("schema_snapshot") if isinstance(context.get("schema_snapshot"), dict) else {}
    display = schema.get("display") if isinstance(schema.get("display"), dict) else {}
    for value in (schema.get("device_type"), display.get("card_type"), context.get("device_type")):
        if isinstance(value, str) and value.strip().lower() in TYPES:
            return value.strip().lower()
    schema_id = str(context.get("device_schema_id") or "").lower()
    return schema_id.removeprefix("devkit_") if schema_id.removeprefix("devkit_") in TYPES else "light"


def _caps(context: dict[str, Any], device_type: str) -> list[str]:
    schema = context.get("schema_snapshot") if isinstance(context.get("schema_snapshot"), dict) else {}
    display = schema.get("display") if isinstance(schema.get("display"), dict) else {}
    caps = [str(v).lower() for v in display.get("capabilities", []) if isinstance(v, str)]
    return caps or {"light": ["power", "brightness", "rgb", "color_temperature"], "switch": ["power"], "fan": ["power", "fan_speed"], "sensor": ["value"]}[device_type]


def _path(device_id: str) -> str:
    return f"/{quote(device_id, safe='')}/test"


def _url(session: dict[str, Any]) -> str | None:
    host, port = session.get("hub_host"), session.get("port")
    return f"http://{host}:{port}{_path(session['device_id'])}" if host and port else None


def _state(device_type: str, url: str | None = None) -> dict[str, Any]:
    base: dict[str, Any] = {"ip_address": url} if url else {}
    st = {
        "light": {"power": "off", "brightness": 75, "rgb": "#ff5500", "color_temperature": 5000},
        "switch": {"power": "off"},
        "fan": {"power": "off", "fan_speed": 50, "speed": 50},
        "sensor": {"value": 22.5, "unit": "°C"},
    }[device_type]
    return {**base, **st}


def _port(context: dict[str, Any]) -> int:
    config = context.get("config") if isinstance(context.get("config"), dict) else {}
    value = config.get("simulator_port")
    if value not in (None, ""):
        try:
            num = int(value)
            if 1024 <= num <= 65535:
                return num
        except (TypeError, ValueError):
            pass
    return DEFAULT_SIMULATOR_PORT


def _private_ipv4(value: Any) -> str | None:
    """Return a non-loopback RFC1918 IPv4 address, never a public address."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if address.version != 4:
        return None
    rfc1918 = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))
    return str(address) if any(address in network for network in rfc1918) else None


def _lan_host_candidates() -> set[str]:
    """Gather all locally resolvable RFC1918 IPv4 addresses without trusting one route."""
    candidates: set[str] = set()
    try:
        for family, _kind, _proto, _name, address in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            if family == socket.AF_INET and (host := _private_ipv4(address[0])):
                candidates.add(host)
    except OSError:
        pass
    try:
        for address in socket.gethostbyname_ex(socket.gethostname())[2]:
            if host := _private_ipv4(address):
                candidates.add(host)
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("10.255.255.255", 1))
            if host := _private_ipv4(probe.getsockname()[0]):
                candidates.add(host)
    except OSError:
        pass
    return candidates


def _resolve_hub_host(context: dict[str, Any]) -> str | None:
    """Prefer an explicit safe Hub LAN address, then discover the routed LAN IP."""
    config = context.get("config") if isinstance(context.get("config"), dict) else {}
    configured = _private_ipv4(config.get("hub_host"))
    if configured:
        return configured
    candidates = _lan_host_candidates()
    return next(iter(candidates)) if len(candidates) == 1 else None


def _hub_host_error(context: dict[str, Any]) -> str | None:
    config = context.get("config") if isinstance(context.get("config"), dict) else {}
    configured = config.get("hub_host")
    if configured not in (None, "") and not _private_ipv4(configured):
        return "hub_host must be an RFC1918 IPv4 address (10/8, 172.16/12, or 192.168/16)."
    candidates = _lan_host_candidates()
    if len(candidates) > 1:
        return "Multiple Hub LAN IPv4 addresses found. Set hub_host to the intended RFC1918 Hub LAN IP."
    return "No safe RFC1918 Hub LAN IPv4 address found. Set hub_host to the Hub LAN IP."


def _session(context: dict[str, Any]) -> dict[str, Any]:
    device_id = _id(context)
    with LOCK:
        if device_id not in SESSIONS:
            device_type = _type(context)
            host = _resolve_hub_host(context)
            port = _port(context)
            temp_session = {"hub_host": host, "port": port, "device_id": device_id}
            url = _url(temp_session)
            SESSIONS[device_id] = {
                "device_id": device_id,
                "device_type": device_type,
                "capabilities": _caps(context, device_type),
                "state": _state(device_type, url=url),
                "events": [],
                "port": port,
                "hub_host": host,
                "hub_host_error": None if host else _hub_host_error(context),
                "connected": False,
                "connection_error": None,
            }
        else:
            item = SESSIONS[device_id]
            url = _url(item)
            if url and not item["state"].get("ip_address"):
                item["state"]["ip_address"] = url
        return SESSIONS[device_id]


def _event(session: dict[str, Any], kind: str, payload: Any) -> None:
    session["events"].append({"at": datetime.now(UTC).isoformat(), "kind": kind, "payload": _safe(payload)})
    del session["events"][:-MAX_EVENTS]


def _apply(session: dict[str, Any], command: dict[str, Any]) -> None:
    if not isinstance(command, dict):
        return
    state = session["state"]
    raw_name = command.get("command") or command.get("action") or command.get("cmd") or ""
    name = str(raw_name).strip().lower()
    args = command.get("args") if isinstance(command.get("args"), dict) else {}

    # 1. RPC style commands
    if name == "turn_on":
        state["power"] = "on"
        if "fan_speed" in state and state.get("fan_speed", 0) == 0:
            state["fan_speed"] = 50
            state["speed"] = 50
    elif name == "turn_off":
        state["power"] = "off"
        if "fan_speed" in state:
            state["fan_speed"] = 0
            state["speed"] = 0
    elif name in ("set_fan_speed", "set_speed"):
        val = args.get("fan_speed", args.get("speed", command.get("speed", command.get("fan_speed"))))
        if val is not None:
            try:
                num = int(val)
                state["fan_speed"] = num
                state["speed"] = num
                state["power"] = "on" if num > 0 else "off"
            except (ValueError, TypeError):
                pass
    elif name == "set_brightness":
        val = args.get("brightness", args.get("level", command.get("brightness")))
        if val is not None:
            try:
                num = int(val)
                state["brightness"] = num
                if num > 0:
                    state["power"] = "on"
            except (ValueError, TypeError):
                pass
    elif name == "set_rgb":
        val = args.get("rgb", args.get("color", command.get("rgb")))
        if isinstance(val, dict):
            r = int(val.get("r", 0))
            g = int(val.get("g", 0))
            b = int(val.get("b", 0))
            state["rgb"] = f"#{r:02x}{g:02x}{b:02x}"
        elif isinstance(val, (list, tuple)) and len(val) >= 3:
            state["rgb"] = f"#{int(val[0]):02x}{int(val[1]):02x}{int(val[2]):02x}"
        elif isinstance(val, str):
            state["rgb"] = val
    elif name == "set_color_temperature":
        val = args.get("color_temperature", args.get("temperature", command.get("color_temperature")))
        if val is not None:
            try:
                state["color_temperature"] = int(val)
            except (ValueError, TypeError):
                pass
    elif name in ("set_value", "report_value"):
        val = args.get("value", command.get("value"))
        if val is not None:
            state["value"] = val

    # 2. Standard E-Connect Action style commands / payload keys
    if "speed" in command or "fan_speed" in command:
        raw_spd = command.get("speed", command.get("fan_speed"))
        try:
            spd = int(raw_spd)
            state["fan_speed"] = spd
            state["speed"] = spd
            state["power"] = "on" if spd > 0 else "off"
        except (ValueError, TypeError):
            pass

    if "brightness" in command:
        try:
            b_val = int(command["brightness"])
            state["brightness"] = b_val
            if b_val > 0:
                state["power"] = "on"
        except (ValueError, TypeError):
            pass

    if "rgb" in command:
        rgb_val = command["rgb"]
        if isinstance(rgb_val, dict):
            r = int(rgb_val.get("r", 0))
            g = int(rgb_val.get("g", 0))
            b = int(rgb_val.get("b", 0))
            state["rgb"] = f"#{r:02x}{g:02x}{b:02x}"
        elif isinstance(rgb_val, (list, tuple)) and len(rgb_val) >= 3:
            state["rgb"] = f"#{int(rgb_val[0]):02x}{int(rgb_val[1]):02x}{int(rgb_val[2]):02x}"
        elif isinstance(rgb_val, str):
            state["rgb"] = rgb_val

    if "color_temperature" in command or "tone" in command:
        val = command.get("color_temperature", command.get("tone"))
        try:
            state["color_temperature"] = int(val)
        except (ValueError, TypeError):
            pass

    if "power" in command:
        p_val = command["power"]
        if p_val in (True, 1, "on", "true", "1", "ON"):
            state["power"] = "on"
        elif p_val in (False, 0, "off", "false", "0", "OFF"):
            state["power"] = "off"

    if "value" in command and ("speed" not in command and "fan_speed" not in command):
        val = command["value"]
        if "power" in state:
            if val in (True, 1, "on", "true", "1", "ON"):
                state["power"] = "on"
                if "fan_speed" in state and state.get("fan_speed", 0) == 0:
                    state["fan_speed"] = 50
                    state["speed"] = 50
            elif val in (False, 0, "off", "false", "0", "OFF"):
                state["power"] = "off"
                if "fan_speed" in state:
                    state["fan_speed"] = 0
                    state["speed"] = 0
        elif "value" in state:
            state["value"] = val


def _payload(device_id: str) -> dict[str, Any] | None:
    with LOCK:
        item = SESSIONS.get(device_id)
        if not item:
            return None
        return deepcopy({key: item[key] for key in ("device_id", "device_type", "capabilities", "state", "events", "port", "hub_host", "connected", "connection_error")}) | {"test_path": _path(device_id), "simulator_url": _url(item)}


def _ui(device_id: str) -> str:
    return r"""<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>DevKit Protocol Console</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#07111e;color:#dce9f7;font:14px ui-monospace,SFMono-Regular,Consolas,monospace}.shell{max-width:1360px;margin:auto;padding:24px}.eyebrow{color:#50d8ff;letter-spacing:.12em;text-transform:uppercase;font-size:11px}h1{font:700 clamp(25px,4vw,42px) system-ui;margin:8px 0}.sub{color:#91a8bd}.grid{display:grid;grid-template-columns:1.1fr .9fr;gap:14px}.full{grid-column:1/-1}.card{background:#0d1c2c;border:1px solid #1f3d55;border-radius:12px;padding:16px;box-shadow:0 10px 35px #0004}h2{font:600 13px system-ui;margin:0 0 12px;color:#a9c8df;text-transform:uppercase;letter-spacing:.08em}.url{display:flex;gap:8px;align-items:center;background:#06101a;padding:10px;border-radius:7px;color:#6ee7ff;overflow:auto}.chip{display:inline-block;padding:4px 7px;border:1px solid #315a72;border-radius:999px;margin:0 5px 5px 0;color:#a8dcf5}button,input{font:inherit;border-radius:6px;padding:8px;border:1px solid #315a72;background:#102a3e;color:#e7f6ff}button{cursor:pointer;background:#126e91;font-weight:700}button:hover{background:#1686ae}input[type=range]{accent-color:#50d8ff}pre{margin:0;max-height:320px;overflow:auto;background:#050c14;padding:12px;border-radius:8px;color:#b9d9ee}.event{border-left:3px solid #337c9f;padding:8px;margin:7px 0;background:#091522}.event time{color:#6e91aa}.event b{color:#80dcff}.controls{display:flex;flex-wrap:wrap;align-items:center;gap:8px}.status{color:#86efac}.offline{color:#fca5a5}@media(max-width:780px){.shell{padding:14px}.grid{grid-template-columns:1fr}.full{grid-column:auto}.url{align-items:stretch;flex-direction:column}}</style><main class=shell><div class=eyebrow>E-Connect / Developer mode</div><h1>DevKit Protocol Console</h1><p class=sub>Interactive device contract simulator. Inbound commands and returned state are recorded locally; sensitive keys are redacted.</p><div class=grid><section class='card full'><h2>Hub LAN endpoint</h2><div class=url><code id=url>Loading endpoint…</code><button id=copy>Copy URL</button></div><p id=connection class=sub></p></section><section class=card><h2>Device identity &amp; capabilities</h2><div id=identity></div><h2 style='margin-top:18px'>Simulator controls</h2><div id=controls class=controls></div></section><section class=card><h2>State inspector <span class=sub>(probe_state)</span></h2><pre id=state></pre><h2 style='margin-top:18px'>Raw redacted payload</h2><pre id=raw></pre></section><section class='card full'><h2>Command &amp; event timeline</h2><div id=events></div></section></div></main><script>const base=location.pathname.replace(/\/test$/,'');const dump=x=>JSON.stringify(x,null,2);let timer;function node(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}async function action(command,args={}){const r=await fetch(base+'/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command,args})});if(!r.ok)throw new Error('Action rejected');await load()}function btn(label,command){const e=node('button',label);e.addEventListener('click',()=>action(command).catch(showError));return e}function input(type,value,command,key){const e=document.createElement('input');e.type=type;e.value=String(value);if(type==='range'){e.min='0';e.max='100'}if(type==='number')e.step='.1';e.addEventListener('change',()=>action(command,{[key]:type==='color'?e.value:Number(e.value)}).catch(showError));return e}function showError(e){document.querySelector('#connection').textContent=e.message;document.querySelector('#connection').className='offline'}function controls(d){const r=document.querySelector('#controls');r.replaceChildren();if(d.capabilities.includes('power'))r.append(btn('Turn on','turn_on'),btn('Turn off','turn_off'));if(d.capabilities.includes('brightness'))r.append(node('span','Brightness'),input('range',d.state.brightness||0,'set_brightness','brightness'));if(d.capabilities.includes('fan_speed'))r.append(node('span','Fan speed'),input('range',d.state.fan_speed!=null?d.state.fan_speed:(d.state.speed||0),'set_fan_speed','fan_speed'));if(d.capabilities.includes('rgb'))r.append(node('span','RGB'),input('color',/^#[0-9a-fA-F]{6}$/.test(d.state.rgb)?d.state.rgb:'#000000','set_rgb','rgb'));if(d.capabilities.includes('value'))r.append(node('span','Value'),input('number',d.state.value||0,'set_value','value'))}function timeline(events){const r=document.querySelector('#events');r.replaceChildren();for(const event of [...events].reverse()){const row=node('article',undefined,'event');row.append(node('b',event.kind),node('time','  '+new Date(event.at).toLocaleString()),node('pre',dump(event.payload)));r.append(row)}if(!events.length)r.append(node('p','No protocol traffic yet.'))}function identity(d){const r=document.querySelector('#identity');r.replaceChildren();for(const v of [d.device_id,d.device_type,...d.capabilities])r.append(node('span',v,'chip'))}async function load(){const r=await fetch(base+'/data');if(!r.ok)throw new Error('Simulator data unavailable');const d=await r.json();document.querySelector('#url').textContent=d.simulator_url||'No safe Hub LAN address available';document.querySelector('#connection').textContent=d.connected?'LISTENING on Hub LAN · local developer exposure only':(d.connection_error||'Offline');document.querySelector('#connection').className=d.connected?'status':'offline';document.querySelector('#state').textContent=dump(d.state);document.querySelector('#raw').textContent=dump(d);identity(d);controls(d);timeline(d.events);document.querySelector('#copy').onclick=()=>navigator.clipboard?.writeText(d.simulator_url||'').catch(showError)}load().catch(showError);timer=setInterval(()=>load().catch(showError),1200)</script>"""


def _index_ui(port: int) -> str:
    with LOCK:
        active = [
            (d["device_id"], d["device_type"], _url(d))
            for d in SESSIONS.values()
            if d.get("port") == port
        ]
    rows = "".join(
        f"<li><b><a href='{u}' style='color:#50d8ff'>{html.escape(did)}</a></b> ({html.escape(dtype)}) - <a href='{u}'>{u}</a></li>"
        for did, dtype, u in active
    )
    if not rows:
        rows = "<li>No active DevKit devices registered on this port yet.</li>"
    return f"""<!doctype html><meta charset=utf-8><title>DevKit Device Hub</title><style>body{{background:#07111e;color:#dce9f7;font:14px system-ui;padding:28px}}a{{color:#50d8ff;text-decoration:none}}a:hover{{text-decoration:underline}}ul{{line-height:2}}code{{background:#050c14;padding:3px 6px;border-radius:4px}}</style><h1>E-Connect DevKit Simulator Hub</h1><p>Shared Hub LAN Port: <code>{port}</code></p><h3>Active Devices:</h3><ul>{rows}</ul>"""


def _action(device_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    with LOCK:
        item = SESSIONS.get(device_id)
        if not item: return None
        url = _url(item)
        if url:
            item["state"]["ip_address"] = url
        command = {"command": body.get("command"), "args": body.get("args", {})}; _apply(item, command)
        _event(item, "simulator_action", {"command": command, "resulting_state": deepcopy(item["state"])})
    return _payload(device_id)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: Any) -> None: return

    def _reply(self, status: int, kind: str, value: str | bytes) -> None:
        data = value.encode() if isinstance(value, str) else value
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        req_path = unquote(urlparse(self.path).path).rstrip("/")
        if req_path in ("", "/devkit"):
            self._reply(200, "text/html; charset=utf-8", _index_ui(self.server.server_port))
            return

        match = re.fullmatch(r"/(?:devkit/)?([^/]+)/(test|data)", req_path)
        if not match:
            self._reply(404, "application/json", json.dumps({"detail": "Unknown DevKit route."}))
            return

        device_id, endpoint = match.groups()
        with LOCK:
            item = SESSIONS.get(device_id)
        if not item or item.get("port") != self.server.server_port:
            self._reply(404, "application/json", json.dumps({"detail": f"Unknown DevKit device '{device_id}' on port {self.server.server_port}."}))
            return

        if endpoint == "test":
            self._reply(200, "text/html; charset=utf-8", _ui(device_id))
            return

        data = _payload(device_id)
        self._reply(200 if data else 404, "application/json", json.dumps(data or {"detail": "Unknown device."}))

    def do_POST(self) -> None:  # noqa: N802
        match = re.fullmatch(r"/(?:devkit/)?([^/]+)/action", unquote(urlparse(self.path).path).rstrip("/"))
        if not match:
            self._reply(404, "application/json", json.dumps({"detail": "Unknown DevKit route."}))
            return

        device_id = match.group(1)
        with LOCK:
            item = SESSIONS.get(device_id)
        if not item or item.get("port") != self.server.server_port:
            self._reply(404, "application/json", json.dumps({"detail": f"Unknown DevKit device '{device_id}' on port {self.server.server_port}."}))
            return

        try: size = int(self.headers.get("Content-Length", "0"))
        except ValueError: size = -1
        if not 0 <= size <= MAX_REQUEST_BYTES:
            self._reply(413, "application/json", json.dumps({"detail": "Request body must be at most 16 KiB."}))
            return

        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self._reply(415, "application/json", json.dumps({"detail": "Content-Type must be application/json."}))
            return

        try: body = json.loads(self.rfile.read(size) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._reply(400, "application/json", json.dumps({"detail": "Invalid JSON."}))
            return

        if not isinstance(body, dict) or not isinstance(body.get("command"), str) or len(body["command"]) > 120 or ("args" in body and not isinstance(body["args"], dict)):
            self._reply(400, "application/json", json.dumps({"detail": "Expected a command string and optional object args."}))
            return

        data = _action(device_id, body)
        self._reply(200 if data else 404, "application/json", json.dumps(data or {"detail": "Unknown device."}))


def _start(session: dict[str, Any]) -> None:
    port, device_id, host = session["port"], session["device_id"], session.get("hub_host")
    if not host:
        session["connected"] = False
        session["connection_error"] = str(session.get("hub_host_error") or "No safe RFC1918 Hub LAN IPv4 address found. Set hub_host to the Hub LAN IP.")
        _event(session, "simulator_warning", {"message": session["connection_error"]})
        return

    with LOCK:
        if port in SERVERS:
            session["connected"] = True
            session["connection_error"] = None
            return

        bind_host = host if host == "127.0.0.1" else ""
        try:
            server = ThreadingHTTPServer((bind_host, port), Handler)
        except OSError as exc:
            session["connected"] = False
            session["connection_error"] = f"Could not bind simulator_port {port}: {exc}"
            _event(session, "simulator_error", {"message": session["connection_error"]})
            return

        SERVERS[port] = server
        session["connected"] = True
        session["connection_error"] = None
        threading.Thread(target=server.serve_forever, name=f"devkit-port-{port}", daemon=True).start()
        _event(session, "simulator_ready", {"simulator_url": _url(session)})


def on_validate_command(device_context: dict[str, Any], command_context: dict[str, Any]) -> bool:
    item = _session(device_context); _start(item)
    with LOCK: _event(item, "validate_command", {"device_id": item["device_id"], "command": command_context})
    return bool(item["connected"])


def on_execute_command(device_context: dict[str, Any], command_context: dict[str, Any]) -> dict[str, Any]:
    item = _session(device_context); _start(item)
    if not item["connected"]:
        return {"status": "error", "message": str(item["connection_error"] or "DevKit simulator is unavailable.")}
    url = _url(item)
    with LOCK:
        if url:
            item["state"]["ip_address"] = url
        _apply(item, command_context)
        resulting_state = deepcopy(item["state"])
        _event(item, "execute_command", {"device_id": item["device_id"], "command": command_context, "resulting_state": resulting_state})
    return {"status": "success", "message": f"DevKit simulated command for {item['device_id']}", "state": resulting_state}


def on_probe_state(device_context: dict[str, Any]) -> dict[str, Any]:
    item = _session(device_context); _start(item)
    url = _url(item)
    with LOCK:
        if url:
            item["state"]["ip_address"] = url
        _event(item, "probe_state", {"device_id": item["device_id"]})
        state = deepcopy(item["state"])
    response = {"connected": bool(item["connected"]), "state": state}
    if item["connection_error"]: response["error"] = item["connection_error"]
    return response


def _release(device_id: str) -> None:
    """Close the simulator server only when no more devices use this port."""
    with LOCK:
        item = SESSIONS.pop(device_id, None)
        if item is None:
            return
        port = item.get("port")
        if any(s.get("port") == port for s in SESSIONS.values()):
            return
        server = SERVERS.pop(port, None)
    if server is not None:
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass


def on_device_deleted(device_context: dict[str, Any]) -> None:
    _release(_id(device_context))


def on_device_updated(device_context: dict[str, Any], _previous_device_context: dict[str, Any] | None = None) -> None:
    device_id = _id(device_context)
    with LOCK:
        old_item = SESSIONS.get(device_id)
        old_port = old_item.get("port") if old_item else None
    new_item = _session(device_context)
    new_item["device_type"] = _type(device_context)
    new_item["capabilities"] = _caps(device_context, new_item["device_type"])
    new_port = _port(device_context)
    if old_port and old_port != new_port:
        _release(device_id)
        new_item = _session(device_context)
    _start(new_item)
