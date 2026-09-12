"""Electron 逆向分析 Python Agent 脚本

用法:
    python -m fridapilot.scripts.electron_agent --target "YourApp.exe"
    python -m fridapilot.scripts.electron_agent --target "YourApp.exe" --devtools
    python -m fridapilot.scripts.electron_agent --target "YourApp.exe" --dump-asar

功能:
    - 自动识别 Electron 主进程 / 渲染进程
    - IPC 通信完整监控 (ipcRenderer + ipcMain)
    - contextBridge API 枚举
    - BrowserWindow 安全配置检测
    - Electron Fuses 检测
    - asar 包内容枚举
    - Node.js 模块调用监控 (fs/child_process/crypto/net)
    - 强制打开 DevTools
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import frida


def on_message(message: dict, data) -> None:
    """Handle Frida messages with structured output."""
    if message["type"] == "send":
        payload = message.get("payload", {})
        msg_type = payload.get("type", "unknown") if isinstance(payload, dict) else "raw"

        if msg_type == "ipc_renderer":
            print(f"  [IPC →] {payload['method']}({payload['channel']}) args={payload.get('args','')}")
        elif msg_type == "ipc_main_call":
            print(f"  [IPC ←] handle({payload['channel']}) args={payload.get('args','')}")
        elif msg_type == "ipc_main_on":
            print(f"  [IPC ←] on({payload['channel']})")
        elif msg_type == "ipc_main_handle":
            print(f"  [IPC ←] handle registered: {payload['channel']}")
        elif msg_type == "ipc_renderer_listen":
            print(f"  [IPC →] listening: {payload['channel']}")
        elif msg_type == "context_bridge":
            print(f"  [Bridge] {payload['apiKey']}: {payload.get('methods', [])}")
        elif msg_type == "browser_window":
            print(f"  [Window] {payload['action']}: {payload.get('url', payload.get('path', ''))}")
            if "webPreferences" in payload:
                prefs = payload["webPreferences"]
                print(f"           nodeIntegration={prefs.get('nodeIntegration')}, "
                      f"contextIsolation={prefs.get('contextIsolation')}, "
                      f"sandbox={prefs.get('sandbox')}")
        elif msg_type == "electron_fuses":
            print(f"  [Fuses] at {payload['offset']}:")
            for k, v in payload.get("details", {}).items():
                status = "✓" if v == "enabled" else "✗"
                print(f"    {status} {k}: {v}")
        elif msg_type == "electron_package":
            print(f"  [Package] {payload.get('name')} v{payload.get('version')}")
            print(f"    main: {payload.get('main')}")
            print(f"    deps: {payload.get('dependencies', [])}")
        elif msg_type == "asar_contents":
            print(f"  [ASAR] top-level: {payload.get('topLevel', [])}")
        elif msg_type == "node_fs":
            print(f"  [fs] {payload['fn']}({payload.get('path', '')})")
        elif msg_type == "node_child_process":
            print(f"  [exec] {payload['fn']}({payload.get('cmd', '')})")
        elif msg_type == "node_crypto":
            print(f"  [crypto] {payload['op']} algo={payload.get('algorithm')}")
        elif msg_type == "node_http":
            print(f"  [http] {payload.get('method')} {payload.get('host')}{payload.get('path')}")
        else:
            print(f"  [{msg_type}] {payload}")
    elif message["type"] == "error":
        print(f"  [ERROR] {message.get('description', message)}")


def load_script(session: frida.core.Session, script_path: str) -> frida.core.Script:
    """Load and inject a Frida script."""
    source = Path(script_path).read_text(encoding="utf-8")
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    return script


def find_electron_processes(device: frida.core.Device) -> list[dict]:
    """Find all Electron-related processes."""
    procs = device.enumerate_processes()
    electron_names = ["electron", "Electron"]
    results = []
    for p in procs:
        name_lower = p.name.lower()
        if any(e.lower() in name_lower for e in electron_names):
            results.append({"pid": p.pid, "name": p.name, "type": "electron_framework"})
        # Most Electron apps have their own name
        # We'll let the user specify the target
    return results


def main():
    parser = argparse.ArgumentParser(description="FridaPilot Electron Reverse Engineering Agent")
    parser.add_argument("--target", "-t", required=True, help="Process name or PID")
    parser.add_argument("--device", "-d", default="local", choices=["local", "usb", "remote"])
    parser.add_argument("--host", default="", help="Remote frida-server host:port")
    parser.add_argument("--devtools", action="store_true", help="Force open DevTools")
    parser.add_argument("--dump-asar", action="store_true", help="Dump asar package contents")
    parser.add_argument("--timeout", type=int, default=0, help="Seconds to run (0=until Ctrl+C)")
    args = parser.parse_args()

    # Connect
    if args.device == "usb":
        device = frida.get_usb_device()
    elif args.device == "remote":
        device = frida.get_device_manager().add_remote_device(args.host)
    else:
        device = frida.get_local_device()

    # Attach
    try:
        pid = int(args.target)
        session = device.attach(pid)
    except ValueError:
        session = device.attach(args.target)

    print(f"[*] Attached to {args.target}")

    # Load comprehensive Electron script
    script_dir = Path(__file__).parent.parent / "templates" / "electron"
    script = load_script(session, str(script_dir / "comprehensive.js"))

    if args.devtools:
        script.exports_sync  # ensure loaded
        print("[*] DevTools force-open requested (will trigger on next BrowserWindow)")

    print("[*] Monitoring Electron app... Press Ctrl+C to stop.\n")

    try:
        if args.timeout > 0:
            time.sleep(args.timeout)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
    finally:
        script.unload()
        session.detach()
        print("[*] Detached.")


if __name__ == "__main__":
    main()
