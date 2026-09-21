"""fp electron-agent - Electron 监控（H-T2 通道重设计：CDP 为主、preload 兜底）。

用法:
    python -m fridapilot.scripts.electron_agent --app "C:\\path\\app.exe" [--args "..."]
    python -m fridapilot.scripts.electron_agent --cdp-url ws://127.0.0.1:9222/... （目标已自行开启调试端口）
    python -m fridapilot.scripts.electron_agent --app ... --channel preload

通道:
    cdp      默认。spawn 时追加 --remote-debugging-port=0，经 CDP 在主进程/
             渲染进程真实 JS 上下文安装钩子（主进程 require 可用）。
    preload  回退：NODE_OPTIONS=--require 注入 preload_monitor.cjs（受目标
             Fuses 制约，NodeOptions=DISABLE 时被静默忽略——因此必须等待
             health 消息确认，未收到即明确告警，绝不假装在监控）。

健康检查（H-T2 教训的直接对策）：钩子安装后模板回传 health 消息，
agent 校验钩子计数后才打印 Monitoring；失败时打印明确原因。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

TEMPLATES = Path(__file__).parent.parent / "templates" / "electron"
STDOUT_PREFIX = "__FPLINE__"
CONSOLE_PREFIX = "__FP__"

# 模板回传的 payload type → 显示标签（与旧版输出格式兼容）
LABELS = {
    "ipc_main_on": "IPC ← on",
    "ipc_main_handle": "IPC ← handle registered",
    "ipc_main_call": "IPC ← call",
    "ipc_renderer": "IPC →",
    "ipc_renderer_listen": "IPC → listening",
    "context_bridge": "Bridge",
    "browser_window": "Window",
    "electron_fuses": "Fuses",
    "electron_package": "Package",
    "electron_app_path": "AppPath",
    "asar_contents": "ASAR",
    "node_fs": "fs",
    "node_child_process": "exec",
    "node_http": "http",
    "renderer_ready": "Renderer ready",
    "renderer_skip": "Renderer skipped",
    "hook_error": "HOOK ERROR",
    "health": "HEALTH",
}


def _print_payload(payload: dict) -> None:
    t = payload.get("type", "?")
    label = LABELS.get(t, f"[{t}]")
    if t in ("ipc_main_on", "ipc_main_handle"):
        print(f"  [{label}] {payload.get('channel', '')}")
    elif t == "ipc_main_call":
        print(f"  [{label}] {payload.get('channel', '')} args={payload.get('args', '')}")
    elif t == "ipc_renderer":
        print(f"  [{label}] {payload.get('method', '')}({payload.get('channel', '')}) args={payload.get('args', '')}")
    elif t == "context_bridge":
        print(f"  [{label}] {payload.get('apiKey', '')}: {payload.get('methods', [])}")
    elif t == "browser_window":
        print(f"  [{label}] {payload.get('action', '')}: {payload.get('url', payload.get('path', ''))}")
    elif t == "electron_fuses":
        print(f"  [{label}] at {payload.get('offset', '')}: {payload.get('details', payload.get('fuses', ''))}")
    elif t == "health":
        print(f"  [{label}] hooks={payload.get('hooks', [])}")
    else:
        print(f"  [{label}] {payload}")


def _print_health_verdict(health: dict | None, source: str) -> bool:
    """健康检查（H-T2 教训对策）：钩子计数不达标就明说，绝不打印 Monitoring。"""
    if not health:
        print(f"[!] 未收到 {source} 通道的 health 消息 —— 目标可能阻止了该通道，"
              "不要相信本次监控输出。")
        return False
    hooks = health.get("hooks", [])
    missed = [h for h in hooks if h.endswith(":miss")]
    print(f"[*] 健康检查：{len(hooks) - len(missed)}/{len(hooks)} 个钩子安装成功")
    if missed:
        print(f"[!] 未安装：{', '.join(missed)}")
    return len(hooks) > 0 and not missed


def _spawn_and_find_ws(app: str, app_args: str, timeout: float) -> tuple[subprocess.Popen, str]:
    """Spawn the target with a free debugging port, then poll the HTTP
    endpoint (/json/version). Chromium/Electron launchers sometimes hand
    off to a child process, which makes the stderr line unreliable."""
    port = cdp_client.find_free_port()
    cmd = [app] + (app_args.split() if app_args else []) + \
        [f"--remote-debugging-port={port}", "--no-first-run"]
    print(f"[*] Spawning: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")
    version = cdp_client.wait_for_endpoint(port, timeout=timeout)
    if version is None:
        raise RuntimeError("DevTools HTTP 端点未就绪 —— 目标可能不是 "
                           "Electron/Chromium，或调试端口被禁用。")
    ws = version.get("webSocketDebuggerUrl")
    if not ws:
        raise RuntimeError("DevTools 端点缺少 webSocketDebuggerUrl。")
    return proc, ws


def run_cdp(args) -> int:
    from fridapilot.tools import cdp_client

    proc = None
    ws_url = args.cdp_url
    if not ws_url:
        if not args.app:
            print("[!] 需要 --app（由 agent 启动以开启调试端口）或 --cdp-url（目标已自行开启时）")
            return 1
        try:
            proc, ws_url = _spawn_and_find_ws(args.app, args.app_args, timeout=20.0)
        except RuntimeError as exc:
            print(f"[!] {exc}")
            return 1
        print(f"[*] DevTools endpoint: {ws_url}")

    conn = cdp_client.CDPConnection(ws_url)
    state: dict = {"main_sid": None, "health": None, "seen": set(),
                   "main_src": (TEMPLATES / "cdp_main_hooks.js").read_text(encoding="utf-8"),
                   "renderer_src": (TEMPLATES / "cdp_renderer_hooks.js").read_text(encoding="utf-8")}

    def on_console(msg: dict) -> None:
        if msg.get("sessionId") != state["main_sid"]:
            return
        params = msg.get("params", {})
        for a in params.get("args", []):
            v = a.get("value", a.get("description", ""))
            if isinstance(v, str) and v.startswith(CONSOLE_PREFIX):
                try:
                    payload = json.loads(v[len(CONSOLE_PREFIX):])
                except Exception:
                    continue
                _print_payload(payload)
                if payload.get("type") == "health":
                    state["health"] = payload

    conn.on_event("Runtime.consoleAPICalled", on_console)

    def attach_and_inject() -> None:
        m = re.match(r"ws://([^:/]+):(\d+)", ws_url)
        host, port = (m.group(1), int(m.group(2))) if m else ("127.0.0.1", 0)
        for tgt in cdp_client.list_targets(port, host):
            tid = tgt["targetId"]
            if tid in state["seen"]:
                continue
            state["seen"].add(tid)
            result = conn.call("Target.attachToTarget", {"targetId": tid, "flatten": True})
            sid = result["sessionId"]
            at = cdp_client.AttachedTarget(conn, tid, sid)
            at.enable_runtime()
            ptype = cdp_client.probe_process_type(conn, sid)
            if ptype == "browser":
                at.evaluate(state["main_src"])
                state["main_sid"] = sid
                print(f"[*] 主进程已注入（target {tid[:12]}…）")
            else:
                at.evaluate(state["renderer_src"])
                print(f"[*] 渲染进程已注入（target {tid[:12]}…，尽力而为）")

    try:
        attach_and_inject()
    except Exception as exc:
        print(f"[!] 注入失败：{exc}")
        return 1
    if not state["main_sid"]:
        print("[!] 未找到 Electron 主进程 target —— 目标可能不是 Electron 应用。")
        return 1

    # 健康检查：主进程模板注入后经 console 回传 health
    deadline = time.time() + 10
    while state["health"] is None and time.time() < deadline:
        time.sleep(0.2)
    if not _print_health_verdict(state["health"], "cdp"):
        conn.close()
        return 1

    print("[*] Monitoring Electron app... Press Ctrl+C to stop.\n")
    try:
        deadline = time.time() + args.timeout if args.timeout > 0 else None
        while True:
            time.sleep(1)
            try:
                attach_and_inject()  # 渲染进程可能晚开（轮询补注入）
            except Exception:
                pass
            if deadline is not None and time.time() > deadline:
                break
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        if proc is not None and proc.poll() is None:
            print("[*] 目标进程仍在运行（由你启动，交还控制权）。")
    return 0


def run_preload(args) -> int:
    preload = TEMPLATES / "preload_monitor.cjs"
    if not preload.exists():
        print(f"[!] preload 模板缺失：{preload}")
        return 1
    if not args.app:
        print("[!] preload 通道必须由 agent 启动目标：需要 --app")
        return 1
    env = os.environ.copy()
    env["NODE_OPTIONS"] = f'--require "{preload}"'
    cmd = [args.app] + (args.app_args.split() if args.app_args else [])
    print(f"[*] Spawning with NODE_OPTIONS preload: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace")
    state: dict = {"health": None}

    def _read_stdout() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            if line.startswith(STDOUT_PREFIX):
                try:
                    payload = json.loads(line[len(STDOUT_PREFIX):])
                except Exception:
                    continue
                _print_payload(payload)
                if payload.get("type") == "health":
                    state["health"] = payload
            else:
                print(f"  [app] {line}")

    threading.Thread(target=_read_stdout, daemon=True).start()
    deadline = time.time() + 15
    print("[*] Waiting for preload health message...")
    while state["health"] is None and time.time() < deadline and proc.poll() is None:
        time.sleep(0.2)

    if not _print_health_verdict(state["health"], "preload"):
        print("[!] 可能原因：目标 Fuses 已禁用 NodeOptions/RunAsNode（preload 被静默忽略）。"
              "改用 --channel cdp。")
        return 1

    print("[*] Monitoring Electron app... Press Ctrl+C to stop.\n")
    try:
        while proc.poll() is None:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        print("[*] Done.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FridaPilot Electron Reverse Engineering Agent (H-T2 channels: CDP primary / preload fallback)")
    parser.add_argument("--app", help="Electron 可执行文件或应用目录（由 agent 启动目标）")
    parser.add_argument("--app-args", default="", help="透传给目标应用的额外参数")
    parser.add_argument("--channel", choices=["cdp", "preload"], default="cdp",
                        help="cdp=CDP 注入（默认，全功能）；preload=NODE_OPTIONS 兜底（受 Fuses 制约）")
    parser.add_argument("--cdp-url", help="目标已自行开启调试端口时直接给出 ws:// 地址（免 spawn）")
    parser.add_argument("--timeout", type=int, default=0, help="Seconds to observe (0 = until Ctrl+C).")
    args = parser.parse_args()
    return run_cdp(args) if args.channel == "cdp" else run_preload(args)


if __name__ == "__main__":
    sys.exit(main())
