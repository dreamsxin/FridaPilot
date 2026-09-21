"""macOS 逆向分析 Python Agent 脚本

用法:
    python -m fridapilot.scripts.macos_agent --target YourApp
    python -m fridapilot.scripts.macos_agent --target YourApp --spawn
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import frida


SCRIPT_DIR = Path(__file__).parent.parent / "templates" / "macos"


def on_message(message: dict, data) -> None:
    if message["type"] == "send":
        p = message.get("payload", {})
        t = p.get("type", "raw") if isinstance(p, dict) else "raw"
        if t == "keychain":
            print(f"  [Keychain] {p.get('op')} service={p.get('service','')} account={p.get('account','')}")
        elif t == "crypto":
            print(f"  [Crypto] {p.get('op')} algo={p.get('algo')}")
        elif t == "network":
            print(f"  [Network] {p.get('api')} {p.get('method','')} {p.get('url','')}")
        elif t in ("process", "exec"):
            print(f"  [Process] {p.get('api')} → {p.get('cmd','')}")
        elif t == "file":
            print(f"  [File] {p.get('op')} {p.get('path','')}")
        elif t == "codesign":
            print(f"  [CodeSign] {p.get('detail')}")
        else:
            print(f"  [{t}] {p}")
    elif message["type"] == "error":
        print(f"  [ERROR] {message.get('description', message)}")


def main():
    parser = argparse.ArgumentParser(description="FridaPilot macOS Reverse Engineering Agent")
    parser.add_argument("--target", "-t", required=True, help="App name or PID")
    parser.add_argument("--spawn", action="store_true", help="Spawn instead of attach")
    parser.add_argument("--timeout", type=int, default=0, help="Seconds to run (0=until Ctrl+C)")
    args = parser.parse_args()

    device = frida.get_local_device()

    if args.spawn:
        pid = device.spawn([args.target])
        session = device.attach(pid)
        print(f"[*] Spawned {args.target} (PID: {pid})")
    else:
        try:
            session = device.attach(int(args.target))
        except ValueError:
            session = device.attach(args.target)
        print(f"[*] Attached to {args.target}")

    source = (SCRIPT_DIR / "comprehensive.js").read_text(encoding="utf-8")
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()

    if args.spawn:
        device.resume(pid)
        print("[*] Resumed")

    print("[*] Monitoring macOS app... Press Ctrl+C to stop.\n")
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
