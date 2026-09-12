"""Windows 逆向分析 Python Agent 脚本

用法:
    python -m fridapilot.scripts.windows_agent --target YourApp.exe
    python -m fridapilot.scripts.windows_agent --target 1234
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import frida

SCRIPT_DIR = Path(__file__).parent.parent / "templates" / "windows"


def on_message(message: dict, data) -> None:
    if message["type"] == "send":
        p = message.get("payload", {})
        t = p.get("type", "raw") if isinstance(p, dict) else "raw"
        if t == "win_crypto":
            print(f"  [Crypto] {p['api']} status={p.get('status')}")
        elif t == "registry":
            print(f"  [Registry] {p['op']} {p.get('key','')}")
        elif t == "file":
            print(f"  [File] {p['op']} {p.get('path','')} {p.get('access','')}")
        elif t == "network":
            print(f"  [Network] {p['op']} {p.get('ip','')}{p.get('method','')}:{p.get('port','')}{p.get('path','')}")
        elif t == "antidebug":
            print(f"  [AntiDebug] {p['api']} bypassed")
        else:
            print(f"  [{t}] {p}")
    elif message["type"] == "error":
        print(f"  [ERROR] {message.get('description', message)}")


def main():
    parser = argparse.ArgumentParser(description="FridaPilot Windows Reverse Engineering Agent")
    parser.add_argument("--target", "-t", required=True, help="Process name or PID")
    parser.add_argument("--spawn", action="store_true", help="Spawn instead of attach")
    parser.add_argument("--timeout", type=int, default=0)
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

    print("[*] Monitoring Windows app... Press Ctrl+C to stop.\n")
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
