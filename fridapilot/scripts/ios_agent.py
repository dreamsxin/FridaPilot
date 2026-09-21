"""iOS 逆向分析 Python Agent 脚本

用法:
    python -m fridapilot.scripts.ios_agent --target YourApp --device usb
    python -m fridapilot.scripts.ios_agent --target YourApp --device usb --spawn
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import frida

SCRIPT_DIR = Path(__file__).parent.parent / "templates" / "ios"


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
        elif t in ("lifecycle", "viewcontroller"):
            print(f"  [Lifecycle] {p.get('method')} → {p.get('class','')}")
        elif t == "bypass":
            print(f"  [Bypass] {p.get('detail')}")
        elif t == "userdefaults":
            print(f"  [UserDefaults] {p.get('op')} {p.get('key','')}={str(p.get('value',''))[:80]}")
        else:
            print(f"  [{t}] {p}")
    elif message["type"] == "error":
        print(f"  [ERROR] {message.get('description', message)}")


def main():
    parser = argparse.ArgumentParser(description="FridaPilot iOS Reverse Engineering Agent")
    parser.add_argument("--target", "-t", required=True, help="App name or PID")
    parser.add_argument("--device", "-d", default="usb", choices=["local", "usb", "remote"])
    parser.add_argument("--host", default="", help="Remote frida-server host:port")
    parser.add_argument("--spawn", action="store_true", help="Spawn instead of attach")
    parser.add_argument("--timeout", type=int, default=0, help="Seconds to run (0=until Ctrl+C)")
    parser.add_argument("--bypass", action="store_true", help="Also inject hardening bypass script")
    args = parser.parse_args()

    if args.device == "usb":
        device = frida.get_usb_device()
    elif args.device == "remote":
        device = frida.get_device_manager().add_remote_device(args.host)
    else:
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

    # Inject hardening bypass first if requested
    if args.bypass:
        bypass_path = SCRIPT_DIR / "hardening_bypass.js"
        if bypass_path.exists():
            bypass_source = bypass_path.read_text(encoding="utf-8")
            bypass_script = session.create_script(bypass_source)
            bypass_script.on("message", on_message)
            bypass_script.load()
            print("[*] Hardening bypass injected (jailbreak/Frida/SSL)")

    source = (SCRIPT_DIR / "comprehensive.js").read_text(encoding="utf-8")
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()

    if args.spawn:
        device.resume(pid)
        print("[*] Resumed")

    print("[*] Monitoring iOS app... Press Ctrl+C to stop.\n")
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
