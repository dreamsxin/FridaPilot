// iOS 加固绕过脚本 - 越狱检测/Frida检测/代码签名/SSL Pinning增强/反调试
// Frida 16/17 compat: static Module lookup APIs were removed in Frida 17.
function fpFindExport(moduleName, exportName) {
    if (typeof Module.getGlobalExportByName === "function") {
        if (moduleName) {
            const mod = Process.findModuleByName(moduleName);
            return mod ? mod.findExportByName(exportName) : null;
        }
        try { return Module.getGlobalExportByName(exportName); } catch (e) { return null; }
    }
    return Module.findExportByName(moduleName, exportName);
}
function fpFindModule(moduleName) {
    if (typeof Process.findModuleByName === "function") return Process.findModuleByName(moduleName);
    return Module.findModuleByName(moduleName);
}
// FridaPilot - iOS Hardening Bypass

if (typeof ObjC !== "undefined" && ObjC.available) {
    console.log('[FridaPilot] iOS Hardening Bypass Loaded');

    // ══════════════════════════════════════════
    // 1. 越狱检测绕过 (全面)
    // ══════════════════════════════════════════
    var jbPaths = [
        '/Applications/Cydia.app', '/Library/MobileSubstrate/MobileSubstrate.dylib',
        '/bin/bash', '/usr/sbin/sshd', '/etc/apt', '/usr/bin/ssh',
        '/private/var/lib/apt', '/private/var/lib/cydia', '/private/var/stash',
        '/usr/libexec/sftp-server', '/usr/bin/cycript', '/usr/local/bin/cycript',
        '/usr/lib/libcycript.dylib', '/var/cache/apt', '/var/lib/apt',
        '/var/lib/cydia', '/var/tmp/cydia.log', '/Applications/Sileo.app',
        '/var/jb', '/var/binpack', // rootless jailbreak
    ];

    // 1a. NSFileManager.fileExistsAtPath:
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
            onEnter(args) { this.path = ObjC.Object(args[2]).toString(); },
            onLeave(retval) {
                if (jbPaths.some(p => this.path.includes(p))) {
                    send({ type: 'jb_bypass', method: 'fileExistsAtPath', path: this.path });
                    retval.replace(ptr(0));
                }
            }
        });
    } catch(e) {}

    // 1b. C-level access/stat/open
    ['access', 'stat', 'lstat', 'open'].forEach(fn => {
        try {
            Interceptor.attach(fpFindExport(null, fn), {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    if (this.path && jbPaths.some(p => this.path.includes(p))) {
                        send({ type: 'jb_bypass', method: fn, path: this.path });
                        retval.replace(ptr(-1));
                    }
                }
            });
        } catch(e) {}
    });

    // 1c. canOpenURL (cydia://)
    try {
        var UIApplication = ObjC.classes.UIApplication;
        Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
            onEnter(args) {
                this.url = ObjC.Object(args[2]).absoluteString().toString();
            },
            onLeave(retval) {
                if (this.url && (this.url.includes('cydia://') || this.url.includes('sileo://'))) {
                    send({ type: 'jb_bypass', method: 'canOpenURL', url: this.url });
                    retval.replace(ptr(0));
                }
            }
        });
    } catch(e) {}

    // 1d. fork() check (jailbroken devices can fork)
    try {
        Interceptor.attach(fpFindExport(null, 'fork'), {
            onLeave(retval) {
                send({ type: 'jb_bypass', method: 'fork', detail: 'returning -1' });
                retval.replace(ptr(-1));
            }
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 2. Frida 检测绕过
    // ══════════════════════════════════════════

    // 2a. 端口扫描检测 (27042)
    try {
        Interceptor.attach(fpFindExport(null, 'connect'), {
            onEnter(args) {
                var sockaddr = args[1];
                var family = sockaddr.readU16();
                if (family === 2) {
                    var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                    if (port === 27042 || port === 27043) {
                        send({ type: 'frida_bypass', method: 'connect', port: port });
                        // Change port to prevent detection
                        sockaddr.add(2).writeU8(0);
                        sockaddr.add(3).writeU8(0);
                    }
                }
            }
        });
    } catch(e) {}

    // 2b. dyld 镜像名检测
    try {
        var _dyld_get_image_name = fpFindExport(null, '_dyld_get_image_name');
        Interceptor.attach(_dyld_get_image_name, {
            onLeave(retval) {
                var name = retval.readUtf8String();
                if (name && (name.includes('frida') || name.includes('FridaGadget'))) {
                    send({ type: 'frida_bypass', method: 'dyld_image_name', name: name });
                    retval.replace(Memory.allocUtf8String('/usr/lib/libSystem.B.dylib'));
                }
            }
        });
    } catch(e) {}

    // 2c. strstr 隐藏 frida 字符串
    try {
        Interceptor.attach(fpFindExport(null, 'strstr'), {
            onEnter(args) { this.needle = args[1].readCString(); },
            onLeave(retval) {
                if (this.needle && ['frida', 'LIBFRIDA', 'gum-js-loop', 'gmain'].some(k => this.needle.includes(k))) {
                    retval.replace(ptr(0));
                }
            }
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 3. 反调试绕过
    // ══════════════════════════════════════════
    // sysctl 检测
    try {
        Interceptor.attach(fpFindExport(null, 'sysctl'), {
            onEnter(args) {
                this.mib = args[0];
                this.size = args[1].readU32();
                this.info = args[2];
            },
            onLeave(retval) {
                // CTL_KERN, KERN_PROC, KERN_PROC_PID
                if (this.size >= 4) {
                    var mib0 = this.mib.readS32();
                    var mib1 = this.mib.add(4).readS32();
                    if (mib0 === 1 && mib1 === 14) { // CTL_KERN, KERN_PROC
                        // Clear P_TRACED flag
                        var flagsOffset = Process.pointerSize === 8 ? 32 : 16;
                        var flags = this.info.add(flagsOffset).readS32();
                        if (flags & 0x800) { // P_TRACED
                            this.info.add(flagsOffset).writeS32(flags & ~0x800);
                            send({ type: 'antidebug_bypass', method: 'sysctl P_TRACED cleared' });
                        }
                    }
                }
            }
        });
    } catch(e) {}

    // ptrace
    try {
        Interceptor.attach(fpFindExport(null, 'ptrace'), {
            onEnter(args) { this.req = args[0].toInt32(); },
            onLeave(retval) {
                if (this.req === 31) { // PT_DENY_ATTACH
                    send({ type: 'antidebug_bypass', method: 'PT_DENY_ATTACH bypassed' });
                    retval.replace(ptr(0));
                }
            }
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 4. SSL Pinning 增强版绕过
    // ══════════════════════════════════════════
    // AFNetworking
    try {
        var AFSecPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecPolicy) {
            Interceptor.attach(AFSecPolicy['- setSSLPinningMode:'].implementation, {
                onEnter(args) { args[2] = ptr(0); } // AFSSLPinningModeNone
            });
            send({ type: 'ssl_bypass', framework: 'AFNetworking' });
        }
    } catch(e) {}

    // Alamofire / URLSession delegate
    try {
        var resolver = ObjC.classes['NSURLSessionConfiguration'];
        if (resolver) {
            Interceptor.attach(resolver['- setTLSMinimumSupportedProtocol:'].implementation, {
                onEnter(args) {} // Allow all protocols
            });
        }
    } catch(e) {}

    // TrustKit
    try {
        var TrustKit = ObjC.classes['TSKPinningValidator'];
        if (TrustKit) {
            Interceptor.attach(TrustKit['- evaluateTrust:forHostname:'].implementation, {
                onLeave(retval) {
                    retval.replace(ptr(0)); // TSKTrustDecisionShouldAllowConnection
                    send({ type: 'ssl_bypass', framework: 'TrustKit' });
                }
            });
        }
    } catch(e) {}

    console.log('[FridaPilot] iOS hardening bypass loaded');
}
