// Windows 全面逆向分析脚本 - BCrypt/CryptoAPI/注册表/文件/网络/反调试
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
// FridaPilot - Windows Comprehensive Reverse Engineering

console.log('[FridaPilot] Windows Reverse Engineering Script Loaded');

// ══════════════════════════════════════════
// 1. BCrypt 加密 API 监控
// ══════════════════════════════════════════
var bcrypt = fpFindModule('bcrypt.dll');
if (bcrypt) {
    ['BCryptEncrypt','BCryptDecrypt','BCryptGenerateSymmetricKey',
     'BCryptOpenAlgorithmProvider','BCryptDeriveKeyPBKDF2'].forEach(fn => {
        var addr = fpFindExport('bcrypt.dll', fn);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter(args) { this.fn = fn; this.args = args; },
                onLeave(retval) {
                    send({ type: 'win_crypto', api: this.fn, status: retval.toInt32() });
                }
            });
        }
    });
}

// ══════════════════════════════════════════
// 2. 注册表操作监控
// ══════════════════════════════════════════
['RegOpenKeyExW','RegQueryValueExW','RegSetValueExW','RegCreateKeyExW'].forEach(fn => {
    var addr = fpFindExport('advapi32.dll', fn);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter(args) {
                var keyName = '';
                try { keyName = args[1].readUtf16String(); } catch(e) {}
                send({ type: 'registry', op: fn, key: keyName });
            }
        });
    }
});

// ══════════════════════════════════════════
// 3. 文件操作监控
// ══════════════════════════════════════════
var createFileW = fpFindExport('kernel32.dll', 'CreateFileW');
if (createFileW) {
    Interceptor.attach(createFileW, {
        onEnter(args) {
            var path = '';
            try { path = args[0].readUtf16String(); } catch(e) {}
            var access = args[1].toInt32();
            send({ type: 'file', op: 'CreateFileW', path: path,
                   access: access === 0x80000000 ? 'READ' : access === 0x40000000 ? 'WRITE' : 'OTHER' });
        }
    });
}

// ══════════════════════════════════════════
// 4. 网络连接监控
// ══════════════════════════════════════════
var ws2 = fpFindModule('ws2_32.dll');
if (ws2) {
    var connectAddr = fpFindExport('ws2_32.dll', 'connect');
    if (connectAddr) {
        Interceptor.attach(connectAddr, {
            onEnter(args) {
                var sockaddr = args[1];
                var family = sockaddr.readU16();
                if (family === 2) { // AF_INET
                    var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                    var ip = [4,5,6,7].map(i => sockaddr.add(i).readU8()).join('.');
                    send({ type: 'network', op: 'connect', ip: ip, port: port });
                }
            }
        });
    }

    // WinHTTP
    var httpOpen = fpFindExport('winhttp.dll', 'WinHttpOpenRequest');
    if (httpOpen) {
        Interceptor.attach(httpOpen, {
            onEnter(args) {
                var verb = '', path = '';
                try { verb = args[1].readUtf16String(); } catch(e) {}
                try { path = args[2].readUtf16String(); } catch(e) {}
                send({ type: 'network', op: 'WinHttpOpenRequest', method: verb, path: path });
            }
        });
    }
}

// ══════════════════════════════════════════
// 5. 反调试检测监控
// ══════════════════════════════════════════
var isDebugger = fpFindExport('kernel32.dll', 'IsDebuggerPresent');
if (isDebugger) {
    Interceptor.attach(isDebugger, {
        onLeave(retval) {
            send({ type: 'antidebug', api: 'IsDebuggerPresent', original: retval.toInt32() });
            retval.replace(ptr(0));
        }
    });
}

var ntQueryInfo = fpFindExport('ntdll.dll', 'NtQueryInformationProcess');
if (ntQueryInfo) {
    Interceptor.attach(ntQueryInfo, {
        onEnter(args) {
            this.infoClass = args[1].toInt32();
            this.pInfo = args[2];
        },
        onLeave(retval) {
            if (this.infoClass === 7) { // ProcessDebugPort
                send({ type: 'antidebug', api: 'NtQueryInformationProcess', infoClass: 'ProcessDebugPort' });
                this.pInfo.writePointer(ptr(0));
            }
        }
    });
}

console.log('[FridaPilot] Windows hooks loaded');
