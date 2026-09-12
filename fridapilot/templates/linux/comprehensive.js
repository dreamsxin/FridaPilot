// Linux 全面逆向分析脚本 - 系统调用/文件/网络/加密/ptrace
// FridaPilot - Linux Comprehensive Reverse Engineering

console.log('[FridaPilot] Linux Reverse Engineering Script Loaded');

// ══════════════════════════════════════════
// 1. 文件操作监控
// ══════════════════════════════════════════
Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter(args) {
        this.path = args[0].readUtf8String();
        this.flags = args[1].toInt32();
    },
    onLeave(retval) {
        send({ type: 'file', op: 'open', path: this.path, flags: this.flags, fd: retval.toInt32() });
    }
});

try {
    Interceptor.attach(Module.findExportByName(null, 'openat'), {
        onEnter(args) {
            this.path = args[1].readUtf8String();
        },
        onLeave(retval) {
            send({ type: 'file', op: 'openat', path: this.path, fd: retval.toInt32() });
        }
    });
} catch(e) {}

// ══════════════════════════════════════════
// 2. 网络连接监控
// ══════════════════════════════════════════
Interceptor.attach(Module.findExportByName(null, 'connect'), {
    onEnter(args) {
        var sockaddr = args[1];
        var family = sockaddr.readU16();
        if (family === 2) { // AF_INET
            var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            var ip = [4,5,6,7].map(i => sockaddr.add(i).readU8()).join('.');
            send({ type: 'network', op: 'connect', ip: ip, port: port });
        } else if (family === 10) { // AF_INET6
            var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            send({ type: 'network', op: 'connect', family: 'IPv6', port: port });
        }
    }
});

// DNS
try {
    Interceptor.attach(Module.findExportByName(null, 'getaddrinfo'), {
        onEnter(args) {
            send({ type: 'dns', host: args[0].readUtf8String(), service: args[1].isNull() ? '' : args[1].readUtf8String() });
        }
    });
} catch(e) {}

// ══════════════════════════════════════════
// 3. 进程/命令执行
// ══════════════════════════════════════════
Interceptor.attach(Module.findExportByName(null, 'execve'), {
    onEnter(args) {
        send({ type: 'exec', op: 'execve', path: args[0].readUtf8String() });
    }
});

try {
    Interceptor.attach(Module.findExportByName(null, 'system'), {
        onEnter(args) {
            send({ type: 'exec', op: 'system', cmd: args[0].readUtf8String() });
        }
    });
} catch(e) {}

// ══════════════════════════════════════════
// 4. OpenSSL 加密监控
// ══════════════════════════════════════════
['libssl.so', 'libssl.so.3', 'libssl.so.1.1'].forEach(lib => {
    try {
        var sslWrite = Module.findExportByName(lib, 'SSL_write');
        if (sslWrite) {
            Interceptor.attach(sslWrite, {
                onEnter(args) {
                    send({ type: 'ssl', op: 'SSL_write', size: args[2].toInt32(),
                           preview: args[1].readUtf8String(Math.min(args[2].toInt32(), 100)) });
                }
            });
        }
        var sslRead = Module.findExportByName(lib, 'SSL_read');
        if (sslRead) {
            Interceptor.attach(sslRead, {
                onEnter(args) { this.buf = args[1]; this.size = args[2].toInt32(); },
                onLeave(retval) {
                    var n = retval.toInt32();
                    if (n > 0) {
                        send({ type: 'ssl', op: 'SSL_read', size: n,
                               preview: this.buf.readUtf8String(Math.min(n, 100)) });
                    }
                }
            });
        }
    } catch(e) {}
});

// ══════════════════════════════════════════
// 5. ptrace 反调试绕过
// ══════════════════════════════════════════
try {
    Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
        onEnter(args) {
            this.request = args[0].toInt32();
        },
        onLeave(retval) {
            if (this.request === 0) { // PTRACE_TRACEME
                send({ type: 'antidebug', api: 'ptrace', detail: 'PTRACE_TRACEME bypassed' });
                retval.replace(ptr(0));
            }
        }
    });
} catch(e) {}

// ══════════════════════════════════════════
// 6. dlopen 动态加载监控
// ══════════════════════════════════════════
Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter(args) {
        if (!args[0].isNull()) {
            send({ type: 'dlopen', path: args[0].readUtf8String() });
        }
    }
});

console.log('[FridaPilot] Linux hooks loaded');
