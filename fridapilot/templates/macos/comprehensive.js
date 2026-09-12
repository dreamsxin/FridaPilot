// macOS 全面逆向分析脚本 - Keychain/网络/权限/签名/系统调用
// FridaPilot - macOS Comprehensive Reverse Engineering

if (ObjC.available) {
    console.log('[FridaPilot] macOS Reverse Engineering Script Loaded');

    // ══════════════════════════════════════════
    // 1. Keychain 操作监控
    // ══════════════════════════════════════════
    ['SecItemAdd','SecItemCopyMatching','SecItemUpdate','SecItemDelete'].forEach(fn => {
        var addr = Module.findExportByName('Security', fn);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter(args) {
                    send({ type: 'keychain', op: fn });
                },
                onLeave(retval) {
                    send({ type: 'keychain', op: fn, result: retval.toInt32() });
                }
            });
        }
    });

    // ══════════════════════════════════════════
    // 2. NSURLSession 网络请求
    // ══════════════════════════════════════════
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        var dataTask = NSURLSession['- dataTaskWithRequest:completionHandler:'];
        if (dataTask) {
            Interceptor.attach(dataTask.implementation, {
                onEnter(args) {
                    var req = ObjC.Object(args[2]);
                    send({ type: 'network', api: 'NSURLSession',
                           url: req.URL().absoluteString().toString(),
                           method: req.HTTPMethod().toString() });
                }
            });
        }
    } catch(e) {}

    // ══════════════════════════════════════════
    // 3. NSTask / Process 命令执行
    // ══════════════════════════════════════════
    try {
        var NSTask = ObjC.classes.NSTask;
        if (NSTask) {
            Interceptor.attach(NSTask['- launch'].implementation, {
                onEnter(args) {
                    var task = ObjC.Object(args[0]);
                    send({
                        type: 'exec', api: 'NSTask',
                        launchPath: task.launchPath().toString(),
                        args: task.arguments() ? task.arguments().toString() : ''
                    });
                }
            });
        }
    } catch(e) {}

    // ══════════════════════════════════════════
    // 4. 文件操作监控
    // ══════════════════════════════════════════
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        Interceptor.attach(NSFileManager['- contentsOfDirectoryAtPath:error:'].implementation, {
            onEnter(args) {
                send({ type: 'file', op: 'listDir', path: ObjC.Object(args[2]).toString() });
            }
        });
    } catch(e) {}

    // open() syscall
    var openFunc = Module.findExportByName('libSystem.B.dylib', 'open');
    if (openFunc) {
        Interceptor.attach(openFunc, {
            onEnter(args) {
                send({ type: 'file', op: 'open', path: args[0].readUtf8String(), flags: args[1].toInt32() });
            }
        });
    }

    // ══════════════════════════════════════════
    // 5. 代码签名检查
    // ══════════════════════════════════════════
    var csOps = Module.findExportByName(null, 'csops');
    if (csOps) {
        Interceptor.attach(csOps, {
            onEnter(args) {
                send({ type: 'codesign', op: 'csops', callsite: args[1].toInt32() });
            }
        });
    }

    // ══════════════════════════════════════════
    // 6. CommonCrypto 加密监控
    // ══════════════════════════════════════════
    var ccCrypt = Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt');
    if (ccCrypt) {
        Interceptor.attach(ccCrypt, {
            onEnter(args) {
                send({
                    type: 'crypto', api: 'CCCrypt',
                    op: args[0].toInt32() === 0 ? 'encrypt' : 'decrypt',
                    algo: args[1].toInt32(),
                    keySize: args[4].toInt32()
                });
            }
        });
    }

    console.log('[FridaPilot] macOS hooks loaded');
}
