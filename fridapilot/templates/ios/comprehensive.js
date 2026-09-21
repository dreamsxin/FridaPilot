// iOS 全面逆向分析脚本 - ViewController/Keychain/网络/越狱检测
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
// FridaPilot - iOS Comprehensive Reverse Engineering

if (typeof ObjC !== "undefined" && ObjC.available) {
    console.log('[FridaPilot] iOS Reverse Engineering Script Loaded');

    // ══════════════════════════════════════════
    // 1. ViewController 生命周期
    // ══════════════════════════════════════════
    try {
        const UIViewController = ObjC.classes.UIViewController;
        ['viewDidLoad','viewWillAppear:','viewDidAppear:','viewWillDisappear:'].forEach(sel => {
            const method = UIViewController['- ' + sel];
            if (method) {
                Interceptor.attach(method.implementation, {
                    onEnter(args) {
                        const self = ObjC.Object(args[0]);
                        send({ type: 'viewcontroller', method: sel, class: self.$className });
                    }
                });
            }
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 2. Keychain 读写监控
    // ══════════════════════════════════════════
    try {
        Interceptor.attach(fpFindExport('Security','SecItemAdd'), {
            onEnter(args) { send({ type: 'keychain', op: 'SecItemAdd' }); }
        });
        Interceptor.attach(fpFindExport('Security','SecItemCopyMatching'), {
            onEnter(args) { send({ type: 'keychain', op: 'SecItemCopyMatching' }); },
            onLeave(retval) {
                send({ type: 'keychain', op: 'SecItemCopyMatching', result: retval.toInt32() });
            }
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 3. NSURLSession 网络请求
    // ══════════════════════════════════════════
    try {
        const NSURLSession = ObjC.classes.NSURLSession;
        const dataTask = NSURLSession['- dataTaskWithRequest:completionHandler:'];
        if (dataTask) {
            Interceptor.attach(dataTask.implementation, {
                onEnter(args) {
                    const req = ObjC.Object(args[2]);
                    send({ type: 'network', api: 'NSURLSession',
                           url: req.URL().absoluteString().toString(),
                           method: req.HTTPMethod().toString() });
                }
            });
        }
    } catch(e) {}

    // ══════════════════════════════════════════
    // 4. CommonCrypto 监控
    // ══════════════════════════════════════════
    try {
        Interceptor.attach(fpFindExport('libcommonCrypto.dylib','CCCrypt'), {
            onEnter(args) {
                send({
                    type: 'crypto', api: 'CCCrypt',
                    op: args[0].toInt32() === 0 ? 'encrypt' : 'decrypt',
                    algo: args[1].toInt32(), // 0=AES, 1=DES, 2=3DES
                    keySize: args[4].toInt32(),
                    dataSize: args[6].toInt32()
                });
            }
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 5. 越狱检测绕过
    // ══════════════════════════════════════════
    try {
        const NSFileManager = ObjC.classes.NSFileManager;
        const origExists = NSFileManager['- fileExistsAtPath:'];
        Interceptor.attach(origExists.implementation, {
            onEnter(args) {
                this.path = ObjC.Object(args[2]).toString();
            },
            onLeave(retval) {
                const jbPaths = ['/Applications/Cydia.app','/usr/sbin/sshd','/bin/bash',
                    '/etc/apt','/private/var/lib/apt','/Library/MobileSubstrate','/usr/bin/ssh'];
                if (jbPaths.some(p => this.path.includes(p))) {
                    send({ type: 'bypass', detail: 'Jailbreak check bypassed: ' + this.path });
                    retval.replace(ptr(0));
                }
            }
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 6. UserDefaults 监控
    // ══════════════════════════════════════════
    try {
        const NSUserDefaults = ObjC.classes.NSUserDefaults;
        Interceptor.attach(NSUserDefaults['- objectForKey:'].implementation, {
            onEnter(args) { this.key = ObjC.Object(args[2]).toString(); },
            onLeave(retval) {
                if (!retval.isNull()) {
                    send({ type: 'userdefaults', op: 'get', key: this.key,
                           value: ObjC.Object(retval).toString().substring(0, 200) });
                }
            }
        });
    } catch(e) {}

    console.log('[FridaPilot] iOS hooks loaded');
}
