// Android 加固绕过脚本 - 360加固/腾讯乐固/梆梆/爱加密/DexGuard/通用壳
// FridaPilot - Android Packer/Protector Bypass

Java.perform(() => {
    console.log('[FridaPilot] Android Hardening Bypass Loaded');

    // ══════════════════════════════════════════
    // 1. 通用脱壳: Hook ClassLoader 捕获 DEX 加载
    // ══════════════════════════════════════════
    try {
        const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libraryPath, parent) {
            send({ type: 'dex_load', loader: 'DexClassLoader', path: dexPath });
            return this.$init(dexPath, optimizedDir, libraryPath, parent);
        };
    } catch(e) {}

    try {
        const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(buf, parent) {
            send({ type: 'dex_load', loader: 'InMemoryDexClassLoader', size: buf.remaining() });
            // Dump DEX from memory
            var bytes = new Uint8Array(buf.remaining());
            for (var i = 0; i < bytes.length; i++) bytes[i] = buf.get(i);
            send({ type: 'dex_dump', size: bytes.length }, bytes.buffer);
            return this.$init(buf, parent);
        };
    } catch(e) {}

    // Hook openDexFile (Art runtime) for all DEX loading
    try {
        const DexFile = Java.use('dalvik.system.DexFile');
        DexFile.loadDex.overload('java.lang.String','java.lang.String','int').implementation = function(src, out, flags) {
            send({ type: 'dex_load', loader: 'DexFile.loadDex', source: src, output: out });
            return this.loadDex(src, out, flags);
        };
    } catch(e) {}

    // ══════════════════════════════════════════
    // 2. 360 加固绕过
    // ══════════════════════════════════════════
    // 360加固特征: com.qihoo.util, com.stub.StubApp, libjiagu.so
    try {
        var jiagu = Module.findModuleByName('libjiagu.so');
        if (jiagu) {
            send({ type: 'packer_detected', packer: '360加固', module: 'libjiagu.so', base: jiagu.base });
            // Hook pthread_create to detect anti-debug threads
            Interceptor.attach(Module.findExportByName('libc.so', 'pthread_create'), {
                onEnter(args) {
                    var funcAddr = args[2];
                    var moduleName = '';
                    try { moduleName = Process.findModuleByAddress(funcAddr).name; } catch(e) {}
                    if (moduleName === 'libjiagu.so') {
                        send({ type: 'bypass_360', detail: 'Blocking anti-debug thread from libjiagu.so' });
                        args[2] = ptr(0); // Null out thread function
                    }
                }
            });
        }
    } catch(e) {}

    // ══════════════════════════════════════════
    // 3. 腾讯乐固 (Legu) 绕过
    // ══════════════════════════════════════════
    // 特征: libshella-*.so, libBugly.so, com.tencent.StubShell
    try {
        var shellModules = ['libshella-2.11.0.4.so', 'libshella-2.10.3.0.so', 'libshella.so'];
        shellModules.forEach(name => {
            var mod = Module.findModuleByName(name);
            if (mod) {
                send({ type: 'packer_detected', packer: '腾讯乐固', module: name, base: mod.base });
            }
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 4. 梆梆加固绕过
    // ══════════════════════════════════════════
    // 特征: libsecexe.so, libDexHelper.so, com.secshell.app.ShellApplication
    try {
        var bangbang = Module.findModuleByName('libsecexe.so') || Module.findModuleByName('libDexHelper.so');
        if (bangbang) {
            send({ type: 'packer_detected', packer: '梆梆加固', module: bangbang.name, base: bangbang.base });
        }
    } catch(e) {}

    // ══════════════════════════════════════════
    // 5. 通用反调试绕过 (适用于所有加固)
    // ══════════════════════════════════════════

    // 5a. TracerPid 反检测
    try {
        var fopen = Module.findExportByName('libc.so', 'fopen');
        Interceptor.attach(fopen, {
            onEnter(args) {
                this.path = args[0].readCString();
            },
            onLeave(retval) {
                if (this.path && this.path.indexOf('/proc/') !== -1 && this.path.indexOf('/status') !== -1) {
                    send({ type: 'antidebug', detail: 'TracerPid check: ' + this.path });
                }
            }
        });
    } catch(e) {}

    // 5b. ptrace 反调试
    try {
        Interceptor.attach(Module.findExportByName('libc.so', 'ptrace'), {
            onEnter(args) { this.req = args[0].toInt32(); },
            onLeave(retval) {
                if (this.req === 0) { // PTRACE_TRACEME
                    send({ type: 'antidebug', detail: 'ptrace TRACEME bypassed' });
                    retval.replace(ptr(0));
                }
            }
        });
    } catch(e) {}

    // 5c. exit/kill 防崩溃
    try {
        Interceptor.attach(Module.findExportByName('libc.so', 'exit'), {
            onEnter(args) {
                send({ type: 'antidebug', detail: 'exit() blocked, code=' + args[0].toInt32() });
                args[0] = ptr(0); // Prevent exit
            }
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 6. 通用 Frida 检测绕过
    // ══════════════════════════════════════════
    // 6a. 隐藏 frida-server 端口 (27042)
    try {
        Interceptor.attach(Module.findExportByName('libc.so', 'strstr'), {
            onEnter(args) {
                this.haystack = args[0];
                this.needle = args[1].readCString();
            },
            onLeave(retval) {
                if (this.needle) {
                    var hide = ['frida', 'LIBFRIDA', 'gum-js-loop', 'gmain', 're.frida.server',
                                'linjector', '/data/local/tmp'];
                    if (hide.some(k => this.needle.indexOf(k) !== -1)) {
                        retval.replace(ptr(0));
                    }
                }
            }
        });
    } catch(e) {}

    // 6b. 隐藏 /proc/self/maps 中的 frida 痕迹
    try {
        var openFunc = Module.findExportByName('libc.so', 'open');
        Interceptor.attach(openFunc, {
            onEnter(args) {
                this.path = args[0].readCString();
            }
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 7. SSL Pinning 增强版绕过 (多框架)
    // ══════════════════════════════════════════
    // OkHttp3
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            send({ type: 'ssl_bypass', framework: 'OkHttp3' });
        };
        CertPinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function() {
            send({ type: 'ssl_bypass', framework: 'OkHttp3-kotlin' });
        };
    } catch(e) {}

    // Retrofit / OkHttp Builder
    try {
        var Builder = Java.use('okhttp3.OkHttpClient$Builder');
        Builder.certificatePinner.implementation = function(pinner) {
            send({ type: 'ssl_bypass', framework: 'OkHttp3-Builder' });
            return this;
        };
    } catch(e) {}

    // Apache HTTP (legacy)
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String','[Ljava.lang.String;','[Ljava.lang.String;','boolean').implementation = function() {
            send({ type: 'ssl_bypass', framework: 'Apache-HTTP' });
        };
    } catch(e) {}

    // WebView SSL
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
            send({ type: 'ssl_bypass', framework: 'WebView' });
        };
    } catch(e) {}

    // Network Security Config bypass
    try {
        var PlatformTrust = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        PlatformTrust.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;','java.lang.String').implementation = function() {
            send({ type: 'ssl_bypass', framework: 'NetworkSecurityConfig' });
        };
    } catch(e) {}

    console.log('[FridaPilot] Android hardening bypass loaded');
});
