// Android 全面逆向分析脚本 - Activity/Service/加密/网络/Root检测
// FridaPilot - Android Comprehensive Reverse Engineering

Java.perform(() => {
    console.log('[FridaPilot] Android Reverse Engineering Script Loaded');

    // ══════════════════════════════════════════
    // 1. Activity 生命周期监控
    // ══════════════════════════════════════════
    try {
        const Activity = Java.use('android.app.Activity');
        ['onCreate','onResume','onPause','onDestroy'].forEach(method => {
            Activity[method].overload('android.os.Bundle').implementation = function(bundle) {
                send({ type: 'activity', method: method, class: this.getClass().getName() });
                return this[method](bundle);
            };
        });
    } catch(e) {}

    // ══════════════════════════════════════════
    // 2. SharedPreferences 读写监控
    // ══════════════════════════════════════════
    try {
        const SP = Java.use('android.app.SharedPreferencesImpl');
        SP.getString.overload('java.lang.String','java.lang.String').implementation = function(key, def) {
            const val = this.getString(key, def);
            send({ type: 'sharedprefs', op: 'get', key: key, value: String(val) });
            return val;
        };
    } catch(e) {}

    // ══════════════════════════════════════════
    // 3. Crypto 监控 (AES/RSA/Hash)
    // ══════════════════════════════════════════
    try {
        const Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function(input) {
            const result = this.doFinal(input);
            send({
                type: 'crypto', op: 'Cipher.doFinal',
                algo: this.getAlgorithm(),
                mode: this.getOpmode(),
                inputLen: input.length, outputLen: result.length
            });
            return result;
        };
    } catch(e) {}

    try {
        const MD = Java.use('java.security.MessageDigest');
        MD.digest.overload('[B').implementation = function(input) {
            const result = this.digest(input);
            send({ type: 'crypto', op: 'MessageDigest', algo: this.getAlgorithm(), inputLen: input.length });
            return result;
        };
    } catch(e) {}

    // ══════════════════════════════════════════
    // 4. 网络请求监控 (OkHttp / HttpURLConnection)
    // ══════════════════════════════════════════
    try {
        const URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            send({ type: 'network', api: 'URL.openConnection', url: this.toString() });
            return this.openConnection();
        };
    } catch(e) {}

    try {
        const OkHttpClient = Java.use('okhttp3.OkHttpClient');
        const RealCall = Java.use('okhttp3.internal.connection.RealCall');
        RealCall.execute.implementation = function() {
            const req = this.request();
            send({ type: 'network', api: 'OkHttp', method: req.method(), url: req.url().toString() });
            return this.execute();
        };
    } catch(e) {}

    // ══════════════════════════════════════════
    // 5. Root 检测绕过
    // ══════════════════════════════════════════
    try {
        const File = Java.use('java.io.File');
        File.exists.implementation = function() {
            const path = this.getAbsolutePath();
            const rootPaths = ['/system/app/Superuser.apk','/sbin/su','/system/bin/su',
                '/system/xbin/su','/data/local/xbin/su','/data/local/bin/su','/data/local/su',
                '/su/bin/su','magisk','frida'];
            if (rootPaths.some(p => path.includes(p))) {
                send({ type: 'bypass', detail: 'Root check bypassed: ' + path });
                return false;
            }
            return this.exists();
        };
    } catch(e) {}

    // ══════════════════════════════════════════
    // 6. Intent 监控
    // ══════════════════════════════════════════
    try {
        const Intent = Java.use('android.content.Intent');
        Intent.putExtra.overload('java.lang.String','java.lang.String').implementation = function(key, val) {
            send({ type: 'intent', op: 'putExtra', key: key, value: val });
            return this.putExtra(key, val);
        };
    } catch(e) {}

    console.log('[FridaPilot] Android hooks loaded');
});
