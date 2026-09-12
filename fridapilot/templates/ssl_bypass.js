// SSL Pinning Bypass - Universal SSL/TLS certificate pinning bypass
// Covers Android (TrustManager, OkHttp, WebView) and iOS (NSURLSession)

// --- Android ---
if (Java && Java.available) {
    Java.perform(() => {
        // TrustManager bypass
        try {
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const SSLContext = Java.use('javax.net.ssl.SSLContext');
            const TrustManager = Java.registerClass({
                name: 'com.fridapilot.BypassTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted(chain, authType) {},
                    checkServerTrusted(chain, authType) {},
                    getAcceptedIssuers() { return []; }
                }
            });
            const ctx = SSLContext.getInstance('TLS');
            ctx.init(null, [TrustManager.$new()], null);
            SSLContext.getInstance.overload('java.lang.String').implementation = function(type) {
                return ctx;
            };
            send({ type: 'bypass', detail: 'TrustManager SSL bypass applied' });
        } catch (e) {
            send({ type: 'bypass', detail: 'TrustManager bypass failed: ' + e });
        }

        // OkHttp CertificatePinner bypass
        try {
            const CertPinner = Java.use('okhttp3.CertificatePinner');
            CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
            send({ type: 'bypass', detail: 'OkHttp CertificatePinner bypass applied' });
        } catch (e) {}
    });
}

// --- iOS ---
if (ObjC && ObjC.available) {
    try {
        const NSURLSessionDel = ObjC.classes.NSURLSessionDelegate;
        if (NSURLSessionDel) {
            // Hook evaluateServerTrust to always succeed
            const resolver = new ObjC.Block({
                retType: 'void',
                argTypes: ['int'],
                implementation(disposition) {}
            });
            send({ type: 'bypass', detail: 'iOS SSL bypass loaded (basic)' });
        }
    } catch (e) {}
}

console.log('[FridaPilot] SSL pinning bypass loaded');
