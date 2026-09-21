// FridaPilot · Electron 渲染进程监控（CDP 注入版，尽力而为）
// 渲染进程页面世界默认没有 require（nodeIntegration=true 时才有）——
// 有则挂 ipcRenderer 钩子，无则明确上报 renderer_skip，绝不静默空转。
(() => {
    if (globalThis.__fpRendererInstalled) return;
    globalThis.__fpRendererInstalled = true;
    const emit = (o) => { try { console.log("__FP__" + JSON.stringify(o)); } catch (e) {} };
    const safe = (args) => { try { return JSON.stringify(args).substring(0, 2000); } catch (e) { return "[]"; } };

    let ipc = null;
    try { ipc = (typeof window !== "undefined" && window.require) ? window.require("electron") : null; }
    catch (e) { ipc = null; }

    if (!ipc || !ipc.ipcRenderer) {
        emit({ type: "renderer_skip",
               reason: "renderer has no node integration - ipcRenderer unreachable" });
        return;
    }

    const ir = ipc.ipcRenderer;
    ["send", "invoke", "sendSync", "sendToHost"].forEach(method => {
        if (!ir[method]) return;
        const orig = ir[method];
        ir[method] = function (channel) {
            const args = Array.prototype.slice.call(arguments, 1);
            emit({ type: "ipc_renderer", method: method, channel: channel,
                   args: safe(args), stack: (new Error()).stack });
            return orig.apply(this, arguments);
        };
    });

    const origOn = ir.on;
    ir.on = function (channel, listener) {
        emit({ type: "ipc_renderer_listen", channel: channel });
        return origOn.apply(this, arguments);
    };

    emit({ type: "renderer_ready", hooks: ["send", "invoke", "sendSync", "sendToHost", "on"] });
})();
