// FridaPilot · Electron preload 兜底通道（CommonJS，主进程最先执行）
// 用法：NODE_OPTIONS="--require <本文件>" 启动 Electron。
// 仅当目标 Fuses 允许 NodeOptions/RunAsNode 时生效——被忽略时本脚本
// 根本不会运行，因此 agent 必须等待下面的 health 行作为健康检查。
// 事件回传：process.stdout.write("__FPLINE__" + JSON.stringify(o) + "\n")
// （绕过应用对 console 的任何补丁）。
(() => {
    const hooks = [];
    const emit = (o) => { try { process.stdout.write("__FPLINE__" + JSON.stringify(o) + "\n"); } catch (e) {} };
    const mark = (name, ok) => { hooks.push(name + (ok ? "" : ":miss")); return ok; };
    const safe = (args) => { try { return JSON.stringify(args).substring(0, 2000); } catch (e) { return "[]"; } };

    const { app, ipcMain, BrowserWindow } = require("electron");

    ["handle", "on"].forEach(kind => {
        const orig = ipcMain[kind];
        ipcMain[kind] = function (channel, handler) {
            emit({ type: kind === "on" ? "ipc_main_on" : "ipc_main_handle", channel: channel });
            return orig.call(this, channel, function (event) {
                const args = Array.prototype.slice.call(arguments, 1);
                emit({ type: "ipc_main_call", channel: channel, args: safe(args) });
                return handler.apply(this, arguments);
            });
        };
    });
    mark("ipcMain", true);

    const ol = BrowserWindow.prototype.loadURL;
    BrowserWindow.prototype.loadURL = function (url) {
        emit({ type: "browser_window", action: "loadURL", url: url });
        return ol.apply(this, arguments);
    };
    mark("BrowserWindow", true);

    try {
        const fs = require("fs");
        ["readFileSync", "writeFileSync", "readFile", "writeFile", "unlinkSync"].forEach(fn => {
            if (!fs[fn]) return;
            const orig = fs[fn];
            fs[fn] = function () {
                emit({ type: "node_fs", fn: fn, path: String(arguments[0]) });
                return orig.apply(this, arguments);
            };
        });
        mark("node:fs", true);
    } catch (e) { mark("node:fs", false); }

    try {
        const cp = require("child_process");
        ["exec", "execSync", "spawn", "execFile"].forEach(fn => {
            if (!cp[fn]) return;
            const orig = cp[fn];
            cp[fn] = function () {
                emit({ type: "node_child_process", fn: fn, cmd: String(arguments[0]) });
                return orig.apply(this, arguments);
            };
        });
        mark("node:child_process", true);
    } catch (e) { mark("node:child_process", false); }

    app.whenReady().then(() => {
        try {
            const path = require("path");
            const appPath = app.getAppPath();
            emit({ type: "electron_app_path", path: appPath });
            const pkgPath = path.join(appPath, "package.json");
            if (require("fs").existsSync(pkgPath)) {
                const pkg = JSON.parse(require("fs").readFileSync(pkgPath, "utf-8"));
                emit({ type: "electron_package", name: pkg.name, version: pkg.version,
                       main: pkg.main, dependencies: Object.keys(pkg.dependencies || {}) });
            }
            mark("asar", true);
        } catch (e) { mark("asar", false); }
        emit({ type: "health", hooks: hooks });
    });
    emit({ type: "health_early", hooks: hooks });
})();
