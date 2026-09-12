// Electron 全面逆向分析脚本 - 主进程 + 渲染进程 + IPC + DevTools + Fuses
// FridaPilot - Electron Comprehensive Reverse Engineering

console.log('[FridaPilot] Electron Reverse Engineering Script Loaded');

// ═══════════════════════════════════════════════════════════
// 1. 进程识别: 区分主进程 / 渲染进程 / GPU 进程
// ═══════════════════════════════════════════════════════════
(function detectProcessType() {
    try {
        const cmdline = Process.enumerateModules().map(m => m.name).join(',');
        if (cmdline.includes('electron') || cmdline.includes('libnode')) {
            send({ type: 'electron_info', detail: 'Electron process detected', pid: Process.id });
        }
    } catch(e) {}
})();

// ═══════════════════════════════════════════════════════════
// 2. IPC 通信监控 (核心)
// ═══════════════════════════════════════════════════════════

// Hook ipcRenderer.send / invoke / sendSync
function hookIpcRenderer() {
    try {
        const ipcRenderer = require('electron').ipcRenderer;
        if (!ipcRenderer) return;

        ['send', 'invoke', 'sendSync', 'sendTo', 'sendToHost'].forEach(method => {
            if (ipcRenderer[method]) {
                const orig = ipcRenderer[method];
                ipcRenderer[method] = function(channel) {
                    const args = Array.prototype.slice.call(arguments, 1);
                    send({
                        type: 'ipc_renderer',
                        method: method,
                        channel: channel,
                        args: safeStringify(args),
                        stack: new Error().stack
                    });
                    return orig.apply(this, arguments);
                };
            }
        });

        // Hook ipcRenderer.on to see what channels renderer listens to
        const origOn = ipcRenderer.on;
        ipcRenderer.on = function(channel, listener) {
            send({ type: 'ipc_renderer_listen', channel: channel });
            return origOn.apply(this, arguments);
        };

        console.log('[FridaPilot] ipcRenderer hooks applied');
    } catch(e) {}
}

// Hook ipcMain.handle / on
function hookIpcMain() {
    try {
        const ipcMain = require('electron').ipcMain;
        if (!ipcMain) return;

        const origHandle = ipcMain.handle;
        ipcMain.handle = function(channel, handler) {
            send({ type: 'ipc_main_handle', channel: channel });
            const wrappedHandler = async function(event) {
                const args = Array.prototype.slice.call(arguments, 1);
                send({
                    type: 'ipc_main_call',
                    channel: channel,
                    args: safeStringify(args)
                });
                return handler.apply(this, arguments);
            };
            return origHandle.call(this, channel, wrappedHandler);
        };

        const origOn = ipcMain.on;
        ipcMain.on = function(channel, listener) {
            send({ type: 'ipc_main_on', channel: channel });
            return origOn.apply(this, arguments);
        };

        console.log('[FridaPilot] ipcMain hooks applied');
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════
// 3. contextBridge 监控
// ═══════════════════════════════════════════════════════════
function hookContextBridge() {
    try {
        const contextBridge = require('electron').contextBridge;
        if (!contextBridge) return;

        const origExpose = contextBridge.exposeInMainWorld;
        contextBridge.exposeInMainWorld = function(apiKey, api) {
            send({
                type: 'context_bridge',
                apiKey: apiKey,
                methods: Object.keys(api)
            });
            return origExpose.apply(this, arguments);
        };
        console.log('[FridaPilot] contextBridge hooks applied');
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════
// 4. BrowserWindow 创建监控
// ═══════════════════════════════════════════════════════════
function hookBrowserWindow() {
    try {
        const { BrowserWindow } = require('electron');
        if (!BrowserWindow) return;

        const origCtor = BrowserWindow;
        // Hook webPreferences to detect security settings
        const origLoadURL = BrowserWindow.prototype.loadURL;
        BrowserWindow.prototype.loadURL = function(url, options) {
            send({
                type: 'browser_window',
                action: 'loadURL',
                url: url,
                webPreferences: this.webContents ? {
                    nodeIntegration: this.webContents.getWebPreferences().nodeIntegration,
                    contextIsolation: this.webContents.getWebPreferences().contextIsolation,
                    sandbox: this.webContents.getWebPreferences().sandbox,
                } : {}
            });
            return origLoadURL.apply(this, arguments);
        };

        const origLoadFile = BrowserWindow.prototype.loadFile;
        BrowserWindow.prototype.loadFile = function(filePath) {
            send({ type: 'browser_window', action: 'loadFile', path: filePath });
            return origLoadFile.apply(this, arguments);
        };
        console.log('[FridaPilot] BrowserWindow hooks applied');
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════
// 5. 强制打开 DevTools
// ═══════════════════════════════════════════════════════════
function forceDevTools() {
    try {
        const { BrowserWindow } = require('electron');
        const windows = BrowserWindow.getAllWindows();
        windows.forEach(win => {
            if (!win.webContents.isDevToolsOpened()) {
                win.webContents.openDevTools({ mode: 'detach' });
                send({ type: 'devtools', action: 'forced_open', windowId: win.id });
            }
        });
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════
// 6. Node.js 核心模块监控
// ═══════════════════════════════════════════════════════════
function hookNodeModules() {
    // fs
    try {
        const fs = require('fs');
        ['readFileSync','writeFileSync','readFile','writeFile',
         'existsSync','mkdirSync','unlinkSync','readdirSync'].forEach(fn => {
            if (!fs[fn]) return;
            const orig = fs[fn];
            fs[fn] = function() {
                send({ type: 'node_fs', fn: fn, path: String(arguments[0]) });
                return orig.apply(this, arguments);
            };
        });
    } catch(e) {}

    // child_process
    try {
        const cp = require('child_process');
        ['exec','execSync','spawn','execFile','fork'].forEach(fn => {
            if (!cp[fn]) return;
            const orig = cp[fn];
            cp[fn] = function() {
                send({ type: 'node_child_process', fn: fn, cmd: String(arguments[0]) });
                return orig.apply(this, arguments);
            };
        });
    } catch(e) {}

    // net / http / https
    try {
        const http = require('http');
        const origRequest = http.request;
        http.request = function(options) {
            send({ type: 'node_http', method: options.method || 'GET',
                   host: options.hostname || options.host, path: options.path });
            return origRequest.apply(this, arguments);
        };
    } catch(e) {}

    // crypto
    try {
        const crypto = require('crypto');
        const origCreateCipher = crypto.createCipheriv;
        if (origCreateCipher) {
            crypto.createCipheriv = function(algorithm, key, iv) {
                send({
                    type: 'node_crypto',
                    op: 'createCipheriv',
                    algorithm: algorithm,
                    keyLen: key.length
                });
                return origCreateCipher.apply(this, arguments);
            };
        }
    } catch(e) {}

    console.log('[FridaPilot] Node.js module hooks applied');
}

// ═══════════════════════════════════════════════════════════
// 7. Electron Fuses 检测
// ═══════════════════════════════════════════════════════════
function detectFuses() {
    try {
        const path = require('path');
        const fs = require('fs');
        const execPath = process.execPath;
        const binary = fs.readFileSync(execPath);
        const sentinel = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX');
        const idx = binary.indexOf(sentinel);
        if (idx !== -1) {
            const fuseWire = binary.slice(idx + sentinel.length, idx + sentinel.length + 20);
            send({
                type: 'electron_fuses',
                offset: '0x' + idx.toString(16),
                fuseBytes: Array.from(fuseWire).map(b => b.toString(16)).join(' '),
                details: {
                    runAsNode: fuseWire[0] === 0x31 ? 'enabled' : 'disabled',
                    cookieEncryption: fuseWire[1] === 0x31 ? 'enabled' : 'disabled',
                    nodeOptions: fuseWire[2] === 0x31 ? 'enabled' : 'disabled',
                    nodeCliInspect: fuseWire[3] === 0x31 ? 'enabled' : 'disabled',
                    embeddedAsarIntegrity: fuseWire[4] === 0x31 ? 'enabled' : 'disabled',
                    onlyLoadAppFromAsar: fuseWire[5] === 0x31 ? 'enabled' : 'disabled',
                }
            });
        }
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════
// 8. asar 包内容枚举
// ═══════════════════════════════════════════════════════════
function enumerateAsar() {
    try {
        const path = require('path');
        const fs = require('fs');
        const appPath = require('electron').app.getAppPath();
        send({ type: 'electron_app_path', path: appPath });

        // List top-level files
        const files = fs.readdirSync(appPath);
        send({ type: 'asar_contents', topLevel: files.slice(0, 50) });

        // Find package.json
        const pkgPath = path.join(appPath, 'package.json');
        if (fs.existsSync(pkgPath)) {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
            send({
                type: 'electron_package',
                name: pkg.name,
                version: pkg.version,
                main: pkg.main,
                dependencies: Object.keys(pkg.dependencies || {})
            });
        }
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════
// 工具函数
// ═══════════════════════════════════════════════════════════
function safeStringify(obj) {
    try {
        return JSON.stringify(obj, null, 0).substring(0, 2000);
    } catch(e) {
        return String(obj);
    }
}

// ═══════════════════════════════════════════════════════════
// 启动所有 hooks
// ═══════════════════════════════════════════════════════════
hookIpcRenderer();
hookIpcMain();
hookContextBridge();
hookBrowserWindow();
hookNodeModules();
detectFuses();
enumerateAsar();

console.log('[FridaPilot] Electron comprehensive hooks loaded');
