// FridaPilot · Electron 主进程监控（CDP 注入版，H-T2 通道重设计）
// 运行在真实 Node 上下文（Runtime.evaluate 经 CDP 注入），require 可用。
// 事件回传：console.log('__FP__' + JSON.stringify(payload))，agent 侧过滤前缀。
// 幂等：重复注入回传首次安装时保存的钩子列表，而不是一个空列表——空列表会让
// agent 的健康检查算出 0/0 并判定失败。
(() => {
    const hooks = [];
    // 限流：繁忙应用每秒可产生上千次 fs/ipc 调用，无节制回传会把 CDP 通道刷满，
    // 并显著拖慢被监控进程。超出上限的事件计数后汇总成一条 emit_dropped。
    const RATE_LIMIT = 200;
    let windowStart = 0;
    let windowCount = 0;
    let dropped = 0;
    const emit = o => {
        try {
            const now = Date.now();
            if (now - windowStart >= 1000) {
                if (dropped > 0) {
                    console.log('__FP__' + JSON.stringify({type: 'emit_dropped', count: dropped}));
                    dropped = 0;
                }
                windowStart = now;
                windowCount = 0;
            }
            if (windowCount >= RATE_LIMIT) {
                dropped += 1;
                return;
            }
            windowCount += 1;
            console.log('__FP__' + JSON.stringify(o));
        } catch (e) {
            // 回传失败不能影响宿主逻辑
        }
    };
    const mark = (name, ok) => {
        hooks.push(name + (ok ? '' : ':miss'));
        return ok;
    };
    const safe = args => {
        try {
            return JSON.stringify(args).substring(0, 2000);
        } catch (e) {
            return '[]';
        }
    };

    if (globalThis.__fpMainInstalled) {
        const saved = globalThis.__fpHooks || [];
        emit({type: 'health', hooks: saved, repeat: true});
        return {installed: true, hooks: saved};
    }
    globalThis.__fpMainInstalled = true;

    // ── electron: ipcMain / contextBridge / BrowserWindow / app ──
    let electron = null;
    try {
        electron = require('electron');
        mark('require:electron', true);
    } catch (e) {
        mark('require:electron', false);
    }

    if (electron && electron.ipcMain) {
        const om = electron.ipcMain.on;
        electron.ipcMain.on = function (channel, listener) {
            emit({type: 'ipc_main_on', channel: channel});
            return om.call(this, channel, function (event) {
                const args = Array.prototype.slice.call(arguments, 1);
                emit({type: 'ipc_main_call', channel: channel, args: safe(args)});
                return listener.apply(this, arguments);
            });
        };
        const oh = electron.ipcMain.handle;
        electron.ipcMain.handle = function (channel, handler) {
            emit({type: 'ipc_main_handle', channel: channel});
            return oh.call(this, channel, async function (event) {
                const args = Array.prototype.slice.call(arguments, 1);
                emit({type: 'ipc_main_call', channel: channel, args: safe(args)});
                return handler.apply(this, arguments);
            });
        };
        mark('ipcMain', true);
    } else {
        mark('ipcMain', false);
    }

    if (electron && electron.contextBridge) {
        const oe = electron.contextBridge.exposeInMainWorld;
        electron.contextBridge.exposeInMainWorld = function (apiKey, api) {
            emit({type: 'context_bridge', apiKey: apiKey, methods: Object.keys(api || {})});
            return oe.apply(this, arguments);
        };
        mark('contextBridge', true);
    } else {
        mark('contextBridge', false);
    }

    if (electron && electron.BrowserWindow) {
        const BW = electron.BrowserWindow;
        const ol = BW.prototype.loadURL;
        BW.prototype.loadURL = function (url) {
            emit({type: 'browser_window', action: 'loadURL', url: url});
            return ol.apply(this, arguments);
        };
        const ofl = BW.prototype.loadFile;
        BW.prototype.loadFile = function (p) {
            emit({type: 'browser_window', action: 'loadFile', path: p});
            return ofl.apply(this, arguments);
        };
        mark('BrowserWindow', true);
    } else {
        mark('BrowserWindow', false);
    }

    if (electron && electron.app) {
        try {
            emit({type: 'electron_app_path', path: electron.app.getAppPath()});
            mark('app', true);
        } catch (e) {
            mark('app', false);
        }
    } else {
        mark('app', false);
    }

    // ── node: fs / child_process / http ──
    try {
        const fs = require('fs');
        ['readFileSync', 'writeFileSync', 'readFile', 'writeFile', 'unlinkSync',
            'readdirSync'].forEach(fn => {
            if (!fs[fn]) {
                return;
            }
            const orig = fs[fn];
            fs[fn] = function () {
                emit({type: 'node_fs', fn: fn, path: String(arguments[0])});
                return orig.apply(this, arguments);
            };
        });
        mark('node:fs', true);
    } catch (e) {
        mark('node:fs', false);
    }

    try {
        const cp = require('child_process');
        ['exec', 'execSync', 'spawn', 'execFile', 'fork'].forEach(fn => {
            if (!cp[fn]) {
                return;
            }
            const orig = cp[fn];
            cp[fn] = function () {
                emit({type: 'node_child_process', fn: fn, cmd: String(arguments[0])});
                return orig.apply(this, arguments);
            };
        });
        mark('node:child_process', true);
    } catch (e) {
        mark('node:child_process', false);
    }

    try {
        const http = require('http');
        const orq = http.request;
        http.request = function (options) {
            emit({
                type: 'node_http',
                method: (options && options.method) || 'GET',
                host: options && (options.hostname || options.host),
                path: options && options.path
            });
            return orq.apply(this, arguments);
        };
        mark('node:http', true);
    } catch (e) {
        mark('node:http', false);
    }

    // ── fuses / asar（信息性探针，失败不影响监控能力）──
    try {
        const fs = require('fs');
        // 分块读取：Electron 可执行文件常有上百 MB，readFileSync 会一次性进堆并
        // 阻塞主进程事件循环，用户会感知为卡顿。块间保留 sentinel.length-1 字节重叠，
        // 避免哨兵跨块被切断。
        const sentinel = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX');
        const CHUNK = 1 << 20;
        const fd = fs.openSync(process.execPath, 'r');
        let idx = -1;
        let fuseWire = null;
        try {
            const buf = Buffer.alloc(CHUNK + sentinel.length + 20);
            let base = 0;
            let carry = 0;
            for (;;) {
                const read = fs.readSync(fd, buf, carry, CHUNK, base + carry);
                if (read <= 0) {
                    break;
                }
                const view = buf.slice(0, carry + read);
                const at = view.indexOf(sentinel);
                if (at !== -1 && at + sentinel.length + 20 <= view.length) {
                    idx = base + at;
                    fuseWire = Buffer.from(view.slice(at + sentinel.length,
                        at + sentinel.length + 20));
                    break;
                }
                const keep = Math.min(view.length, sentinel.length + 20 - 1);
                view.slice(view.length - keep).copy(buf, 0);
                base += carry + read - keep;
                carry = keep;
            }
        } finally {
            fs.closeSync(fd);
        }
        if (fuseWire) {
            emit({
                type: 'electron_fuses',
                offset: '0x' + idx.toString(16),
                fuseBytes: Array.from(fuseWire).map(b => b.toString(16)).join(' '),
                details: {
                    runAsNode: fuseWire[0] === 0x31 ? 'enabled' : 'disabled',
                    cookieEncryption: fuseWire[1] === 0x31 ? 'enabled' : 'disabled',
                    nodeOptions: fuseWire[2] === 0x31 ? 'enabled' : 'disabled',
                    nodeCliInspect: fuseWire[3] === 0x31 ? 'enabled' : 'disabled',
                    embeddedAsarIntegrity: fuseWire[4] === 0x31 ? 'enabled' : 'disabled',
                    onlyLoadAppFromAsar: fuseWire[5] === 0x31 ? 'enabled' : 'disabled'
                }
            });
            mark('fuses', true);
        } else {
            mark('fuses', false);
        }
    } catch (e) {
        mark('fuses', false);
    }

    try {
        const path = require('path');
        const fs = require('fs');
        const appPath = electron.app.getAppPath();
        const files = fs.readdirSync(appPath);
        emit({type: 'asar_contents', topLevel: files.slice(0, 50)});
        const pkgPath = path.join(appPath, 'package.json');
        if (fs.existsSync(pkgPath)) {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
            emit({
                type: 'electron_package',
                name: pkg.name,
                version: pkg.version,
                main: pkg.main,
                dependencies: Object.keys(pkg.dependencies || {})
            });
        }
        mark('asar', true);
    } catch (e) {
        mark('asar', false);
    }

    globalThis.__fpHooks = hooks;
    globalThis.__fpHealth = function () {
        return {installed: true, hooks: globalThis.__fpHooks || []};
    };
    emit({type: 'health', hooks: hooks});
    return {installed: true, hooks: hooks};
})();
